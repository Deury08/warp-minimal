package warp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	conn "golang.zx2c4.com/wireguard/conn"
	wgdev "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var ErrTunnelClosed = errors.New("tunnel closed")

const (
	// WARP requires an MTU that fits inside the WireGuard-over-UDP overhead;
	// 1280 (IPv6 minimum) is the safe choice used by every WARP client.
	tunnelMTU = 1280
	// Outbound packet queue between netstack and the WireGuard device.
	outboundQLen = 256
	// WireGuard persistent keepalive keeps the Cloudflare NAT mapping alive.
	keepAliveInterval = 25
)

// Tunnel is a userspace WARP exit: a wireguard-go device fed by a gVisor
// netstack through an in-memory channel endpoint. No kernel TUN device, no
// root, no NET_ADMIN.
type Tunnel struct {
	mu     sync.Mutex
	closed bool

	stack *stack.Stack
	dev   *wgdev.Device
	ep    *channel.Endpoint
	tfile *os.File

	defaultIPv6 bool

	// masqueClose terminates the MASQUE session when set (WG path: nil).
	masqueClose func()

	// onDead notifies the owner (pool) when the MASQUE session dies, so the
	// exit can be failed and replaced without waiting for a dial error.
	onDeadMu sync.Once
	onDead   func(reason string)
}

// WGLogHook, if set, receives every wireguard-go log line (verbose+errors).
// Production installs a log.Printf hook; probes install filters.
var WGLogHook func(msg string)

// netstackTun adapts a channel.Endpoint to the wireguard-go tun.Device
// interface. WireGuard reads outbound IP packets from it and writes inbound
// plaintext IP packets to it.
type netstackTun struct {
	t      *Tunnel
	ep     *channel.Endpoint
	file   *os.File
	events chan wgtun.Event
}

var _ wgtun.Device = (*netstackTun)(nil)

// NewTunnel builds and brings up one userspace WireGuard tunnel toward the
// Cloudflare WARP peer described by cfg.
func NewTunnel(ctx context.Context, cfg WireGuardConfig) (*Tunnel, error) {
	if _, err := base64.StdEncoding.DecodeString(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if _, err := base64.StdEncoding.DecodeString(cfg.PeerPublicKey); err != nil {
		return nil, fmt.Errorf("decode peer public key: %w", err)
	}

	ep := channel.New(outboundQLen, tunnelMTU, "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cleanup := func() {
		s.Destroy()
		ep.Close()
	}

	if err := s.CreateNIC(1, ep); err != nil {
		cleanup()
		return nil, fmt.Errorf("create netstack nic: %v", err)
	}

	if cfg.ClientIPv6 != "" {
		if addr, err := tcpipAddrFromString(cfg.ClientIPv6); err == nil {
			pa := tcpip.ProtocolAddress{
				Protocol: ipv6.ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   addr,
					PrefixLen: 128,
				},
			}
			if tcpipErr := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); tcpipErr != nil {
				cleanup()
				return nil, fmt.Errorf("add client ipv6 %s: %v", cfg.ClientIPv6, tcpipErr)
			}
		}
	}
	if cfg.ClientIPv4 != "" {
		if addr, err := tcpipAddrFromString(cfg.ClientIPv4); err == nil {
			pa := tcpip.ProtocolAddress{
				Protocol: ipv4.ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   addr,
					PrefixLen: 32,
				},
			}
			if tcpipErr := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); tcpipErr != nil {
				log.Printf("add client ipv4 %s failed: %v (ipv6-only tunnel)", cfg.ClientIPv4, tcpipErr)
			}
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv6EmptySubnet, NIC: 1},
		{Destination: header.IPv4EmptySubnet, NIC: 1},
	})

	fileR, fileW, err := os.Pipe()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create tun placeholder pipe: %w", err)
	}

	t := &Tunnel{
		stack:       s,
		ep:          ep,
		tfile:       fileR,
		defaultIPv6: cfg.ClientIPv6 != "",
	}
	nt := &netstackTun{
		t:      t,
		ep:     ep,
		file:   fileR,
		events: make(chan wgtun.Event, 1),
	}

	// WARP's WireGuard handshake runs inside the standard WG header except for
	// the per-account "reserved" prefix bytes, which must be re-stamped on
	// every packet in both directions, so we wrap the default bind.
	bind := newReservedBind(cfg.Reserved)

	dev := wgdev.NewDevice(nt, bind, wgdev.NewLogger(wgdev.LogLevelVerbose, "wg: "))
	if err := configureWGDevice(dev, cfg); err != nil {
		dev.Close()
		fileW.Close()
		fileR.Close()
		cleanup()
		return nil, fmt.Errorf("configure wg device: %w", err)
	}

	// Close the scratch write end; wg now owns flow control through nt.
	fileW.Close()

	t.dev = dev

	log.Printf("WARP tunnel up: peer=%s endpoint=%s client=%s", cfg.PeerPublicKey, cfg.Endpoint, cfg.ClientIPv6)
	return t, nil
}

// hexKey converts a base64-encoded WireGuard key to the hex encoding the
// wireguard-go IPC protocol expects.
func hexKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// newWGLogger routes wireguard-go logs through WGLogHook (or discards them).
func newWGLogger() *wgdev.Logger {
	logf := func(level string) func(string, ...any) {
		return func(format string, args ...any) {
			if WGLogHook != nil {
				WGLogHook(level + ": " + fmt.Sprintf(format, args...))
			}
		}
	}
	return &wgdev.Logger{Verbosef: logf("V"), Errorf: logf("E")}
}

func configureWGDevice(dev *wgdev.Device, cfg WireGuardConfig) error {
	priv, err := hexKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	peer, err := hexKey(cfg.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%d\n",
		priv, peer, cfg.Endpoint, keepAliveInterval,
	)
	if err := dev.IpcSet(ipc); err != nil {
		return err
	}
	return dev.Up()
}

// tcpipAddrFromString parses "1.2.3.4" or "2606:..." into a tcpip.Address.
func tcpipAddrFromString(s string) (tcpip.Address, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return tcpip.Address{}, err
	}
	return tcpip.AddrFromSlice(addr.AsSlice()), nil
}

// DialContext dials through the tunnel. network is Go's "tcp"/"udp" or
// "tcp4"/"tcp6" style; hostnames are resolved with the host resolver, picking
// an IPv6 first when the tunnel has a v6 client address.
const dialTimeout = 30 * time.Second

func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, ErrTunnelClosed
	}
	// A dead or wedged netstack must not hold the caller forever: cap the
	// dial so the pool can release the exit and request another.
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) > dialTimeout {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dialTimeout)
			defer cancel()
		}
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
	}

	ap, err := t.resolveTarget(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", addr, err)
	}
	log.Printf("DIAL %s -> %s proto=%s defaultIPv6=%v", addr, ap.Addr(), protoName(ap.Addr()), t.defaultIPv6)
	// Forzar IPv6-only cuando el stack está en modo ipv6: rechazar direcciones
	// IPv4 literales y no hacer fallback a IPv4 si el destino no tiene AAAA.
	if t.defaultIPv6 && ap.Addr().Is4() {
		return nil, fmt.Errorf("resolve %s: IPv4 address rejected in ipv6-only stack", addr)
	}
	fa := tcpip.FullAddress{
		Addr: tcpipAddrFromNetIP(ap.Addr()),
		Port: uint16(ap.Port()),
	}
	proto := tcpipProtoFor(ap.Addr(), strings.TrimSuffix(network, "4"))

	if strings.HasPrefix(network, "udp") {
		c, err := gonet.DialUDP(t.stack, nil, &fa, proto)
		if err != nil {
			return nil, fmt.Errorf("netstack udp dial: %v", err)
		}
		return c, nil
	}
	c, err := gonet.DialContextTCP(ctx, t.stack, fa, proto)
	if err != nil {
		return nil, fmt.Errorf("netstack tcp dial: %v", err)
	}
	return c, nil
}

// resolveTarget maps "host:port" or "ip:port" into a netip.AddrPort. IP
// literals pass through untouched; hostnames are resolved with the host DNS
// server, preferring the address family the tunnel supports.
func (t *Tunnel) resolveTarget(ctx context.Context, addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}

	// hostname:port — resolve via the host DNS.
	idx := strings.LastIndex(addr, ":")
	if idx <= 0 {
		return netip.AddrPort{}, fmt.Errorf("missing port in %q", addr)
	}
	host, port := addr[:idx], addr[idx+1:]
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	ctxDial, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// En modo IPv6-only, consultar específicamente registros AAAA. En
	// Windows, el resolver del sistema (GetAddrInfoW con AI_ADDRCONFIG)
	// filtra resultados IPv6 si la interfaz física no tiene IPv6, aunque
	// el servidor DNS sí los tenga. Usamos un resolver Go puro (PreferGo)
	// que hace consultas UDP DNS directamente para evitar esa limitación.
	var ips []netip.Addr
	var err error
	resolver := net.DefaultResolver
	if t.defaultIPv6 {
		resolver = &net.Resolver{PreferGo: true}
		ips, err = resolver.LookupNetIP(ctxDial, "ip6", host)
		if err != nil || len(ips) == 0 {
			ips4, err2 := resolver.LookupNetIP(ctxDial, "ip", host)
			if err2 == nil {
				for _, ip := range ips4 {
					a := ip.Unmap()
					if a.Is6() && !a.Is4In6() {
						ips = append(ips, a)
					}
				}
			}
		}
	} else {
		ips, err = resolver.LookupNetIP(ctxDial, "ip", host)
	}
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("dns: %w", err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no addresses for %q", host)
	}

	var chosen netip.Addr
	for _, ip := range ips {
		a := ip.Unmap()
		if t.defaultIPv6 && a.Is6() && !a.Is4In6() {
			chosen = a
			break
		}
		if !t.defaultIPv6 && a.Is4() {
			chosen = a
			break
		}
	}
	if !chosen.IsValid() {
		if t.defaultIPv6 {
			return netip.AddrPort{}, fmt.Errorf("no IPv6 address for %q (ipv6-only stack)", addr)
		}
		chosen = ips[0].Unmap()
	}
	log.Printf("RESOLVE %s -> %s (%s)", addr, chosen, protoName(chosen))
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", port, err)
	}
	return netip.AddrPortFrom(chosen, uint16(portNum)), nil
}

func tcpipAddrFromNetIP(a netip.Addr) tcpip.Address {
	s := a.AsSlice()
	if a.Is4() {
		return tcpip.AddrFrom4Slice(s)
	}
	return tcpip.AddrFrom16Slice(s)
}

func tcpipProtoFor(a netip.Addr, network string) tcpip.NetworkProtocolNumber {
	if strings.HasSuffix(network, "4") || a.Is4() || a.Is4In6() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func protoName(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "ipv4"
	}
	return "ipv6"
}

// ---- wireguard tun.Device adapter ----

func (n *netstackTun) File() *os.File { return n.file }

func (n *netstackTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := n.ep.ReadContext(context.Background())
	if pkt == nil {
		return 0, io.EOF // tunnel closed or spurious wakeup: stop this read
	}
	defer pkt.DecRef()

	data := pkt.Data()
	sizes[0] = data.Size()
	b, ok := data.PullUp(data.Size())
	if !ok {
		return 0, io.EOF
	}
	copy(bufs[0][offset:], b)
	return 1, nil
}

func (n *netstackTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		b := buf[offset:]
		if len(b) == 0 {
			continue
		}
		proto := ipv6.ProtocolNumber
		if int(b[0])>>4 == 4 {
			proto = ipv4.ProtocolNumber
		}
		var pl buffer.Buffer
		pl.Append(buffer.NewViewWithData(b))
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pl})
		pkt.NetworkProtocolNumber = proto
		n.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func (n *netstackTun) MTU() (int, error) { return tunnelMTU, nil }

func (n *netstackTun) Name() (string, error) { return "warp0", nil }

func (n *netstackTun) Events() <-chan wgtun.Event { return n.events }

func (n *netstackTun) Close() error {
	select {
	case n.events <- wgtun.EventDown:
	default:
	}
	return nil
}

func (n *netstackTun) BatchSize() int { return 1 }

// reservedBind stamps the WARP per-account "reserved" bytes into the first
// three bytes of every WG packet and clears them on receive so the standard
// parser sees known values.
type reservedBind struct {
	conn.Bind
	reserved [3]byte
}

func newReservedBind(reserved []int) *reservedBind {
	b := &reservedBind{Bind: conn.NewDefaultBind()}
	// TODO(warp): WARP classic accounts require all-zero reserved bytes;
	// HKDF-derived bytes are ignored for now (no-op).
	// WARP classic accounts reject non-zero reserved prefixes: the server
	// answers nothing. Use all-zero reserved bytes unconditionally.
	_ = reserved
	return b
}

func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, 0, len(fns))
	for _, fn := range fns {
		f := fn
		out = append(out, func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := f(packets, sizes, eps)
			if err != nil {
				return 0, err
			}
			for i := 0; i < n && i < len(packets); i++ {
				// Clear the reserved prefix so the standard parser can read
				// the WireGuard message type.
				if sizes[i] >= 4 {
					packets[i][0], packets[i][1], packets[i][2] = 0, 0, 0
				}
			}
			return n, nil
		})
	}
	return out, actual, nil
}

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) >= 4 {
			copy(buf[0:3], b.reserved[:])
		}
	}
	return b.Bind.Send(bufs, ep)
}

// Close shuts down the tunnel and its netstack.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	if t.masqueClose != nil {
		t.masqueClose()
		return nil
	}
	t.dev.Close()
	t.ep.Close()
	t.stack.Destroy()
	return t.tfile.Close()
}

// SetOnDead registers the callback invoked exactly once when the tunnel dies.
func (t *Tunnel) SetOnDead(fn func(reason string)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onDead = fn
}

// markDead invokes the on-dead callback once, unless the tunnel was closed
// intentionally (Close flows also produce read errors, not failures).
func (t *Tunnel) markDead(reason string) {
	t.mu.Lock()
	fn := t.onDead
	t.onDead = nil
	closed := t.closed
	t.mu.Unlock()
	if fn != nil && !closed {
		fn(reason)
	}
}
