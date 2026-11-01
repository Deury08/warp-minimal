package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	uri "github.com/yosida95/uritemplate/v3"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// MASQUE constants mirror the official Cloudflare WARP client.
var masqueEndpointAddr = "162.159.198.1:443"

const (
	masqueSNI        = "consumer-masque.cloudflareclient.com"
	masqueConnectURI = "https://cloudflareaccess.com"
	masqueProtocol   = "cf-connect-ip"
	masquePacketSize = 1242
)

// NewMasqueTunnel builds a MASQUE (QUIC Connect-IP) WARP exit and bridges it
// to the local gVisor netstack, replacing the (ISP-blocked) WireGuard path.
// Enrollment data (DeviceID/Token) must come from RegisterDevice.
func NewMasqueTunnel(ctx context.Context, cfg WireGuardConfig, endpoint string) (*Tunnel, error) {
	if cfg.DeviceID == "" || cfg.Token == "" {
		return nil, fmt.Errorf("masque enrollment requires a registered device (missing id/token)")
	}

	// 1. ECDSA P-256 key + self-signed cert (valid 24h, like the official client).
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EC key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal EC public key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "warp-minimal"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create self-signed cert: %w", err)
	}
	clientCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	// 2. Enroll the EC key (PATCH /reg/<id>, tunnel_type=masque) and refresh
	// the interface addresses Cloudflare assigned for this masque device.
	v4, v6, epV4, epV6, err := EnrollAndAddresses(ctx, cfg.DeviceID, cfg.Token, pubDER)
	if err != nil {
		return nil, fmt.Errorf("enroll masque key: %w", err)
	}
	cfg.ClientIPv4, cfg.ClientIPv6 = v4, v6
	// Prefer IPv4: the endpoint's /103::6 may be unreachable from WISP v6.
	if epV4 != "" {
		masqueEndpointAddr = epV4 + ":443"
	} else if epV6 != "" {
		masqueEndpointAddr = "[" + epV6 + "]:443"
	}

	// 3. QUIC dial with client-cert TLS auth.
	ep := masqueEndpointAddr
	if endpoint != "" {
		ep = endpoint
	}
	udpAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return nil, fmt.Errorf("resolve masque endpoint %s: %w", ep, err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		ServerName:   masqueSNI,
		NextProtos:   []string{http3.NextProtoH3},
		// SNI/Application host is not the wire endpoint: certificates on it are
		// not verifiable until we pin the ECDSA endpoint key, so skip here.
		InsecureSkipVerify: true,
	}
	quicConf := &quic.Config{
		EnableDatagrams:         true,
		KeepAlivePeriod:         10 * time.Second,
		InitialPacketSize:       masquePacketSize,
		DisablePathMTUDiscovery: true,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	// Without ConnectionIDLength set, the backend occasionally throws
	// PROTOCOL_VIOLATION and closes the connection (usque connectTunnelHTTP3).
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	qconn, err := qtr.Dial(ctx, udpAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	transport := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// Deprecated H3_DATAGRAM_00 setting the official client still sends.
			0x276: 1,
		},
		DisableCompression: true,
	}
	hconn := transport.NewClientConn(qconn)

	// 4. CONNECT-IP with Cloudflare's non-RFC :protocol.
	template := uri.MustNew(masqueConnectURI)
	// The official client sends an explicit empty User-Agent header.
	additionalHeaders := http.Header{"User-Agent": []string{""}}
	ipconn, rsp, err := connectip.Dial(ctx, hconn, template, masqueProtocol, additionalHeaders, true)
	if err != nil {
		qconn.CloseWithError(0, "connect-ip dial failed")
		if rsp != nil {
			return nil, fmt.Errorf("connect-ip dial: %w (status %d)", err, rsp.StatusCode)
		}
		return nil, fmt.Errorf("connect-ip dial: %w", err)
	}
	log.Printf("masque connect-ip established (status %d)", rsp.StatusCode)

	// 5. Local netstack (same layout as the WG path) with no WG device.
	stackS, epCh, cleanup := buildMasqueStack(cfg)
	if stackS == nil {
		return nil, fmt.Errorf("build masque netstack failed")
	}

	t := &Tunnel{
		stack:       stackS,
		ep:          epCh,
		defaultIPv6: cfg.ClientIPv6 != "",
	}

	// Outbound: netstack -> masque datagrams.
	go func() {
		for {
			pkt := epCh.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			// Full packet = network/transport headers + payload.
			full := pkt.ToView().AsSlice()
			if len(full) == 0 {
				pkt.DecRef()
				continue
			}
			sent, err := ipconn.WritePacket(append([]byte(nil), full...))
			if err != nil {
				pkt.DecRef()
				log.Printf("masque: outbound write packet (%d bytes): %v", len(full), err)
				if err == io.ErrClosedPipe || err.Error() == "tunnel closed" {
					return
				}
				// Transient datagram errors must not kill the pipe.
				continue
			}
			_ = sent
			pkt.DecRef()
		}
	}()

	// Inbound: masque datagrams -> netstack.
	go func() {
		buf := make([]byte, 65535)
		nread := 0
		for {
			n, err := ipconn.ReadPacket(buf, true)
			if err != nil {
				nread++
				if nread <= 3 {
					log.Printf("masque: inbound read error (%d): %v", nread, err)
				}
				return
			}
			if n == 0 {
				continue
			}
			proto := ipv6.ProtocolNumber
			if int(buf[0])>>4 == 4 {
				proto = ipv4.ProtocolNumber
			}
			var pl buffer.Buffer
			pl.Append(buffer.NewViewWithData(append([]byte(nil), buf[:n]...)))
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload:            pl,
				ReserveHeaderBytes: header.IPv6MinimumSize, // covers IPv4 too
			})
			// The QUIC datagram payload may carry an uncomputed IP checksum;
			// inbound transport checksums stay verifiable, skip IP rx check.
			pkt.RXChecksumValidated = true
			pkt.NetworkProtocolNumber = proto
			epCh.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()

	t.dev = nil
	t.masqueClose = func() {
		cleanup()
		ipconn.Close()
		qconn.CloseWithError(0, "tunnel closed")
	}

	log.Printf("WARP masque tunnel up: endpoint=%s client=%s", ep, cfg.ClientIPv6)
	return t, nil
}

// buildMasqueStack creates the gVisor stack + channel endpoint and adds the
// client addresses + default routes (same layout as the WG path).
func buildMasqueStack(cfg WireGuardConfig) (*stack.Stack, *channel.Endpoint, func()) {
	mtu := uint32(1280)
	ch := channel.New(outboundQLen, mtu, "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(1, ch); err != nil {
		s.Destroy()
		return nil, nil, func() {}
	}

	addAddr := func(proto tcpip.NetworkProtocolNumber, addr string, prefix int) error {
		a, err := tcpipAddrFromString(addr)
		if err != nil {
			return err
		}
		pa := tcpip.ProtocolAddress{
			Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   a,
				PrefixLen: prefix,
			},
		}
		if terr := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); terr != nil {
			return fmt.Errorf("add %s: %v", addr, terr)
		}
		return nil
	}
	if err := addAddr(ipv6.ProtocolNumber, cfg.ClientIPv6, 128); err != nil {
		log.Printf("masque: add client ipv6 %s: %v (ipv6-only)", cfg.ClientIPv6, err)
	}
	if err := addAddr(ipv4.ProtocolNumber, cfg.ClientIPv4, 32); err != nil {
		log.Printf("masque: add client ipv4 %s: %v", cfg.ClientIPv4, err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv6EmptySubnet, NIC: 1},
		{Destination: header.IPv4EmptySubnet, NIC: 1},
	})
	return s, ch, func() { s.Destroy(); ch.Close() }
}
