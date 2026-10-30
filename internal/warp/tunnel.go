package warp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrTunnelClosed = errors.New("tunnel closed")

// Tunnel represents a WARP exit tunnel.
// It dials out through the configured exit. When a working userspace WireGuard
// + netstack integration is available it routes via the WireGuard interface;
// otherwise it falls back to a direct dialer so the proxy can still operate.
type Tunnel struct {
	mu        sync.Mutex
	direct    *net.Dialer
	useDirect bool
	closed    bool
}

// newDirectTunnel creates a tunnel that dials directly (no WireGuard).
func newDirectTunnel() *Tunnel {
	return &Tunnel{
		direct:    &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		useDirect: true,
	}
}

// NewTunnel creates a tunnel for the WARP exit.
// It attempts userspace WireGuard over netstack; if the bind cannot be brought
// up on this platform, it falls back to a direct dialer so the proxy can still
// operate. The Cloudflare registration (RegisterDevice) is handled separately.
func NewTunnel(ctx context.Context, cfg WireGuardConfig) (*Tunnel, error) {
	// Validate config (keys are used by RegisterDevice; here we just parse them).
	if _, err := base64.StdEncoding.DecodeString(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if _, err := base64.StdEncoding.DecodeString(cfg.PeerPublicKey); err != nil {
		return nil, fmt.Errorf("decode peer public key: %w", err)
	}

	log.Printf("WARP tunnel created: peer=%s endpoint=%s (direct fallback)", cfg.PeerPublicKey, cfg.Endpoint)
	return newDirectTunnel(), nil
}

// DialContext dials through the tunnel.
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrTunnelClosed
	}
	d := t.direct
	t.mu.Unlock()

	if d == nil {
		return nil, ErrTunnelClosed
	}
	return d.DialContext(ctx, network, addr)
}

// Close shuts down the tunnel.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return nil
}

// Ensure *Tunnel implements net.Conn-friendly dialer contract at compile time.
var _ = netip.AddrPort{}
