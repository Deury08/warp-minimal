package warp

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

type Exit struct {
	ID         string
	PrivateKey string
	Endpoint   string
	IPv6       string
	CreatedAt  time.Time
	Cooldown   time.Time
	InUse      bool
	streams    int // active conns THROUGH the exit; also the swap drain signal
	// draining marks an exit that must take no new work because a per-exit swap
	// is in flight: its live streams keep running, then it is re-enrolled.
	// Guarded by Pool.mu.
	draining bool

	// served counts the CONNECT tunnels this exit established. Monotonic and never
	// reset, so a client whose HTTP stack hides the CONNECT reply can still
	// attribute an upstream failure by diffing /health around one attempt: the
	// exit whose served went up is the one that carried it. Atomic, because the
	// proxy increments it without holding Pool.mu.
	served int64
	InUseSince time.Time
	tunnel     *Tunnel
}

func (e *Exit) Tunnel() *Tunnel {
	return e.tunnel
}

func (e *Exit) SetTunnel(t *Tunnel) {
	e.tunnel = t
}

func (e *Exit) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if e.tunnel == nil {
		return nil, ErrNoTunnel
	}
	return e.tunnel.DialContext(ctx, network, addr)
}

type PoolConfig struct {
	PoolSize int
	Stack    string
}

type WireGuardConfig struct {
	PrivateKey    string
	PeerPublicKey string
	Endpoint      string
	ClientIPv4    string
	ClientIPv6    string
	Reserved      []int
	// MASQUE enrollment data (valid after RegisterDevice).
	Token    string
	DeviceID string
}

var (
	ErrNotImplemented  = NewError("not implemented")
	ErrWarpUnavailable = NewError("WARP egress unavailable")
	ErrNoTunnel        = NewError("no tunnel available")
	ErrNoHealthyExit   = NewError("no healthy WARP exit available")
)

type warpError string

func NewError(msg string) error   { return warpError(msg) }
func (e warpError) Error() string { return string(e) }

// servedCount reports the monotonic CONNECT count this exit established, for
// /health. Safe without Pool.mu: the counter is atomic.
func (e *Exit) servedCount() int64 { return atomic.LoadInt64(&e.served) }

// noteServed records that this exit established one CONNECT tunnel.
func (e *Exit) noteServed() { atomic.AddInt64(&e.served, 1) }
