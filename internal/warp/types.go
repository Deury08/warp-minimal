package warp

import (
	"context"
	"net"
	"sync"
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

type Tunnel struct {
	mu       sync.Mutex
	dialer   *net.Dialer
	closed   bool
}

type PoolConfig struct {
	PoolSize int
	Stack    string
}

type WireGuardConfig struct {
	PrivateKey     string
	PeerPublicKey  string
	Endpoint       string
	ClientIPv4     string
	ClientIPv6     string
	Reserved       []int
}

var (
	ErrNotImplemented     = NewError("not implemented")
	ErrWarpUnavailable    = NewError("WARP egress unavailable")
	ErrNoTunnel           = NewError("no tunnel available")
	ErrNoHealthyExit      = NewError("no healthy WARP exit available")
)

type warpError string

func NewError(msg string) error { return warpError(msg) }
func (e warpError) Error() string { return string(e) }
