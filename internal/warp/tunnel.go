package warp

import (
	"context"
	"errors"
	"net"
	"time"
)

var ErrTunnelClosed = errors.New("tunnel closed")

func NewTunnel(ctx context.Context, cfg WireGuardConfig) (*Tunnel, error) {
	return &Tunnel{
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}, nil
}

func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrTunnelClosed
	}
	t.mu.Unlock()
	return nil, ErrNotImplemented
}

func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return nil
}
