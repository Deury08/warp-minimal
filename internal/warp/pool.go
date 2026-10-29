package warp

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	cooldownDuration   = 30 * time.Minute
	registrationTimeout = 30 * time.Second
	maxRetries         = 3
	retryDelay         = 5 * time.Second
)

type Pool struct {
	mu          sync.Mutex
	config      PoolConfig
	exits       []*Exit
	healthy     int
	coolingDown int
}

func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 2
	}
	if cfg.Stack == "" {
		cfg.Stack = "ipv6"
	}

	p := &Pool{
		config: cfg,
		exits:  make([]*Exit, 0, cfg.PoolSize),
	}

	for i := 0; i < cfg.PoolSize; i++ {
		go p.ensureExit(context.Background(), i)
	}

	return p, nil
}

func (p *Pool) Acquire(ctx context.Context) (*Exit, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, e := range p.exits {
		if !e.InUse && e.Cooldown.IsZero() && e.Tunnel() != nil {
			e.InUse = true
			p.healthy--
			return e, nil
		}
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			p.mu.Lock()
			for _, e := range p.exits {
				if !e.InUse && e.Cooldown.IsZero() && e.Tunnel() != nil {
					e.InUse = true
					p.healthy--
					p.mu.Unlock()
					return e, nil
				}
			}
			p.mu.Unlock()
		}
	}
}

func (p *Pool) Release(exit *Exit) {
	if exit == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	exit.InUse = false
	if exit.Cooldown.IsZero() {
		p.healthy++
	}
}

func (p *Pool) Fail(exit *Exit, reason string) {
	if exit == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	exit.InUse = false
	exit.Cooldown = time.Now().Add(cooldownDuration)
	p.healthy--
	p.coolingDown++
	log.Printf("WARP exit %s failed: %s (cooldown %v)", exit.ID, reason, cooldownDuration)
	go p.replaceExit(exit)
}

func (p *Pool) ensureExit(ctx context.Context, index int) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		exit, err := p.createExit(ctx)
		if err == nil {
			p.mu.Lock()
			if index < len(p.exits) {
				p.exits[index] = exit
			} else {
				p.exits = append(p.exits, exit)
			}
			p.healthy++
			p.mu.Unlock()
			log.Printf("WARP exit %s ready at %s", exit.ID, exit.IPv6)
			return
		}

		log.Printf("WARP exit creation failed (attempt %d/%d): %v", attempt+1, maxRetries, err)
		time.Sleep(retryDelay)
	}

	log.Printf("WARP exit creation failed after %d attempts", maxRetries)
}

func (p *Pool) replaceExit(failed *Exit) {
	ctx, cancel := context.WithTimeout(context.Background(), registrationTimeout)
	defer cancel()

	exit, err := p.createExit(ctx)
	if err != nil {
		log.Printf("Failed to replace WARP exit: %v", err)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for i, e := range p.exits {
		if e == failed {
			p.exits[i] = exit
			break
		}
	}
	p.healthy++
	p.coolingDown--
	log.Printf("WARP exit replaced: %s -> %s", failed.ID, exit.ID)
}

func (p *Pool) createExit(ctx context.Context) (*Exit, error) {
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()

	cfg, err := RegisterDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	tunnel, err := NewTunnel(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}

	exit := &Exit{
		ID:         fmt.Sprintf("warp-%x", time.Now().UnixNano()),
		PrivateKey: cfg.PrivateKey,
		Endpoint:   cfg.Endpoint,
		IPv6:       cfg.ClientIPv6,
		CreatedAt:  time.Now(),
	}
	exit.SetTunnel(tunnel)

	return exit, nil
}

func (p *Pool) Status() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()

	exits := make([]string, len(p.exits))
	for i, e := range p.exits {
		status := "healthy"
		if e.InUse {
			status = "in_use"
		} else if !e.Cooldown.IsZero() {
			status = "cooldown"
		} else if e.Tunnel() == nil {
			status = "starting"
		}
		exits[i] = fmt.Sprintf("%s (%s)", e.ID[:8], status)
	}

	return map[string]any{
		"pool_size":    p.config.PoolSize,
		"active":       len(p.exits),
		"healthy":      p.healthy,
		"cooling_down": p.coolingDown,
		"exits":        exits,
	}
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.exits {
		if e.Tunnel() != nil {
			e.Tunnel().Close()
		}
	}
	p.exits = nil
	p.healthy = 0
}
