package warp

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	cooldownDuration    = 30 * time.Minute
	registrationTimeout = 30 * time.Second
	maxRetries          = 3
	retryDelay          = 5 * time.Second

	// Replacement retry: after createExit fails once (e.g. transient DNS
	// outage), retry with exponential backoff 10s -> 60s cap, up to 20
	// attempts (~15 min coverage) so the pool self-heals without a restart.
	replaceRetryInitial  = 10 * time.Second
	replaceRetryMaxDelay = 60 * time.Second
	replaceRetryAttempts = 20
)

type Pool struct {
	mu          sync.Mutex
	config      PoolConfig
	exits       []*Exit
	healthy     int
	coolingDown int
	recycling   bool // a recycle is creating fresh exits; never double-run
	retrying    map[*Exit]bool
	stopped     chan struct{}
	closeOnce   sync.Once
}

func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 2
	}
	if cfg.Stack == "" {
		cfg.Stack = "ipv6"
	}

	p := &Pool{
		config:   cfg,
		exits:    make([]*Exit, 0, cfg.PoolSize),
		retrying: make(map[*Exit]bool),
		stopped:  make(chan struct{}),
	}

	for i := 0; i < cfg.PoolSize; i++ {
		go p.ensureExit(context.Background(), i)
	}

	return p, nil
}

func (p *Pool) Acquire(ctx context.Context) (*Exit, error) {
	// NOTE: no defer-based unlock across the wait path — locking the same
	// mutex twice (wait path re-locks) self-deadlocks the whole pool.

	for _, e := range p.exits {
		p.mu.Lock()
		// Exits are SHARED: a MASQUE tunnel is a full netstack host that
		// carries any number of concurrent TCP flows, so an exit is
		// available whenever it is healthy, regardless of other streams.
		if e.Cooldown.IsZero() && e.Tunnel() != nil {
			e.streams++
			e.InUseSince = time.Now()
			p.mu.Unlock()
			return e, nil
		}
		p.mu.Unlock()
	}
	return nil, fmt.Errorf("no WARP exit available (all cooling down or starting)")
}

func (p *Pool) Release(exit *Exit) {
	if exit == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if exit.streams > 0 {
		exit.streams--
	}
}

func (p *Pool) Fail(exit *Exit, reason string) {
	if exit == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	exit.streams = 0
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
	// Dedup guard: Fail + concurrent RecycleAll must not stack two retry
	// loops for the same exit.
	p.mu.Lock()
	if p.retrying[failed] {
		p.mu.Unlock()
		return
	}
	p.retrying[failed] = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.retrying, failed)
		p.mu.Unlock()
	}()

	delay := replaceRetryInitial
	for attempt := 1; attempt <= replaceRetryAttempts; attempt++ {
		select {
		case <-p.stopped:
			log.Printf("WARP pool closed: replacement for %s aborted", failed.ID)
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), registrationTimeout)
		exit, err := p.createExit(ctx)
		cancel()
		if err == nil {
			p.finishReplacement(failed, exit)
			return
		}

		if attempt == replaceRetryAttempts {
			log.Printf("WARP pool replacement permanently failed for %s after %d attempts: %v (exit stays in cooldown; manual recovery via RecycleAll once network recovers)", failed.ID, attempt, err)
			return
		}
		log.Printf("WARP exit replacement failed for %s (attempt %d/%d, next retry in %v): %v", failed.ID, attempt, replaceRetryAttempts, delay, err)

		select {
		case <-p.stopped:
			log.Printf("WARP pool closed: replacement for %s aborted", failed.ID)
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > replaceRetryMaxDelay {
			delay = replaceRetryMaxDelay
		}
	}
}

func (p *Pool) finishReplacement(failed, exit *Exit) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close the old tunnel
	if failed.Tunnel() != nil {
		failed.Tunnel().Close()
	}
	for i, e := range p.exits {
		if e == failed {
			p.exits[i] = exit
			break
		}
	}
	// Recalculate counters from actual state
	healthy := 0
	cooling := 0
	for _, e := range p.exits {
		if e.Cooldown.IsZero() && e.Tunnel() != nil {
			healthy++
		} else if !e.Cooldown.IsZero() {
			cooling++
		}
	}
	p.healthy = healthy
	p.coolingDown = cooling
	log.Printf("WARP exit replaced: %s -> %s (healthy=%d cooling=%d)", failed.ID, exit.ID, healthy, cooling)
}

func (p *Pool) createExit(ctx context.Context) (*Exit, error) {
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()

	cfg, err := RegisterDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	// MASQUE is the default egress (WireGuard is DPI-blocked on many ISPs).
	tunnel, err := NewMasqueTunnel(ctx, cfg, "")
	if err != nil {
		return nil, fmt.Errorf("create masque tunnel: %w", err)
	}

	exit := &Exit{
		ID:         fmt.Sprintf("warp-%x", time.Now().UnixNano()),
		PrivateKey: cfg.PrivateKey,
		Endpoint:   cfg.Endpoint,
		IPv6:       cfg.ClientIPv6,
		CreatedAt:  time.Now(),
	}
	exit.SetTunnel(tunnel)

	// A dead MASQUE session must fail this exit immediately (auto-replace):
	// otherwise requests queue on a zombie tunnel until the dial times out.
	tunnel.SetOnDead(func(reason string) {
		p.Fail(exit, reason)
	})

	return exit, nil
}

// Recycle re-enrolls every exit so all tunnels get fresh WARP egress IPs.
// Idempotent: a second call while a recycle is in flight just reports the
// in-flight state and never duplicates the (rate-limited) enrollment work.
// Returns recycling=true if a new cycle started, plus the current Status
// snapshot either way; Status carries "recycling" for the caller.
func (p *Pool) RecycleAll() (started bool, status map[string]any) {
	p.mu.Lock()
	if p.recycling {
		s := p.statusLocked()
		p.mu.Unlock()
		return false, s
	}
	p.recycling = true
	targets := make([]*Exit, 0, len(p.exits))
	for _, e := range p.exits {
		if e != nil && !e.Cooldown.IsZero() {
			// Already cooling down: its replacement is running.
			continue
		}
		targets = append(targets, e)
	}
	snapshot := p.statusLocked()
	p.mu.Unlock()
	if len(targets) == 0 {
		p.mu.Lock()
		p.recycling = false
		p.mu.Unlock()
		return false, snapshot
	}
	var wg sync.WaitGroup
	wg.Add(len(targets))
	for _, t := range targets {
		go func(ex *Exit) {
			defer wg.Done()
			p.replaceExit(ex)
		}(t)
	}
	go func() {
		wg.Wait()
		p.mu.Lock()
		p.recycling = false
		p.mu.Unlock()
		log.Print("WARP pool recycle complete: fresh egress addresses enrolled")
	}()
	return true, snapshot
}

func (p *Pool) Status() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.statusLocked()
}

func (p *Pool) statusLocked() map[string]any {
	// MUST be called with p.mu already held. Do not lock here.
	exits := make([]string, len(p.exits))
	for i, e := range p.exits {
		status := "healthy"
		streams := e.streams
		if streams > 0 {
			status = "in_use"
		} else if !e.Cooldown.IsZero() {
			status = "cooldown"
		} else if e.Tunnel() == nil {
			status = "starting"
		}
		exits[i] = fmt.Sprintf("%s (%s, streams=%d)", e.ID[:8], status, streams)
	}

	return map[string]any{
		"pool_size":    p.config.PoolSize,
		"recycling":    p.recycling,
		"active":       len(p.exits),
		"healthy":      p.healthy,
		"cooling_down": p.coolingDown,
		"exits":        exits,
	}
}

func (p *Pool) Close() {
	p.closeOnce.Do(func() { close(p.stopped) })
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
