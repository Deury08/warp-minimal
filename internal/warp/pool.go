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

	// Replacement retry: after createExit fails once (e.g. transient DNS
	// outage), retry with exponential backoff 10s -> 60s cap, up to 20
	// attempts (~15 min coverage) so the pool self-heals without a restart.
	replaceRetryInitial  = 10 * time.Second
	replaceRetryMaxDelay = 60 * time.Second
	replaceRetryAttempts = 20

	// Fill retry logging: keep detail for the first attempts, then only every
	// 10th. The fill path retries forever, so a long WARP outage must not flood
	// the log for as long as it lasts.
	fillLogFirst = 5
	fillLogEvery = 10

	// Swap drain: how long a swapped-out exit may keep serving its live streams
	// before it is re-enrolled anyway. Best effort by design — a stream that
	// never ends must not pin the slot forever.
	drainTimeout = 120 * time.Second
)

// exitFactory enrolls one exit. Production uses Pool.createExit; tests inject a
// fake so pool behavior (fill, retry, failover) is pinned without WARP.
type exitFactory func(context.Context) (*Exit, error)

// poolOptions carries test seams. The zero value is production behavior.
type poolOptions struct {
	factory          exitFactory
	fillRetryInitial time.Duration
	fillRetryMax     time.Duration

	replaceAttempts int
	replaceInitial  time.Duration
	replaceMax      time.Duration
}

type Pool struct {
	mu          sync.Mutex
	config      PoolConfig
	exits       []*Exit
	healthy     int
	coolingDown int
	recycling   bool // a recycle is creating fresh exits; never double-run
	swapping    bool   // a per-exit swap is draining/re-enrolling; never double-run
	swapTarget  string // id of the exit the in-flight swap is draining; "" when none
	retrying    map[*Exit]bool
	stopped     chan struct{}
	closeOnce   sync.Once

	factory          exitFactory
	fillRetryInitial time.Duration
	fillRetryMax     time.Duration

	replaceAttempts int
	replaceInitial  time.Duration
	replaceMax      time.Duration
}

func NewPool(cfg PoolConfig) (*Pool, error) { return newPoolWith(cfg, poolOptions{}), nil }

func newPoolWith(cfg PoolConfig, opt poolOptions) *Pool {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 2
	}
	if cfg.Stack == "" {
		cfg.Stack = "ipv6"
	}
	if opt.fillRetryInitial <= 0 {
		opt.fillRetryInitial = replaceRetryInitial
	}
	if opt.fillRetryMax <= 0 {
		opt.fillRetryMax = replaceRetryMaxDelay
	}
	if opt.replaceAttempts <= 0 {
		opt.replaceAttempts = replaceRetryAttempts
	}
	if opt.replaceInitial <= 0 {
		opt.replaceInitial = replaceRetryInitial
	}
	if opt.replaceMax <= 0 {
		opt.replaceMax = replaceRetryMaxDelay
	}

	p := &Pool{
		config:           cfg,
		exits:            make([]*Exit, 0, cfg.PoolSize),
		retrying:         make(map[*Exit]bool),
		stopped:          make(chan struct{}),
		factory:          opt.factory,
		fillRetryInitial: opt.fillRetryInitial,
		fillRetryMax:     opt.fillRetryMax,
		replaceAttempts:  opt.replaceAttempts,
		replaceInitial:   opt.replaceInitial,
		replaceMax:       opt.replaceMax,
	}

	// A single reconciler owns filling: two enrollments racing on the same
	// slice could append one exit and overwrite it with the other, leaving
	// len(exits) short of pool_size while healthy still counted both.
	go p.fill()

	return p
}

// buildExit enrolls through the injected factory when a test provided one.
func (p *Pool) buildExit(ctx context.Context) (*Exit, error) {
	if p.factory != nil {
		return p.factory(ctx)
	}
	return p.createExit(ctx)
}

func (p *Pool) Acquire(ctx context.Context) (*Exit, error) {
	// p.mu is held across the whole scan. The slice header is shared state, so
	// ranging it unlocked raced with the fill reconciler appending an exit: a
	// torn header could return the wrong exit, or miss a healthy one, on a live
	// request. Nothing reached under this lock re-enters p.mu (Exit.Tunnel only
	// reads a field, and a tunnel's on-dead callback runs after that tunnel
	// releases its own mutex), so p.mu -> t.mu is the only lock order in play.
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, e := range p.exits {
		// Exits are SHARED: a MASQUE tunnel is a full netstack host that
		// carries any number of concurrent TCP flows, so an exit is
		// available whenever it is healthy, regardless of other streams.
		if !e.draining && e.Cooldown.IsZero() && e.Tunnel() != nil {
			e.streams++
			e.InUseSince = time.Now()
			return e, nil
		}
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
	if !exit.Cooldown.IsZero() {
		// Already failed (onDead plus a dial error on the same exit): its
		// replacement is running and the counters are already accounted for.
		return
	}
	exit.streams = 0
	exit.Cooldown = time.Now().Add(cooldownDuration)
	p.recountLocked()
	log.Printf("WARP exit %s failed: %s (cooldown %v)", exit.ID, reason, cooldownDuration)
	go p.replaceExit(exit)
}

// fill is the single reconciler that keeps pool_size exits enrolled. It never
// gives up: a transient enrollment failure only delays convergence, so the pool
// recovers on its own when the network returns instead of staying short until a
// restart. Contrast replaceExit, which handles an exit that exists but broke.
func (p *Pool) fill() {
	delay := p.fillRetryInitial
	attempt := 0
	for {
		select {
		case <-p.stopped:
			return
		default:
		}

		p.mu.Lock()
		full := len(p.exits) >= p.config.PoolSize
		p.mu.Unlock()
		if full {
			// Nothing removes an exit, so reaching pool_size is terminal for the
			// fill path; keep the loop cheap and re-check in case that changes.
			attempt = 0
			delay = p.fillRetryInitial
			select {
			case <-p.stopped:
				return
			case <-time.After(p.fillRetryMax):
			}
			continue
		}

		exit, err := p.buildExit(context.Background())
		if err == nil {
			p.addExit(exit)
			attempt = 0
			delay = p.fillRetryInitial
			continue
		}

		attempt++
		// Always retry; only the logging thins out so a long outage does not
		// flood the log for as long as it lasts.
		if attempt <= fillLogFirst || attempt%fillLogEvery == 0 {
			log.Printf("WARP exit fill failed (attempt %d, next retry in %v): %v", attempt, delay, err)
		}

		select {
		case <-p.stopped:
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > p.fillRetryMax {
			delay = p.fillRetryMax
		}
	}
}

// addExit appends one enrolled exit, refusing to exceed pool_size so a surplus
// enrollment is closed instead of leaked. It also refuses once the pool is
// closed: an enrollment that finishes after Close must be torn down here, or its
// tunnel outlives the pool with nobody left to close it.
func (p *Pool) addExit(exit *Exit) {
	p.mu.Lock()
	accept := !p.closedLocked() && len(p.exits) < p.config.PoolSize
	if accept {
		p.exits = append(p.exits, exit)
		p.recountLocked()
	}
	p.mu.Unlock()

	if !accept {
		if exit.Tunnel() != nil {
			exit.Tunnel().Close()
		}
		return
	}
	log.Printf("WARP exit %s ready at %s", exit.ID, exit.IPv6)
}

// closedLocked reports whether Close has already run. Call it with p.mu held.
func (p *Pool) closedLocked() bool {
	select {
	case <-p.stopped:
		return true
	default:
		return false
	}
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

	delay := p.replaceInitial
	for attempt := 1; attempt <= p.replaceAttempts; attempt++ {
		select {
		case <-p.stopped:
			log.Printf("WARP pool closed: replacement for %s aborted", failed.ID)
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), registrationTimeout)
		exit, err := p.buildExit(ctx)
		cancel()
		if err == nil {
			p.finishReplacement(failed, exit)
			return
		}

		if attempt == p.replaceAttempts {
			log.Printf("WARP pool replacement permanently failed for %s after %d attempts: %v", failed.ID, attempt, err)
			p.releaseSlot(failed)
			return
		}
		log.Printf("WARP exit replacement failed for %s (attempt %d/%d, next retry in %v): %v", failed.ID, attempt, p.replaceAttempts, delay, err)

		select {
		case <-p.stopped:
			log.Printf("WARP pool closed: replacement for %s aborted", failed.ID)
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > p.replaceMax {
			delay = p.replaceMax
		}
	}
}

// releaseSlot drops an exit that could not be replaced, so the fill reconciler
// owns the seat again. Keeping a permanently cooling exit in the slice would let
// it occupy one of the pool_size seats forever while the fill path, seeing a full
// pool, never enrolls a working exit in its place.
func (p *Pool) releaseSlot(exit *Exit) {
	p.mu.Lock()
	for i, e := range p.exits {
		if e == exit {
			p.exits = append(p.exits[:i], p.exits[i+1:]...)
			break
		}
	}
	p.recountLocked()
	p.mu.Unlock()

	if exit.Tunnel() != nil {
		exit.Tunnel().Close()
	}
	log.Printf("WARP exit %s released: the fill reconciler owns this slot again", exit.ID)
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
	// Recalculate counters from actual state (single source of truth).
	p.recountLocked()
	log.Printf("WARP exit replaced: %s -> %s (healthy=%d cooling=%d)", failed.ID, exit.ID, p.healthy, p.coolingDown)
}

// recountLocked derives both counters from the exits themselves. Every other
// place used to adjust them by hand, so a double fail or a lost append could
// leave /health reporting a pool that does not exist. Call it with p.mu held.
func (p *Pool) recountLocked() {
	healthy, cooling := 0, 0
	for _, e := range p.exits {
		switch {
		case !e.Cooldown.IsZero():
			cooling++
		case e.draining:
			// Draining: still finishing live streams, unavailable for new work, so
			// it must not be counted as healthy.
		case e.Tunnel() != nil:
			healthy++
		}
	}
	p.healthy = healthy
	p.coolingDown = cooling
}


// usableLocked reports whether an exit may serve a new request. p.mu held.
func (p *Pool) usableLocked(e *Exit) bool {
	return e != nil && !e.draining && e.Cooldown.IsZero() && e.Tunnel() != nil
}

// hasStandbyLocked reports whether some exit other than target stays usable, so a
// swap can never degrade the last one. p.mu held.
func (p *Pool) hasStandbyLocked(target *Exit) bool {
	for _, e := range p.exits {
		if e != target && p.usableLocked(e) {
			return true
		}
	}
	return false
}

// Swap rotates exactly one exit: it stops handing that exit to new requests, lets
// its live streams finish (best effort, bounded by drainTimeout) and re-enrolls
// only that exit. The other exits keep serving untouched, which is what
// RecycleAll cannot do: recycle replaces every exit and cuts the streams in
// flight, and it burns one enrollment per exit instead of one total.
//
// Empty targetID picks the exit carrying the most streams, because that is the
// egress most likely to be the one being rate-limited. Async and idempotent: a
// request that arrives while a swap is in flight reports that state and starts
// nothing. Returns a reason of "unknown_exit" or "no_standby" when nothing ran.
func (p *Pool) Swap(targetID string) (started bool, status map[string]any, reason string) {
	p.mu.Lock()
	if p.recycling || p.swapping {
		s := p.statusLocked()
		// Report the target of the swap already in flight, so a caller that gets
		// the idempotent 202 never has to guess which exit was taken.
		s["target"] = p.swapTarget
		p.mu.Unlock()
		return false, s, ""
	}

	var target *Exit
	if targetID == "" {
		for _, e := range p.exits {
			if !p.usableLocked(e) {
				continue
			}
			if target == nil || e.streams > target.streams {
				target = e
			}
		}
	} else {
		for _, e := range p.exits {
			if e.ID == targetID {
				target = e
				break
			}
		}
		if target == nil {
			s := p.statusLocked()
			p.mu.Unlock()
			return false, s, "unknown_exit"
		}
	}

	if !p.usableLocked(target) || !p.hasStandbyLocked(target) {
		s := p.statusLocked()
		s["target"] = target.ID
		p.mu.Unlock()
		return false, s, "no_standby"
	}

	target.draining = true
	p.swapping = true
	p.swapTarget = target.ID
	p.recountLocked()
	s := p.statusLocked()
	s["target"] = target.ID
	p.mu.Unlock()

	log.Printf("WARP swap requested for %s: draining before re-enrolling that exit only", target.ID)
	go p.completeSwap(target)
	return true, s, ""
}

func (p *Pool) completeSwap(target *Exit) {
	defer func() {
		p.mu.Lock()
		p.swapping = false
		p.swapTarget = ""
		p.mu.Unlock()
	}()

	if !p.waitDrained(target) {
		log.Printf("WARP pool closed: swap for %s aborted", target.ID)
		return
	}
	log.Printf("WARP swap for %s: drained, re-enrolling that exit only", target.ID)
	p.replaceExit(target)
}

// waitDrained blocks until target has no live streams, the drain deadline passes
// (a stream that never ends must not pin the slot forever), or the pool closes.
// It reports false only when the pool is closing.
func (p *Pool) waitDrained(target *Exit) bool {
	deadline := time.Now().Add(drainTimeout)
	for {
		p.mu.Lock()
		streams := target.streams
		p.mu.Unlock()
		switch {
		case streams == 0:
			return true
		case time.Now().After(deadline):
			log.Printf("WARP swap for %s: drain timed out with %d stream(s) still open; closing anyway", target.ID, streams)
			return true
		}
		select {
		case <-p.stopped:
			return false
		case <-time.After(20 * time.Millisecond):
		}
	}
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
	if p.recycling || p.swapping {
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
		served := e.servedCount()
		switch {
		// draining goes first: a swap in flight is the dominant fact, and the
		// consumer infers "swap in progress" from this state. If the draining
		// exit's tunnel dies mid-swap, cooldown must not hide it.
		case e.draining:
			status = "draining"
		case !e.Cooldown.IsZero():
			status = "cooldown"
		case e.Tunnel() == nil:
			status = "starting"
		case streams > 0:
			status = "in_use"
		}
		exits[i] = fmt.Sprintf("%s (%s, served=%d, streams=%d)", e.ID, status, served, streams)
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
	p.recountLocked()
}
