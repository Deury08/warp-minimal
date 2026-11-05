package warp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeExit builds an Exit whose tunnel Close is a no-op, so pool tests never
// touch the network, a netstack, or the operator's live proxy.
func fakeExit(id string) *Exit {
	tun := &Tunnel{}
	tun.masqueClose = func() {}
	exit := &Exit{ID: id}
	exit.SetTunnel(tun)
	return exit
}

// testPool builds a pool with an injected exit factory and millisecond retry
// delays: convergence has to happen inside a test, not after a 10s backoff.
func testPool(t *testing.T, size int, factory exitFactory) *Pool {
	t.Helper()
	p := newPoolWith(PoolConfig{PoolSize: size}, poolOptions{
		factory:          factory,
		fillRetryInitial: time.Millisecond,
		fillRetryMax:     2 * time.Millisecond,
	})
	t.Cleanup(p.Close)
	return p
}

func activeExits(p *Pool) int { return p.Status()["active"].(int) }

// waitActive polls until the pool reaches want, so a test asserts the outcome
// instead of an internal timing.
func waitActive(t *testing.T, p *Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if activeExits(p) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active = %d, want %d; status %v", activeExits(p), want, p.Status())
}

// closeCountingExit is a fake exit whose tunnel Close increments a counter, so a
// test can prove a tunnel was actually torn down (not merely dropped).
func closeCountingExit(id string, closes *atomic.Int64) *Exit {
	tun := &Tunnel{}
	tun.masqueClose = func() { closes.Add(1) }
	exit := &Exit{ID: id}
	exit.SetTunnel(tun)
	return exit
}

func poolExit(p *Pool, i int) *Exit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exits[i]
}

// TestPoolFillsEverySlot pins the invariant the whole pool exists for: the
// configured pool_size is a promise about reality, not a wish.
func TestPoolFillsEverySlot(t *testing.T) {
	var n atomic.Int64
	p := testPool(t, 2, func(context.Context) (*Exit, error) {
		return fakeExit(fmt.Sprintf("warp-fill-%d", n.Add(1))), nil
	})

	waitActive(t, p, 2)

	if got := p.Status()["healthy"].(int); got != 2 {
		t.Errorf("healthy = %d, want 2", got)
	}
	if first, second := poolExit(p, 0), poolExit(p, 1); first == second {
		t.Errorf("both slots hold the same exit %q: one enrollment was overwritten", first.ID)
	}
}

// TestPoolKeepsRetryingAfterTransientFailures is the regression this work
// exists for: today the bootstrap gives up after 3 attempts per slot, so a
// transient enrollment failure leaves the pool permanently short.
func TestPoolKeepsRetryingAfterTransientFailures(t *testing.T) {
	var calls atomic.Int64
	p := testPool(t, 2, func(context.Context) (*Exit, error) {
		// 6 failures == 3 attempts for each of the 2 slots: exactly enough for
		// the old bootstrap to exhaust both and stay empty forever.
		if n := calls.Add(1); n <= 6 {
			return nil, errors.New("transient enroll failure")
		}
		return fakeExit(fmt.Sprintf("warp-retry-%d", calls.Load())), nil
	})

	waitActive(t, p, 2)
}

// TestFailIsIdempotent pins the counters and the cooldown against a double fail
// (onDead plus a dial error on the same exit). The replacement is held in flight
// so the assertion cannot depend on how fast the fake factory succeeds.
func TestFailIsIdempotent(t *testing.T) {
	block := make(chan struct{})
	var calls atomic.Int64
	p := testPool(t, 1, func(context.Context) (*Exit, error) {
		if calls.Add(1) == 1 {
			return fakeExit("warp-fail"), nil
		}
		<-block
		return nil, errors.New("replacement held in flight")
	})
	waitActive(t, p, 1)

	exit := poolExit(p, 0)
	p.Fail(exit, "tunnel read error")
	firstCooldown := exit.Cooldown
	p.Fail(exit, "tunnel read error")

	status := p.Status()
	if got := status["healthy"].(int); got != 0 {
		t.Errorf("healthy = %d, want 0 after a double fail", got)
	}
	if got := status["cooling_down"].(int); got != 1 {
		t.Errorf("cooling_down = %d, want 1 after a double fail", got)
	}
	if !exit.Cooldown.Equal(firstCooldown) {
		t.Errorf("the second fail extended the cooldown: %v -> %v", firstCooldown, exit.Cooldown)
	}
	close(block)
}

// TestPoolCloseDuringFillEnrollmentLeaksNothing pins that an enrollment which
// finishes after Close() is torn down instead of being appended to a closed pool.
func TestPoolCloseDuringFillEnrollmentLeaksNothing(t *testing.T) {
	gate := make(chan struct{})
	var closes, calls atomic.Int64
	p := newPoolWith(PoolConfig{PoolSize: 1}, poolOptions{
		factory: func(context.Context) (*Exit, error) {
			if calls.Add(1) == 1 {
				<-gate
			}
			return closeCountingExit("warp-late", &closes), nil
		},
		fillRetryInitial: time.Millisecond,
		fillRetryMax:     2 * time.Millisecond,
	})

	time.Sleep(30 * time.Millisecond) // fill is parked inside the factory
	p.Close()
	close(gate)
	time.Sleep(150 * time.Millisecond)

	if got := p.Status()["active"].(int); got != 0 {
		t.Errorf("active = %d after Close, want 0", got)
	}
	if got := closes.Load(); got != 1 {
		t.Errorf("tunnel Close calls = %d, want 1: an exit enrolled after Close leaked its tunnel", got)
	}
}

// TestAcquireJoinsFillWithoutRace must run under -race: Acquire reads the exits
// slice header while the fill reconciler appends to it. Only the race detector
// reports the torn read, so this test is a detector assertion, not a plain one.
func TestAcquireJoinsFillWithoutRace(t *testing.T) {
	var n atomic.Int64
	p := testPool(t, 8, func(context.Context) (*Exit, error) {
		return fakeExit(fmt.Sprintf("warp-u%d", n.Add(1))), nil
	})
	for i := 0; i < 4000; i++ {
		_, _ = p.Acquire(context.Background())
	}
}

// TestPermanentReplacementFailureReleasesSlot pins that a slot whose replacement
// cannot be re-enrolled is handed back to the fill reconciler instead of holding
// a pool_size seat in cooldown for the life of the process.
func TestPermanentReplacementFailureReleasesSlot(t *testing.T) {
	var calls atomic.Int64
	p := newPoolWith(PoolConfig{PoolSize: 1}, poolOptions{
		factory: func(context.Context) (*Exit, error) {
			if calls.Add(1) == 1 {
				return fakeExit("warp-dead"), nil
			}
			return nil, errors.New("WARP stays unreachable")
		},
		fillRetryInitial: time.Millisecond,
		fillRetryMax:     2 * time.Millisecond,
		replaceAttempts:  2,
		replaceInitial:   time.Millisecond,
		replaceMax:       2 * time.Millisecond,
	})
	t.Cleanup(p.Close)
	waitActive(t, p, 1)

	p.Fail(poolExit(p, 0), "tunnel read error")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := p.Status()
		if status["active"].(int) == 0 && status["cooling_down"].(int) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("status %v, want active=0 cooling_down=0 after a permanently failed replacement (slot released to fill)", p.Status())
}

// TestStatusExitIDsAreDistinguishable pins the /health contract the relay reads:
// two exits enrolled in the same era share their leading hex digits, so a
// truncated id makes a rotation look like no change at all.
func TestStatusExitIDsAreDistinguishable(t *testing.T) {
	ids := []string{"warp-18e50dc0687bad70", "warp-18e50dc06a8dcd8c"}
	var n atomic.Int64
	p := testPool(t, 2, func(context.Context) (*Exit, error) {
		return fakeExit(ids[int(n.Add(1))-1]), nil
	})
	waitActive(t, p, 2)

	seen := map[string]bool{}
	for _, entry := range p.Status()["exits"].([]string) {
		seen[strings.SplitN(entry, " (", 2)[0]] = true
	}
	if len(seen) != 2 {
		t.Errorf("exit labels = %v, want 2 distinguishable ids", seen)
	}
}


// swapPool returns an already-filled pool of the given size whose factory mints
// a fresh id per enrollment, so a replacement is distinguishable from what it
// replaced.
func swapPool(t *testing.T, size int) *Pool {
	t.Helper()
	var n atomic.Int64
	p := newPoolWith(PoolConfig{PoolSize: size}, poolOptions{
		factory: func(ctx context.Context) (*Exit, error) {
			return fakeExit(fmt.Sprintf("warp-gen-%d", n.Add(1))), nil
		},
		fillRetryInitial: time.Millisecond,
		fillRetryMax:     2 * time.Millisecond,
		replaceAttempts:  3,
		replaceInitial:   time.Millisecond,
		replaceMax:       2 * time.Millisecond,
	})
	t.Cleanup(p.Close)
	waitActive(t, p, size)
	return p
}

func exitAt(p *Pool, i int) *Exit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exits[i]
}

func setStreams(p *Pool, e *Exit, n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.streams = n
}

func healthyOf(p *Pool) int { return p.Status()["healthy"].(int) }

func waitHealthy(t *testing.T, p *Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if healthyOf(p) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("healthy = %d, want %d; status %v", healthyOf(p), want, p.Status())
}

// TestSwapRefusesLastHealthy pins the one rule that makes a per-exit swap safe:
// it may never rotate the only exit that can still serve traffic.
func TestSwapRefusesLastHealthy(t *testing.T) {
	p := swapPool(t, 1)
	target := exitAt(p, 0)

	started, status, reason := p.Swap(target.ID)
	if started || reason != "no_standby" {
		t.Fatalf("Swap on the only usable exit = started %v reason %q; want false/\"no_standby\"", started, reason)
	}
	if got := status["healthy"].(int); got != 1 {
		t.Fatalf("healthy = %d, want 1 (a refused swap must not degrade the pool)", got)
	}
	if exitAt(p, 0) != target {
		t.Fatal("refused swap replaced the exit anyway")
	}
}

// TestSwapUnknownExit pins that an unknown target is named as such instead of
// silently rotating some other exit.
func TestSwapUnknownExit(t *testing.T) {
	p := swapPool(t, 2)

	started, _, reason := p.Swap("warp-does-not-exist")
	if started || reason != "unknown_exit" {
		t.Fatalf("Swap with an unknown id = started %v reason %q; want false/\"unknown_exit\"", started, reason)
	}
	if activeExits(p) != 2 || healthyOf(p) != 2 {
		t.Fatalf("a rejected swap changed the pool: %v", p.Status())
	}
}

// TestSwapDrainsThenReplacesOnlyTarget pins the whole point of the feature: the
// target stops taking work, its live stream finishes, and only then is it
// re-enrolled — while the standby exit is never touched.
func TestSwapDrainsThenReplacesOnlyTarget(t *testing.T) {
	p := swapPool(t, 2)
	target, standby := exitAt(p, 0), exitAt(p, 1)
	setStreams(p, target, 1) // a live stream keeps the target draining

	started, status, reason := p.Swap(target.ID)
	if !started || reason != "" {
		t.Fatalf("Swap = started %v reason %q; want true and no reason", started, reason)
	}
	if got := status["healthy"].(int); got != 1 {
		t.Fatalf("healthy = %d while the target drains, want 1", got)
	}

	// While the stream lives the target must not be re-enrolled.
	time.Sleep(20 * time.Millisecond)
	if exitAt(p, 0) != target {
		t.Fatal("target was replaced while it still had a live stream")
	}

	setStreams(p, target, 0) // the stream ends
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && exitAt(p, 0) == target {
		time.Sleep(time.Millisecond)
	}
	if exitAt(p, 0) == target {
		t.Fatalf("target was never re-enrolled after draining: %v", p.Status())
	}
	if exitAt(p, 1) != standby {
		t.Fatal("the standby exit was replaced too; a swap must touch exactly one exit")
	}
	waitHealthy(t, p, 2)
}

// TestSwapIsIdempotentWhileDraining pins that a second caller during a swap gets
// the in-flight state instead of starting a second drain of the same exit.
func TestSwapIsIdempotentWhileDraining(t *testing.T) {
	p := swapPool(t, 2)
	target := exitAt(p, 0)
	setStreams(p, target, 1)

	if started, _, _ := p.Swap(target.ID); !started {
		t.Fatal("first swap did not start")
	}
	started, status, reason := p.Swap(target.ID)
	if started {
		t.Fatal("second swap started while the first one was still draining")
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (the pool is only busy)", reason)
	}
	if status == nil {
		t.Fatal("a busy swap must still report the pool status")
	}

	setStreams(p, target, 0)
	waitHealthy(t, p, 2)
}

// TestStatusReportsServedPerExit pins the counter the relay uses instead of the
// CONNECT header (its HTTP stack hides that reply): /health must show a
// monotonic served count per exit, so a snapshot diff around one attempt names
// the exit that carried it.
func TestStatusReportsServedPerExit(t *testing.T) {
	p := swapPool(t, 2)
	first, second := exitAt(p, 0), exitAt(p, 1)
	first.noteServed()
	first.noteServed()

	exits := p.Status()["exits"].([]string)
	if !strings.Contains(exits[0], "served=2") {
		t.Fatalf("exits[0] = %q, want served=2", exits[0])
	}
	if !strings.Contains(exits[1], "served=0") {
		t.Fatalf("exits[1] = %q, want served=0 (only the exit that served may count)", exits[1])
	}
	if got := second.servedCount(); got != 0 {
		t.Fatalf("the standby exit counted %d tunnels, want 0", got)
	}
}
