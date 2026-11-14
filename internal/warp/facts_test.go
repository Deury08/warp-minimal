package warp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// basicAuth builds the exact header Bun sends when the proxy URL carries
// credentials: the exit id is the user and the password is ignored.
func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestRequestedExitID(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{name: "id as user with empty password", header: basicAuth("warp-abc", ""), want: "warp-abc"},
		{name: "id with some password", header: basicAuth("warp-abc", "s3cret"), want: "warp-abc"},
		{name: "lowercase scheme", header: "basic " + base64.StdEncoding.EncodeToString([]byte("warp-abc:")), want: "warp-abc"},
		{name: "absent header", header: "", want: ""},
		{name: "not basic", header: "Bearer warp-abc", want: ""},
		{name: "invalid base64", header: "Basic !!!not-base64!!!", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
			if tc.header != "" {
				r.Header.Set("Proxy-Authorization", tc.header)
			}
			if got := requestedExitID(r); got != tc.want {
				t.Fatalf("requestedExitID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequestedExitIDNilRequest(t *testing.T) {
	if got := requestedExitID(nil); got != "" {
		t.Fatalf("requestedExitID(nil) = %q, want \"\"", got)
	}
}

// exitIDs snapshots the pool's exit ids in slice order.
func exitIDs(p *Pool) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := make([]string, len(p.exits))
	for i, e := range p.exits {
		ids[i] = e.ID
	}
	return ids
}

func TestAcquirePreferPicksTheRequestedExit(t *testing.T) {
	p := swapPool(t, 2)
	ids := exitIDs(p)

	// Pedir la SEGUNDA: si el prefer funcionara mal, Acquire devolvería la primera
	// (el pool recorre la slice en orden) y el test lo vería.
	got, err := p.AcquirePrefer(context.Background(), ids[1])
	if err != nil {
		t.Fatalf("AcquirePrefer: %v", err)
	}
	if got.ID != ids[1] {
		t.Fatalf("AcquirePrefer = %q, want %q", got.ID, ids[1])
	}
	if got.streams != 1 {
		t.Fatalf("streams = %d after acquire, want 1", got.streams)
	}
	p.Release(got)
}

func TestAcquirePreferUnknownIDFallsBackSilently(t *testing.T) {
	p := swapPool(t, 2)
	ids := exitIDs(p)

	got, err := p.AcquirePrefer(context.Background(), "warp-does-not-exist")
	if err != nil {
		t.Fatalf("AcquirePrefer with an unknown id must fall back, got error: %v", err)
	}
	if egressExitID(got) != ids[0] {
		t.Fatalf("fallback = %q, want the pool's normal first choice %q", egressExitID(got), ids[0])
	}
	p.Release(got)
}

func TestAcquirePreferDrainingFallsBackSilently(t *testing.T) {
	p := swapPool(t, 2)
	ids := exitIDs(p)

	p.mu.Lock()
	p.exits[1].draining = true
	p.mu.Unlock()

	got, err := p.AcquirePrefer(context.Background(), ids[1])
	if err != nil {
		t.Fatalf("AcquirePrefer on a draining exit must fall back, got error: %v", err)
	}
	if egressExitID(got) == ids[1] {
		t.Fatalf("AcquirePrefer handed out the draining exit %q (a swap in flight must take no new work)", ids[1])
	}
	p.Release(got)
}

// traceText is a faithful slice of the real cdn-cgi/trace body: key=value per
// line, with ip= being the only thing the pool cares about.
const traceText = "fl=123abc\nh=1.1.1.1\nip=2606:4700:10::6816:1a1a\nts=1700000000.0\nwarp=on\n"

// tlsTraceServer serves traceText over TLS, standing in for 1.1.1.1.
func tlsTraceServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dialTo adapts a local TLS server to the trace dialer signature.
func dialTo(srv *httptest.Server) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
}

func TestTraceEgressIPReadsTheIPLine(t *testing.T) {
	srv := tlsTraceServer(t, traceText)

	ip, err := traceEgressIP(context.Background(), dialTo(srv))
	if err != nil {
		t.Fatalf("traceEgressIP: %v", err)
	}
	if want := "2606:4700:10::6816:1a1a"; ip != want {
		t.Fatalf("ip = %q, want %q", ip, want)
	}
}

func TestTraceEgressIPRejectsBodyWithoutIP(t *testing.T) {
	srv := tlsTraceServer(t, "fl=123abc\nwarp=on\n")

	if _, err := traceEgressIP(context.Background(), dialTo(srv)); err == nil {
		t.Fatal("traceEgressIP accepted a body with no ip= line")
	}
}

func TestObserveEgressIPCachesTheTrace(t *testing.T) {
	e := fakeExit("warp-cache")
	srv := tlsTraceServer(t, traceText)

	dials := 0
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials++
		return dialTo(srv)(ctx, network, addr)
	}

	for i := 0; i < 3; i++ {
		ip, family, at, err := e.observeEgressIP(context.Background(), dial)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if family != "v6" {
			t.Fatalf("call %d: family = %q, want v6 (the trace reported an IPv6 egress)", i, family)
		}
		if ip == "" || at.IsZero() {
			t.Fatalf("call %d: ip=%q observedAt=%v, want both set", i, ip, at)
		}
	}

	if dials != 1 {
		t.Fatalf("dials = %d for 3 calls inside the TTL, want 1 (the relay polls this per request)", dials)
	}
}

func TestObserveEgressIPServesCachedIPWhenTheTraceFails(t *testing.T) {
	e := fakeExit("warp-stale")
	srv := tlsTraceServer(t, traceText)

	if _, _, _, err := e.observeEgressIP(context.Background(), dialTo(srv)); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}

	// Force the entry to look stale, then break the transport.
	e.obsMu.Lock()
	e.obs.observedAt = time.Now().Add(-2 * traceCacheTTL)
	e.obsMu.Unlock()
	srv.Close()

	ip, _, at, err := e.observeEgressIP(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("boom")
	})
	if err == nil {
		t.Fatal("a failed trace with a cached value must still report the error, so the caller can tell stale from fresh")
	}
	if ip != "2606:4700:10::6816:1a1a" {
		t.Fatalf("ip = %q, want the cached value: a stale IP is actionable, a hole is not", ip)
	}
	if at.IsZero() {
		t.Fatal("observedAt = zero, want the time of the successful observation")
	}
}

func TestObserveEgressIPWithoutTunnelReportsNoIP(t *testing.T) {
	e := &Exit{ID: "warp-no-tunnel"}

	ip, family, at, err := e.ObserveEgressIP(context.Background())
	if err == nil {
		t.Fatal("ObserveEgressIP without a tunnel must fail")
	}
	if ip != "" || family != "" || !at.IsZero() {
		t.Fatalf("ip=%q family=%q at=%v, want all empty on a tunnel-less exit", ip, family, at)
	}
}

func TestFactLockedUsesAbsoluteEpochAndZeroForUnset(t *testing.T) {
	e := fakeExit("warp-facts")
	e.CreatedAt = time.Unix(1700000000, 0)
	e.Cooldown = time.Unix(1700000900, 0)

	f := e.factLocked()

	if f.CreatedAt != 1700000000 {
		t.Fatalf("created_at = %d, want 1700000000 (absolute epoch)", f.CreatedAt)
	}
	if f.CooldownUntil != 1700000900 {
		t.Fatalf("cooldown_until = %d, want 1700000900", f.CooldownUntil)
	}
	if f.InUseSince != 0 {
		t.Fatalf("in_use_since = %d, want 0 for an unset time (0 means never, not 1970)", f.InUseSince)
	}
	if f.State != "cooldown" {
		t.Fatalf("state = %q, want cooldown", f.State)
	}
	if f.ID != "warp-facts" {
		t.Fatalf("id = %q, want warp-facts", f.ID)
	}
}

// TestTraceFactIsAbsentWhenNoAttemptWasMade pins the absence semantics: no
// attempt ever made means no `trace` key, because absence keeps reading "no sé".
func TestTraceFactIsAbsentWhenNoAttemptWasMade(t *testing.T) {
	e := &Exit{ID: "warp-untraced"}
	if tr, ok := e.traceFact(); ok {
		t.Fatalf("traceFact = %+v, want absent on an exit that was never traced", tr)
	}

	p := &Pool{exits: []*Exit{e}}
	facts := p.ExitFacts(context.Background())
	if len(facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(facts))
	}
	if facts[0].Trace != nil {
		t.Fatalf("trace = %+v, want a nil field so it is omitted from JSON", facts[0].Trace)
	}
}

// TestObserveEgressIPRecordsTheTraceError pins D6: the trace error is kept, not
// thrown away, and a later success clears it.
func TestObserveEgressIPRecordsTheTraceError(t *testing.T) {
	e := &Exit{ID: "warp-trace-error"}
	srv := tlsTraceServer(t, traceText)

	if _, _, _, err := e.observeEgressIP(context.Background(), dialTo(srv)); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	tr, ok := e.traceFact()
	if !ok {
		t.Fatal("traceFact absent after a successful trace")
	}
	if !tr.OK || tr.Error != "" || tr.At == 0 {
		t.Fatalf("after a successful trace: %+v, want ok=true, no error, at>0", tr)
	}

	// Force the cache stale, then break the transport.
	e.obsMu.Lock()
	e.obs.observedAt = time.Now().Add(-2 * traceCacheTTL)
	e.obsMu.Unlock()
	srv.Close()

	failDial := func(context.Context, string, string) (net.Conn, error) { return nil, fmt.Errorf("boom") }
	if _, _, _, err := e.observeEgressIP(context.Background(), failDial); err == nil {
		t.Fatal("a failed trace must still return the error")
	}
	tr, ok = e.traceFact()
	if !ok {
		t.Fatal("traceFact absent after a failed attempt: the failure is the fact worth publishing")
	}
	if tr.OK {
		t.Fatal("trace.ok = true after a failed attempt")
	}
	if !strings.Contains(tr.Error, "boom") {
		t.Fatalf("trace.error = %q, want the trace failure detail", tr.Error)
	}
	if tr.At == 0 {
		t.Fatal("trace.at = 0 after an attempt, want the attempt time")
	}

	// A successful trace clears the error.
	if _, _, _, err := e.observeEgressIP(context.Background(), dialTo(tlsTraceServer(t, traceText))); err != nil {
		t.Fatalf("successful retry: %v", err)
	}
	tr, _ = e.traceFact()
	if !tr.OK || tr.Error != "" {
		t.Fatalf("after a successful retry: %+v, want the error cleared", tr)
	}
}

// TestExitFactsReadsTheTraceFromTheCache pins that publishing the trace never
// costs a TLS handshake: the value comes from the 45s cache.
func TestExitFactsReadsTheTraceFromTheCache(t *testing.T) {
	srv := tlsTraceServer(t, traceText)
	dials := 0
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials++
		return dialTo(srv)(ctx, network, addr)
	}

	// No Tunnel on purpose: if reading a fact dialled, this exit could not.
	e := &Exit{ID: "warp-cached-trace"}
	if _, _, _, err := e.observeEgressIP(context.Background(), dial); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	if dials != 1 {
		t.Fatalf("dials = %d while priming, want 1", dials)
	}

	p := &Pool{exits: []*Exit{e}}
	facts := p.ExitFacts(context.Background())
	one, found := p.ExitFact(context.Background(), "warp-cached-trace")

	if dials != 1 {
		t.Fatalf("dials = %d after reading facts inside the TTL, want 1: a fact read must never force a trace", dials)
	}
	if !found {
		t.Fatal("ExitFact did not find the exit")
	}
	for name, f := range map[string]ExitFact{"ExitFacts": facts[0], "ExitFact": one} {
		if f.IP != "2606:4700:10::6816:1a1a" {
			t.Fatalf("%s ip = %q, want the cached egress IP", name, f.IP)
		}
		if f.Trace == nil {
			t.Fatalf("%s trace absent, want the cached trace result", name)
		}
		if !f.Trace.OK || f.Trace.Error != "" {
			t.Fatalf("%s trace = %+v, want ok=true with no error", name, *f.Trace)
		}
		if f.Trace.At != f.ObservedAt || f.Trace.At == 0 {
			t.Fatalf("%s trace.at = %d vs observed_at = %d, want the same attempt epoch", name, f.Trace.At, f.ObservedAt)
		}
	}
}

// TestStateLockedValues pins the state vocabulary the relay maps without
// translating, and that /health keeps publishing as a plain word.
func TestStateLockedValues(t *testing.T) {
	cases := []struct {
		name string
		exit *Exit
		want string
	}{
		{name: "healthy", exit: fakeExit("a"), want: "healthy"},
		{name: "starting", exit: &Exit{ID: "b"}, want: "starting"},
		{name: "cooldown", exit: func() *Exit { e := fakeExit("c"); e.Cooldown = time.Now(); return e }(), want: "cooldown"},
		{name: "in_use", exit: func() *Exit { e := fakeExit("d"); e.streams = 1; return e }(), want: "in_use"},
		{name: "draining wins over cooldown", exit: func() *Exit { e := fakeExit("e"); e.Cooldown = time.Now(); e.draining = true; return e }(), want: "draining"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.exit.stateLocked(); got != tc.want {
				t.Fatalf("stateLocked = %q, want %q", got, tc.want)
			}
		})
	}
}
