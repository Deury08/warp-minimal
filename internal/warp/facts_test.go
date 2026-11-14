package warp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
