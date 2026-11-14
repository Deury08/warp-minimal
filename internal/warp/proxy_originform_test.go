package warp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordingPool is a pool that remembers every exit blamed for a failure.
type recordingPool struct {
	exit   EgressDialer
	failed []string
}

func (p *recordingPool) Acquire(ctx context.Context) (EgressDialer, error) { return p.exit, nil }
func (p *recordingPool) Release(exit EgressDialer)                        {}
func (p *recordingPool) Fail(exit EgressDialer, reason string) {
	p.failed = append(p.failed, reason)
}

// TestOriginFormRequestDialsTheRealHost pins the rule that a plain, origin-form
// request (GET /path, what browsers, probes and misaimed health checks send) is
// dialled to its Host header.
//
// The bug this covers: proxyRequest read only r.URL.Host, which is empty for
// origin-form, so the address became ":80", the dial failed, and the exit was
// blamed for 30 minutes of cooldown. One ordinary GET / could take a healthy
// exit out of rotation.
func TestOriginFormRequestDialsTheRealHost(t *testing.T) {
	var gotAddr string
	exit := &stubEgress{id: "warp-aaaa1111", dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		gotAddr = addr
		return nil, fmt.Errorf("dial refused by test")
	}}
	pool := &recordingPool{exit: exit}

	req := httptest.NewRequest(http.MethodGet, "/", nil) // origin-form, r.URL.Host == ""
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	ProxyHandlerEgress(pool)(rec, req)

	if gotAddr != "example.com:80" {
		t.Fatalf("dialled %q, want %q: an origin-form request must use its Host header, not an empty authority", gotAddr, "example.com:80")
	}
}

// TestRequestWithoutHostDoesNotBlameTheExit covers the case where there is no
// host at all. That is a client mistake, so it must answer 400 and leave the
// exit untouched: an unusable request must never cost 30 minutes of rotation.
func TestRequestWithoutHostDoesNotBlameTheExit(t *testing.T) {
	exit := &stubEgress{id: "warp-bbbb2222", dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("dial refused by test")
	}}
	pool := &recordingPool{exit: exit}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = ""
	req.URL.Host = ""
	rec := httptest.NewRecorder()

	ProxyHandlerEgress(pool)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for a request with no host", rec.Code, http.StatusBadRequest)
	}
	if len(pool.failed) != 0 {
		t.Fatalf("exit was blamed %d time(s) for a client-side mistake: %v", len(pool.failed), pool.failed)
	}
}

// TestValidHostDialFailureStillBlamesTheExit is the guard on the other side: a
// real dial failure against a well-formed target is still an exit failure, so
// the pool can replace it. Fixing the empty-host case must not silence this.
func TestValidHostDialFailureStillBlamesTheExit(t *testing.T) {
	exit := &stubEgress{id: "warp-cccc3333", dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("tunnel is down")
	}}
	pool := &recordingPool{exit: exit}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()

	ProxyHandlerEgress(pool)(rec, req)

	if len(pool.failed) != 1 {
		t.Fatalf("exit blamed %d time(s), want exactly 1: a real dial failure must still count", len(pool.failed))
	}
}
