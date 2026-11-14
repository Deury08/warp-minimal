package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Deury08/warp-minimal/internal/warp"
)

// fakeFactsPool satisfies appPool plus the optional exitFacts capability.
type fakeFactsPool struct {
	facts []warp.ExitFact
}

func (fakeFactsPool) Status() map[string]any          { return map[string]any{"ok": true} }
func (fakeFactsPool) RecycleAll() (bool, map[string]any) { return false, map[string]any{} }
func (fakeFactsPool) Close()                          {}

func (f fakeFactsPool) ExitFacts(context.Context) []warp.ExitFact { return f.facts }

func (f fakeFactsPool) ExitFact(_ context.Context, id string) (warp.ExitFact, bool) {
	for _, fact := range f.facts {
		if fact.ID == id {
			return fact, true
		}
	}
	return warp.ExitFact{}, false
}

// plainPool is an appPool WITHOUT the exitFacts capability, standing in for the
// WireGuard stack: the fact endpoints must report 404, not a broken response.
type plainPool struct{}

func (plainPool) Status() map[string]any              { return map[string]any{} }
func (plainPool) RecycleAll() (bool, map[string]any)  { return false, map[string]any{} }
func (plainPool) Close()                              {}

// neverProxy fails the test if the fallback proxy is reached: the fact/
// health/verb routes must all be matched by the mux before it.
func neverProxy(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("proxy invoked for %s %s; the mux should have matched a route", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}
}

func factsHandler(t *testing.T, pool appPool) http.Handler {
	t.Helper()
	return newHandler(Config{HealthPath: "/health"}, pool, neverProxy(t), "masque")
}

func sampleFacts() []warp.ExitFact {
	return []warp.ExitFact{
		{
			ID:         "warp-18e7cb21a5cbd555",
			State:      "healthy",
			Served:     3,
			Streams:    0,
			CreatedAt:  1700000000,
			InUseSince: 1700000500,
			IP:         "2606:4700:10::6816:1a1a",
			Family:     "v6",
			ObservedAt: 1700000600,
		},
		{
			ID:        "warp-18e7cb21a3af12f4",
			State:     "cooldown",
			Served:    0,
			CreatedAt: 1700000100,
		},
	}
}

func TestExitsHandlerReturnsTheStructuredArray(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/exits", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not a JSON array: %v (body=%s)", err, rec.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0]["id"] != "warp-18e7cb21a5cbd555" {
		t.Fatalf("id = %v, want warp-18e7cb21a5cbd555", got[0]["id"])
	}
	// Epoch absoluto, no un delta: el plano de control lo compara contra su reset_at.
	if got[0]["created_at"] != float64(1700000000) {
		t.Fatalf("created_at = %v, want 1700000000", got[0]["created_at"])
	}
	if got[0]["observed_at"] != float64(1700000600) {
		t.Fatalf("observed_at = %v, want 1700000600", got[0]["observed_at"])
	}
	if got[0]["ip"] != "2606:4700:10::6816:1a1a" || got[0]["family"] != "v6" {
		t.Fatalf("ip/family = %v/%v, want the observed v6 egress", got[0]["ip"], got[0]["family"])
	}
	// Una exit sin trace todavía reporta el resto: ip/observed_at ausentes.
	if _, ok := got[1]["ip"]; ok {
		t.Fatalf("second exit carries ip=%v, want the field absent when never observed", got[1]["ip"])
	}
	if got[1]["state"] != "cooldown" {
		t.Fatalf("state = %v, want cooldown", got[1]["state"])
	}
}

func TestExitHandlerReturnsOneFact(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/exit/warp-18e7cb21a3af12f4", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not a JSON object: %v", err)
	}
	if got["id"] != "warp-18e7cb21a3af12f4" {
		t.Fatalf("id = %v, want the requested exit", got["id"])
	}
}

func TestExitHandlerUnknownIDIs404(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/exit/warp-does-not-exist", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown exit id", rec.Code)
	}
}

func TestExitHandlerEmptyIDIs404(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/exit/", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an empty exit id", rec.Code)
	}
}

func TestFactEndpointsRejectNonGET(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	for _, path := range []string{"/exits", "/exit/warp-18e7cb21a5cbd555"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d, want 405", path, rec.Code)
		}
	}
}

// TestFactEndpointsAre404OnStacksWithoutFacts pins the capability detection the
// relay relies on: no support means 404, never a 500.
func TestFactEndpointsAre404OnStacksWithoutFacts(t *testing.T) {
	h := factsHandler(t, plainPool{})

	for _, path := range []string{"/exits", "/exit/warp-anything"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404 when the stack has no per-exit facts", path, rec.Code)
		}
	}
}

// TestHealthKeepsTheStringExits is the contract guard against a future cleanup:
// the relay parses this exact shape, so /health must keep publishing []string.
func TestHealthKeepsTheStringExits(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if _, ok := got["exits"].([]any); ok {
		t.Fatal("/health.exits became a JSON array: the relay parses []string and must not be broken")
	}
}
