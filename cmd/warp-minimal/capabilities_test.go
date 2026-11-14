package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthDeclaresExitsCapability pins the signal the control plane needs.
//
// It must not probe for /exits: pointed at a build without the route (or with
// the old catch-all proxy behaviour), that probe lands on the proxy, the pool
// blames an exit and the exit cools down for 30 minutes. A diagnostic read
// costing a working exit is not acceptable, so the capability is declared here
// instead of discovered by hitting it.
func TestHealthDeclaresExitsCapability(t *testing.T) {
	h := factsHandler(t, fakeFactsPool{facts: sampleFacts()})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /health: %v", err)
	}

	caps, ok := body["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("/health.capabilities missing; the control plane reads absence as legacy: %s", rec.Body.String())
	}
	if got, ok := caps["exits"].(bool); !ok || !got {
		t.Fatalf("capabilities.exits = %v, want true", caps["exits"])
	}
}

// TestHealthOmitsCapabilityWithoutFacts covers the other half of the contract:
// a build that does not serve /exits must OMIT the key, not send false. Absence
// is what keeps an old binary from being able to lie about what it supports.
func TestHealthOmitsCapabilityWithoutFacts(t *testing.T) {
	h := factsHandler(t, plainPool{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	if _, present := body["capabilities"]; present {
		t.Fatalf("/health.capabilities must be absent without the /exits route, got: %s", rec.Body.String())
	}
}
