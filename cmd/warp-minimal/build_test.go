package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// shippedBuildIdentity records the identity this test binary was built with,
// captured at package init, before any test can mutate it. It is the only
// trustworthy way to assert the DEFAULTS, because the identifiers are variables
// on purpose (see withBuildIdentity).
var shippedBuildIdentity = [3]string{buildVersion, buildCommit, buildAt}

// withBuildIdentity swaps the linker-injected identity for one test and restores
// it afterwards. Assigning to these identifiers is both the test seam and the
// point: `-ldflags -X main.buildCommit=...` only rewrites package-level
// VARIABLES, so a const here would make every injection a silent no-op and this
// file would not even compile.
func withBuildIdentity(t *testing.T, version, commit, at string) {
	t.Helper()
	oldVersion, oldCommit, oldAt := buildVersion, buildCommit, buildAt
	t.Cleanup(func() { buildVersion, buildCommit, buildAt = oldVersion, oldCommit, oldAt })
	buildVersion, buildCommit, buildAt = version, commit, at
}

// TestBuildIdentityDefaultsAreUnknownNotEmpty pins what a plain `go build`
// reports: the literal "unknown", never an empty string. An empty value reads
// like a broken field; "unknown" reads like "nobody injected this" — and that
// distinction is the whole reason S1 exists.
func TestBuildIdentityDefaultsAreUnknownNotEmpty(t *testing.T) {
	wantVersion, wantCommit, wantAt := "v0.2.3", "unknown", "unknown"
	if got := shippedBuildIdentity; got != [3]string{wantVersion, wantCommit, wantAt} {
		t.Fatalf("shipped build identity = %v, want [%s %s %s]", got, wantVersion, wantCommit, wantAt)
	}
}

// TestHealthPublishesBuildIdentity pins S1: /health must say WHICH binary is
// running, so "runs the installed one" can be told apart from "runs something
// built three hours ago in memory".
func TestHealthPublishesBuildIdentity(t *testing.T) {
	const commit = "677bfa8"
	const at = "2026-11-14T02:50:53Z"
	withBuildIdentity(t, "v0.2.3", commit, at)

	rec := httptest.NewRecorder()
	factsHandler(t, plainPool{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /health: %v", err)
	}

	build, ok := body["build"].(map[string]any)
	if !ok {
		t.Fatalf("/health.build missing: %s", rec.Body.String())
	}
	if build["commit"] != commit {
		t.Fatalf("build.commit = %v, want %q", build["commit"], commit)
	}
	if build["built_at"] != at {
		t.Fatalf("build.built_at = %v, want %q", build["built_at"], at)
	}

	// The stamp is additive: every field the relay already reads stays put.
	if body["ok"] != true {
		t.Fatalf("/health.ok = %v, want true", body["ok"])
	}
	if body["service"] != "warp-minimal" {
		t.Fatalf("/health.service = %v, want warp-minimal", body["service"])
	}
	if body["stack"] != "masque" {
		t.Fatalf("/health.stack = %v, want the stack label main built", body["stack"])
	}
	if _, isArray := body["exits"].([]any); isArray {
		t.Fatal("/health.exits became a JSON array: the relay parses []string")
	}
}

// TestVersionIncludesTheCommit pins the other half of S1: -version keeps
// working and now carries the commit, so `warp-minimal -version` answers the
// same question without starting a pool.
func TestVersionIncludesTheCommit(t *testing.T) {
	withBuildIdentity(t, "v0.2.3", "677bfa8", "2026-11-14T02:50:53Z")

	if got, want := versionLine(), "warp-minimal v0.2.3 (677bfa8)"; got != want {
		t.Fatalf("versionLine = %q, want %q", got, want)
	}
}
