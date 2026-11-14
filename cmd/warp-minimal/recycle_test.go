package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recyclePool is an appPool whose RecycleAll returns exactly what the test
// dictates, so /recycle's answer can be compared against the POOL's real
// recycling flag instead of a constant baked into the handler.
type recyclePool struct {
	started bool
	status  map[string]any
}

func (recyclePool) Status() map[string]any { return map[string]any{} }

func (p recyclePool) RecycleAll() (bool, map[string]any) { return p.started, p.status }

func (recyclePool) Close() {}

// postRecycle sends the one request /recycle accepts and decodes the answer.
func postRecycle(t *testing.T, pool appPool) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	recycleHandler(pool).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/recycle", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /recycle: %v (body=%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

// TestRecycleDoesNotInventARecycleThatIsNotRunning pins D13: the handler used to
// hardcode recycling=true even for a call that started nothing, which makes the
// field useless as evidence. It must publish the pool's real flag.
func TestRecycleDoesNotInventARecycleThatIsNotRunning(t *testing.T) {
	code, body := postRecycle(t, recyclePool{
		started: false,
		status:  map[string]any{"recycling": false, "active": 2, "pool_size": 2},
	})

	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (unchanged for the relay)", code)
	}
	if got, ok := body["recycling"].(bool); !ok || got {
		t.Fatalf("recycling = %v, want false: the pool is not recycling, so /recycle must not say it is", body["recycling"])
	}
	if body["ok"] != false {
		t.Fatalf("ok = %v, want false: ok keeps meaning started", body["ok"])
	}
	// The rest of the pool snapshot still rides along.
	if body["active"] != float64(2) || body["pool_size"] != float64(2) {
		t.Fatalf("pool snapshot changed: %v", body)
	}
}

// TestRecycleKeepsTheRealFlagDuringARealRecycle is the guard for the relay's
// rotation proof: a call that arrives while a recycle is already in flight is
// still 202 and still carries recycling=true, because that IS the pool's flag.
func TestRecycleKeepsTheRealFlagDuringARealRecycle(t *testing.T) {
	code, body := postRecycle(t, recyclePool{
		started: false,
		status:  map[string]any{"recycling": true, "active": 2},
	})

	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", code)
	}
	if body["recycling"] != true {
		t.Fatalf("recycling = %v, want true while the pool reports a cycle in flight", body["recycling"])
	}
	if body["started"] != false {
		t.Fatalf("started = %v, want false for a call that did not start the cycle", body["started"])
	}
}

// TestRecycleExposesStarted is the other half of D13: the caller must be able to
// tell "I started it" from "one was already running".
func TestRecycleExposesStarted(t *testing.T) {
	cases := []struct {
		name    string
		started bool
	}{
		{name: "this call started the cycle", started: true},
		{name: "a cycle was already running", started: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postRecycle(t, recyclePool{
				started: tc.started,
				status:  map[string]any{"recycling": true},
			})

			if code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202", code)
			}
			got, ok := body["started"].(bool)
			if !ok {
				t.Fatalf("started missing from the /recycle answer: %v", body)
			}
			if got != tc.started {
				t.Fatalf("started = %v, want %v (the value RecycleAll reported)", got, tc.started)
			}
			if body["ok"] != tc.started {
				t.Fatalf("ok = %v, want %v (unchanged: ok means started)", body["ok"], tc.started)
			}
		})
	}
}

// TestRecycleRejectsNonPOST keeps the method contract the bridge already relies
// on.
func TestRecycleRejectsNonPOST(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		rec := httptest.NewRecorder()
		recycleHandler(recyclePool{status: map[string]any{}}).
			ServeHTTP(rec, httptest.NewRequest(method, "/recycle", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /recycle status = %d, want 405", method, rec.Code)
		}
	}
}

// TestRecycleKeepsTheFieldOnPoolsWithoutARealFlag pins the regression the D13 fix
// introduced: the WireGuard snapshot carries no "recycling" key, so dropping the
// handler's override made the field vanish from the answer. The relay reads that
// field, and an absent key is neither true nor false. The key must always be there.
func TestRecycleKeepsTheFieldOnPoolsWithoutARealFlag(t *testing.T) {
	code, body := postRecycle(t, recyclePool{
		started: false,
		status:  map[string]any{"active": 2, "pool_size": 2},
	})

	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}
	v, ok := body["recycling"]
	if !ok {
		t.Fatalf("recycling missing from the answer: %v", body)
	}
	if v != false {
		t.Fatalf("recycling = %v, want false", v)
	}
}
