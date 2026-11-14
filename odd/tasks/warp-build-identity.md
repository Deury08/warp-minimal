# warp-build-identity

Make the running binary identifiable, stop /recycle from lying, and publish the per-exit trace error. Requested by the relay owner; no deployment in this change.

Scope: `internal/warp/`, `cmd/warp-minimal/`, focused Go tests.

## Specs

S1 — Build identity in /health (relay owner, verbatim intent):
> "Agregá a `/health` un campo `build:{commit, built_at}` inyectado con `-ldflags -X`, y dame el comando de build completo para que sea reproducible. Sin esto no podemos distinguir 'corre lo instalado' de 'corre algo de hace tres horas en memoria'."

- `/health` publishes `"build": {"commit": "...", "built_at": "..."}`.
- Values come from linker flags: `-X main.buildCommit` and `-X main.buildAt`.
- `buildVersion` (main.go:34) is a `const`; `-X` cannot set a constant, so it becomes a `var` with the same default `v0.2.3`. Same for the two new identifiers.
- Defaults when not injected: the literal `"unknown"`. Never an empty string.
- `built_at` is RFC3339 UTC.
- Exact reproducible command, recorded in the doc and reported back:
  `go build -trimpath -ldflags="-s -w -X main.buildCommit=$(git rev-parse --short HEAD) -X main.buildAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o warp-minimal ./cmd/warp-minimal`
- `-version` keeps working and now includes the commit.

S2 — /recycle must not lie (D13, relay owner):
> "`recycleHandler` pone `recycling:true` siempre, incluso con `started=false`. Reportalo desde la bandera real del pool o sacá el campo."

- Remove the `status["recycling"] = true` override in `recycleHandler` (main.go:266+). The status map already carries the pool's real `p.recycling` from `statusLocked()`.
- Add `"started": <bool from RecycleAll>` so a caller can tell "I started it" from "one was already running".
- KEEP the `202 Accepted` and keep `ok` as today, so the relay's existing `seenRecycling` proof is not broken: during a real recycle `p.recycling` is true and is published as such.

S3 — Per-exit trace error (D6 closure, relay owner):
> "`egressObservation` guarda ip/family/observedAt y tira el error. Publicá `trace:{ok,error,at}` en `ExitFact`, leyendo la cache de 45 s (no fuerces un TLS por request)."

- `egressObservation` (facts.go) gains a stored error string from the last trace attempt.
- `ExitFact` gains `trace` as a nested object: `{"ok": true|false, "error": "<msg, omitted when ok>", "at": <epoch seconds>}`. `at` is 0 when never attempted.
- The value MUST come from the cache; reading facts must never trigger a trace. A successful trace clears the error.
- When no attempt was ever made, `trace` is absent (omitempty semantics), so absence keeps meaning "no sé".

S4 — Out of scope, explicit:
> "NO hagas todavía reconnect sin re-enrolar."

- No `reconnect` verb. No change to enrollment, swap, recycle timing, or the proxy request path.

## Tasks

| ID | Specs | Route | Commit |
|----|-------|-------|--------|
| T1 | S1 | worker | pending |
| T2 | S2 | worker | pending |
| T3 | S3 | worker | pending |

Tests: one RED/GREEN per rule. Each test asserts exit code, exact output field, and that untouched behaviour still holds (`/health.exits` stays []string; `/recycle` still 202; `/health.recycling` still reflects a real recycle).

## Log

L1 — relay owner, verbatim: "Necesito que dejes warp LISTO para UNA sola actualización, sin desplegar nada. Hoy ya movimos producción dos veces y no quiero otra ventana hasta tener todo junto. Código y tests, sin push, sin tocar el 8789 ni el proceso vivo."
L2 — platform note: `buildVersion` is a `const` (main.go:34), and `-ldflags -X` only sets variables. It must become a `var` or the injection silently does nothing.
L3 — risk note for S2: the relay uses `recycling:true` as its primary rotation proof (`seenRecycling`). Removing the override narrows it to real recycles, which is the intent, but the `202` and `ok` must not change.

L4 — T1 (S1) implemented test-first.
> RED #1: `go test ./cmd/warp-minimal/` → `build_test.go:14:52: undefined: buildCommit` **and** `build_test.go:24:21: cannot assign to buildVersion (neither addressable nor a map index expression)`. The second line is L2 reproduced by the compiler, not by reading: a `const` makes `-X` impossible.
> RED #2 (after adding only the two variables and `versionLine`, so the test compiles and the BEHAVIOUR is what fails): `build_test.go:60: /health.build missing: {"ok":true,"service":"warp-minimal","stack":"masque"}`.
> GREEN: `buildVersion`, `buildCommit`, `buildAt` are variables (`v0.2.3`, `unknown`, `unknown`) and `healthHandler` publishes `"build": {"commit", "built_at"}`. Three tests pass; the same test still asserts `ok`/`service`/`stack` unchanged and `/health.exits` still non-array.
> Linker injection proven end to end, not inferred (temp dir, `-version` only: it returns before `loadConfig`, so no pool, no enrollment, no listener, nothing touching 8789):
> - `go build -trimpath -ldflags="-s -w -X main.buildCommit=$(git rev-parse --short HEAD) -X main.buildAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o $SCRATCH/warp-minimal ./cmd/warp-minimal` → `warp-minimal v0.2.3 (677bfa8)`
> - `go build -o $SCRATCH/warp-plain ./cmd/warp-minimal` (no `-ldflags`) → `warp-minimal v0.2.3 (unknown)`
> So an injection that silently does nothing is now observable in one command.
> `built_at` format: `date -u +%Y-%m-%dT%H:%M:%SZ` → `2026-11-14T14:23:03Z`, which round-trips through `date -u -d` unchanged (RFC3339 UTC by construction).
> Reproducible build command (S1, verbatim):
> `go build -trimpath -ldflags="-s -w -X main.buildCommit=$(git rev-parse --short HEAD) -X main.buildAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o warp-minimal ./cmd/warp-minimal`
> Not observed live: `/health.build` from a running server. Serving `/health` requires a pool, and a pool enrolls; the field is pinned by the handler test only.

L5 — T2 (S2) implemented test-first.
> RED: `recycling = true, want false: the pool is not recycling, so /recycle must not say it is` and `started missing from the /recycle answer: map[ok:true recycling:true]`.
> GREEN: the `status["recycling"] = true` override is gone; `status["started"] = started` is added. `202` unchanged, `ok` keeps meaning `started` unchanged, and `recycling` is now whatever `statusLocked()` reported under `Pool.mu` — so a call that arrives during a real cycle still answers `recycling:true` (test `TestRecycleKeepsTheRealFlagDuringARealRecycle` guards the relay's `seenRecycling` proof). `GET`/`PUT` still 405.
> Consequence, recorded instead of hidden: the WireGuard pool's `statusSnapshotLocked()` (wg_pool.go:331+) has no `recycling` key at all, so on `stack:"wireguard"` `/recycle` now answers WITHOUT `recycling` (the handler used to force `true` there). Fixing that means adding a real flag to `wgPool`, which is outside this change's edit surface. The deployed stack is MASQUE (`defaultStack = "ipv6"`, `stackFamily`), so this rebuild does not narrow the live proof; the owner should still decide whether the WG stack deserves the same verb.

L6 — T3 (S3) implemented test-first.
> RED #1: `unknown field Trace in struct literal of type warp.ExitFact`, `undefined: warp.TraceFact`, `e.traceFact undefined`.
> RED #2 (after adding only the types and `traceFact`, so behaviour is what fails): `traceFact absent after a successful trace` and `ExitFacts trace absent, want the cached trace result`.
> GREEN: `egressObservation` keeps `traceErr`/`traceAt`; every attempt stamps `traceAt`, a failure stores `err.Error()` while still serving the cached IP, and a success clears `traceErr`. `ExitFact.Trace` is assembled from `traceFact()`, which only READS `obs` under `obsMu` — a fact read never forces a TLS handshake, proven by a dial counter that stays at 1 across `ExitFacts` plus `ExitFact` calls inside the TTL. `trace` is absent (nil, `omitempty`) when no attempt was ever made, and `error` is `omitempty` so `ok:true` carries no empty string.
> `trace.at` is the epoch of the last ATTEMPT; after a successful trace it equals `observed_at` (same instant, asserted). `dial == nil` (exit with no tunnel, never traced) still returns `ErrNoTunnel` without stamping an attempt, so `trace` stays absent there: "no sé" is preferred over a synthesized error.
> Wire shape pinned at the handler too (`/exits`): `trace:{"ok":true,"at":...}` with no `error` key, `trace:{"ok":false,"error":"...","at":...}`, and no `trace` key for an exit never observed.

L7 — verification for the three tasks: `go vet ./...` clean; `go test -count=1 ./...` clean; 65 top-level tests in `cmd/warp-minimal` + `internal/warp` (11 added: 3 build, 4 recycle, 3 trace facts, 1 `/exits` trace shape). Nothing was built into, deployed to, or probed against `~/.pi/agent/pi-free-bridge/warp/`, 127.0.0.1:8789, or any live process; no `RegisterDevice`, no enrollment, no `/recycle` or `/swap` was ever called on a real pool. The only build outputs were two `-version`-only binaries in a `mktemp -d` directory outside the worktree.
> Commit execution is parent-owned in this run: the worker implemented and verified T1-T3 but did not run `git add`/`git commit` (binding tool-safety rule for this role). Intended split, one commit per task, so the parent can stage by hunk — `main.go` is touched by T1 (lines ~31-55 identity block, `-version`, `healthHandler`) and T2 (`recycleHandler`), while each task owns its test file:
> - T1: `cmd/warp-minimal/main.go` (identity vars + `versionLine` + `healthHandler`), `cmd/warp-minimal/build_test.go`
> - T2: `cmd/warp-minimal/main.go` (`recycleHandler`), `cmd/warp-minimal/recycle_test.go`
> - T3: `internal/warp/facts.go`, `internal/warp/facts_test.go`, `cmd/warp-minimal/facts_test.go`
> - this doc's Log entries travel with whichever commit closes the slice (or a separate `docs(odd)` commit).

L8 — known formatting debt, deliberately NOT touched: `gofmt -l` reports `cmd/warp-minimal/facts_test.go`, `internal/warp/pool.go`, `pool_test.go`, `proxy_test.go`, `proxy_originform_test.go`, `types.go`, `wg_exit.go`, `wg_registrar.go` on the base commit too. `gofmt -d cmd/warp-minimal/facts_test.go` shows only pre-existing alignment of the `fakeFactsPool`/`plainPool` method sets; the added test code is already formatted. Reformatting those files would be a drive-by diff inside this change.

S15 — Not implemented, on purpose (S4): no `reconnect` verb, no change to enrollment, swap, recycle timing, the proxy request path, the catch-all `/` route, or `/health.exits` (`[]string` preserved and asserted).
