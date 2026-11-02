# Feature: Warp WireGuard rollout (make WARP actually useful)

## Objective

Deploy the WireGuard stack (already merged on main as v0.2.0, never deployed
live) as the production egress for pi-free-bridge, prove E2E that the old
failure mode (502 on large payloads / stalled 64KB uploads) is gone, and
harden the repo state so what we ship matches what is tagged.

## Problem

- pi-free-bridge 502s under WARP come from the MASQUE stack: exits die on
  their own, replacement registration can leave the pool empty, and uploads
  >=64KB stall ~15.13s and die (root cause of "WARP always 502").
- WireGuard egress (v0.2.0) passed its live check (warp=on via cdn-cgi/trace)
  but was never deployed to the plugin (plugin still runs the MASQUE v0.1.2
  binary from the same path, currently PID 6116 with warpEnabled "off").
- Unreleased work sits on main after the v0.2.0 tag: Acquire 10s timeout fix
  (6227fd6) plus an uncommitted MASQUE-pool RecycleAll (idempotent recycle,
  tunnel close on replace, counter recalculation). Build/vet/tests pass with
  these included.

## Scope & constraints

- Repo: C:/Users/Polanco/warp-minimal (main, synced). Deployment target:
  C:/Users/Polanco/.pi/agent/pi-free-bridge/warp/warp-minimal.exe.
- Do not touch the user's live config beyond what the test needs; restore
  anything that fails.
- Working test port for standalone binary: 8791 (8789 occupied by PID 6116).
- MASQUE path stays in the codebase as fallback (`stack: "masque"`); we are
  only switching the deployed default to wireguard.

## Tasks

| ID | Task | Route | Status |
|----|------|-------|--------|
| T1 | Commit leftover MASQUE pool RecycleAll + ignore test logs; fix stale `version` string (v0.1.0 -> v0.2.1); work-unit commit | inline | pending |
| T2 | Build binary; standalone smoke on test port 8791: /health, /recycle, trace via proxy -> warp=on | inline | pending |
| T3 | Deploy to plugin warp dir (backup old exe), enable warp "on" in bridge config, make sure proxy runs the new WG binary on 8789 | inline | pending |
| T4 | Live E2E through relay: big POST (~64KB) through warp (old killer repro) + real request round; no 502 | inline | pending |
| T5 | Record results, tag v0.2.1 if green, update task doc + memory | inline | pending |

## Verification checklist

- `go build ./... && go vet ./... && go test ./internal/warp/` green.
- Standalone: `curl -x http://127.0.0.1:8791 https://1.1.1.1/cdn-cgi/trace` => warp=on.
- Deployed: `curl 127.0.0.1:8789/health` => healthy > 0 with WG stack.
- E2E: POST >64KB via warp through proxy AND through bridge relay returns 200.
- Old MASQUE binary kept as backup; rollback = restore backup + revert config.

## Log

- 2026-11-02: feature doc created after session state reconciliation
  (v0.2.0 on origin, Acquire fix + uncommitted RecycleAll behind it,
  plugin still running MASQUE binary). User approved WireGuard rollout.
