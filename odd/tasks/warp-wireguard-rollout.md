# Feature: Warp WireGuard rollout (make WARP actually useful)

> **PIVOT (2026-11-02):** the WG rollout is CANCELLED on this network. Clean
> test after removing the local firewall Blocks: 19/19 WG endpoints fail to
> answer a handshake from this machine, while MASQUE (QUIC UDP 443, same IPs)
> works — the ISP DPI selectively drops WireGuard. New goal: fix the MASQUE
> stack's >=64KB upload stall (root cause hypothesis: QUIC flow-control
> credit never replenished on send), using
> C:\Users\Polanco\.local\temp\opencode\usque-src (shallow clone of
> Diniboy1123/usque, the reference that provably handles 64KB+ uploads in
> 0.58s/0.89s) as the source of truth. WG code stays as `stack:
> "wireguard"` for networks where WG UDP passes.

## Objective (was: deploy WG stack)

Fix the MASQUE stack (already merged on main, v0.1.2 deployed in the plugin)
so pi-free-bridge can actually use WARP egress under real traffic: no 502s
on large payloads, exits kept healthy, prove E2E.

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
| T1 | Commit leftover MASQUE pool RecycleAll + ignore test logs; fix stale `version` string (v0.1.0 -> v0.2.1); work-unit commit | inline | done (00ccefe) |
| T1.1 | WG local firewall Blocks removed (6 rules); WG endpoints rescan: 19/19 handshake false -> WG unfeasible on this ISP; pivot decided | inline | done |
| T1.2 | usque live test: register + l4-http-proxy on 8792; trace warp=on; 64KB & 200KB uploads 200 OK -> stall is our bug, not protocol/ISP | inline | done |
| T2 | Explore delegation: map usque flow-control/QUIC config vs our masque.go upload path; return root cause + fix plan with path:line evidence | delegated explore | pending |
| T3 | Implement flow-control fix in internal/warp (go slice; RED repro test if feasible) | inline | done (code) |
| T3.2 | Wire stack=masque into main.go: unified EgressPool interface in proxy.go + stack switch in main.go | delegated writer | done (code) |
| T4 | Verify: unit tests green; standalone repro via local MASQUE proxy binary on test port: 64KB+ upload 200 OK, trace warp=on | inline | done — live 8793: 64KB 200@3.4s, 200KB 200@1.1s, 1MB 200@10.6s, warp=on, pool healthy |
| T5 | E2E through bridge: enable warp, big POST via relay, real round; no 502 | inline | pending — needs deploy to plugin + warpEnabled on (user gate) |
| T6 | Record results, tag v0.2.1 (incl. Acquire fix + RecycleAll + flow-control fix), update doc + memory | inline | pending |

## Verification evidence

- Commits: 00ccefe (recycle + hygiene), b022543 (flow fix + masque rewiring).
- Review assess (average risk, base ac9fa63, committed-only): medium / review_due=false (under_budget).
- Authors: parent builds only; two delegated writers implemented T3 and T3.2 with parent spot checks; live tests observed directly on port 8793.

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
- 2026-11-02: T3 — enabled quic-go PMTU discovery (InitialPacketSize 1242 kept
  as floor), KeepAlivePeriod 10s -> 30s, and outbound pump now feeds the
  connect-ip-go ICMP Packet-Too-Big return packet back into the gVisor netstack
  (epCh.InjectInbound). quic-go pinned v0.60.0 (v0.64.1 dropped
  http3.ParseCapsule, which connect-ip-go needs).
- 2026-11-02: T3.2 — proxy.go now pool-agnostic via `EgressDialer`/`EgressPool`
  (adapters `wgPoolEgress`/`masquePoolEgress`, exported constructors
  `WGPoolEgress`/`MasquePoolEgress`; exported `ProxyHandlerEgress`,
  `ProxyHandler` kept as WG compat wrapper). main.go routes
  `stack: "masque"` to `warp.NewPool` (Stack "" -> ipv6 default, registrar no
  longer created) and keeps the WG path unchanged; health reports
  `"stack"` label from main because the MASQUE pool's `Status()` lacks it.
