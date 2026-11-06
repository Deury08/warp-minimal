# warp-minimal

> **Minimal WARP egress proxy** — Rotating exits via **Cloudflare WARP MASQUE** (QUIC Connect-IP over UDP 443), zero GPL dependencies, pool with preload and auto-rotation so tunnels don't drop under real traffic.

[![Release](https://img.shields.io/github/v/release/Deury08/warp-minimal?label=latest)](https://github.com/Deury08/warp-minimal/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](go.mod)
[![Build](https://github.com/Deury08/warp-minimal/actions/workflows/release.yml/badge.svg)](https://github.com/Deury08/warp-minimal/actions)

**Idioma / Language:** [Español](README.es.md) | [English](README.md)

---

## What is it?

`warp-minimal` is a **minimal HTTP/HTTPS proxy** that routes outbound traffic through **Cloudflare WARP MASQUE tunnels** (userspace, no root, no TUN). Traffic exits via the pool's IPv6 egress and rotates to a fresh exit when the upstream responds **429 (rate limit)**.

It has **zero dependencies on any specific project** — use it with any HTTP client.

### Why MASQUE (UDP 443)?

MASQUE (QUIC Connect-IP) is the default egress: it is the same transport the
official 1.1.1.1 client uses, it survives networks where WireGuard handshakes
are killed by DPI (many residential ISPs selectively drop UDP 2408), and it
runs fully in userspace (quic-go + gVisor netstack — no root, no TUN). QUIC
path-MTU discovery (with initial packet size 1242 as floor) plus ICMP
Packet-Too-Big feedback into the netstack keep large uploads (64KB+) flowing.
The MASQUE pool enrolls every configured exit at start (the WireGuard pool
preloads half its size, minimum 1), rotates immediately on HTTP 429/403 or
socket errors, and self-heals: a dead tunnel fails its exit and
a replacement registers automatically, retrying with backoff (10s → 60s, 20
attempts) so a transient registration failure cannot leave the pool empty.

The userspace WireGuard stack (UDP 2408, 25s keepalive) remains available as
`"stack": "wireguard"` for networks where WG handshakes are not dropped.

---

## Features

| Feature | Detail |
|---------|--------|
| **MASQUE egress (QUIC / UDP 443)** | Register → ECDSA P-256 device enrollment → QUIC Connect-IP tunnel (quic-go + gVisor). WireGuard (UDP 2408) remains as `stack: "wireguard"` fallback |
| **Pool with preload** | MASQUE enrolls the whole pool at start (WireGuard preloads half, min 1). Acquisition takes the first healthy exit — exits are shared by concurrent flows, so `pool_size: 2` is one primary plus one warm standby |
| **Auto-rotation** | Immediate drop + background re-register on HTTP 429/403 or socket error |
| **Cooldown per egress block** | 30 min per /64 IPv6 or /32 IPv4 after a failure |
| **Idle keepalive** | 30s QUIC PING so the NAT mapping stays alive under traffic |
| **Large-upload flow control** | QUIC path-MTU discovery (1242B floor) + ICMP Packet-Too-Big feedback into the netstack — ≥64KB uploads no longer stall |
| **Self-healing pool** | Dead tunnels fail their exit and are auto-replaced; failed registrations retry with exponential backoff (10s → 60s, 20 attempts) instead of leaving the pool empty |
| **Userspace** | No root, no TUN, no `NET_ADMIN` — quic-go + gVisor netstack |
| **TLS fingerprint** | uTLS with Bun ClientHello (JA4 `t13d1713h1`) to pass fingerprint gates |
| **Health endpoint** | `GET /health` → JSON pool status |
| **License** | **MIT** (wireguard-go is MIT-like and compatible; only the WireGuard kernel module is GPLv2 and is NOT used) |

---

## How it works (`internal/warp/masque.go`)

1. **Register** — anonymous device against `api.cloudflareclient.com`
   (X25519 keys, `/v0a2158/reg`, Android UA). Captures `id` + `token`.
2. **Enroll MASQUE key** — PATCH `/reg/<id>` with an ECDSA P-256 public key
   (`key_type: secp256r1`, `tunnel_type: masque`) + Bearer token. The response
   yields the **real data endpoint** (`config.peers[0].endpoint` — e.g.
   `162.159.198.2`, the `:0` suffix is trimmed) and the FL assigned client
   addresses (`172.16.0.2` / an IPv6 /64).
3. **QUIC dial** — UDP 443 to that endpoint with client-cert auth using the
   enrolled key (self-signed cert, 24 h), `ConnectionIDLength: 20`
   (mandatory — otherwise the backend aborts with `PROTOCOL_VIOLATION`),
   H3 datagrams + deprecated `SETTINGS_H3_DATAGRAM_00 (0x276)`,
   `InitialPacketSize 1242` as the PMTUD floor, keepalive 30 s.
4. **CONNECT-IP** — Cloudflare's non-RFC variant: request protocol
   `cf-connect-ip`, authority `cloudflareaccess.com` (URI template), and —
   critically — an **explicitly empty `User-Agent` header** on the extended
   CONNECT (matching the official client).
5. **Raw IP over datagrams** — context ID `0` prefix (handled by
   `connect-ip-go` fork `Diniboy1123/connect-ip-go`).
6. **gVisor netstack** — the same userspace TCP/IP stack as before bridges
   packets in both directions. Inbound injection **requires**
   `PacketBufferOptions{ReserveHeaderBytes}` **and** payloads built with
   `buffer.NewViewWithData()` — a plain `NewView` + `copy` silently drops the
   chunk and the stack marks every packet `malformed` (covered by
   `inject_test.go` regression test).
7. **Pool rotation** — exit failures (dead QUIC session, dial errors) trip a
   one-shot `Tunnel.SetOnDead` hook → `Pool.Fail` → auto replacement with a
   fresh registration (intentional `Close()` never triggers it). A failing
   registration retries with backoff instead of abandoning the pool; `POST
   /recycle` forces an idempotent pool-wide recycle, and `POST /swap` rotates
   exactly one exit. `CONNECT` replies carry `X-Warp-Exit: <full id>` so a caller
   can tell which exit served a request and swap just that one.
8. **Per-exit swap** — `POST /swap` (body optional: `{"exit":"warp-<full id>"}`)
   marks one exit as `draining`: it stops being handed to new requests, its live
   streams finish (best effort, 120s cap), and only that exit is re-enrolled. The
   others keep serving, so unlike `/recycle` no in-flight stream is cut and only
   one enrollment is burned. Answers `202` (a swap is in flight), `409
   {"ok":false,"reason":"no_standby"}` when degrading the target would leave no
   usable exit, `404 {"ok":false,"reason":"unknown_exit"}`, `405` for non-POST.

---

## Quick Start

### Build from source
```bash
# Requires Go 1.26+
git clone https://github.com/Deury08/warp-minimal.git
cd warp-minimal
go build -ldflags="-s -w" -o warp-minimal ./cmd/warp-minimal
./warp-minimal                      # built-in defaults: MASQUE, IPv6-only, pool 2, :8789
```

> **No config file needed.** Those defaults are the working configuration. If you do
> need to change something — a different port, more exits, a WireGuard network, a log
> path — create a `config.json` next to the binary: start from
> [`config.example.json`](config.example.json) and edit only the fields you care
> about. Every field you leave out keeps its default, so a one-line file is valid.
> See **Configuration** below for the field table and the override rules.

### Verify the egress (IPv6-only)
```bash
curl -x http://127.0.0.1:8789 https://cloudflare.com/cdn-cgi/trace
# ip=2a09:bac5:xxxx:xxxx::xxxx   ← Cloudflare WARP IPv6 (never 104.28.x.x)
# warp=on                        ← egress goes through the WARP tunnel ✅
```

> **IPv6-only guarantee:** with `stack: "ipv6"` the proxy rejects IPv4 addresses and never falls back to IPv4. If a domain has no AAAA record, the connection is refused rather than silently exiting through the shared WARP IPv4 range.

```bash
curl -x http://127.0.0.1:8789 https://www.google.com -o /dev/null -w "%{http_code}\n"
# 200
```

---

## Configuration (`config.json` — optional)

The binary ships with working defaults. **No config file is required**: with no
`config.json` next to it, `warp-minimal` starts with the values below.

```json
{
  "listen": "127.0.0.1:8789",
  "pool_size": 2,
  "stack": "ipv6",
  "health_path": "/health"
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen` | `127.0.0.1:8789` | HTTP proxy listen address |
| `pool_size` | `2` | Concurrent WARP exits. MASQUE enrolls every exit at start, so this is also the startup enrollment count; `2` is one primary plus one warm standby |
| `stack` | `ipv6` | Egress stack. `masque` / `ipv6` / `warp` all select the MASQUE (QUIC) pool — equivalent today, with `ipv6` kept for v0.1.x configs and for its IPv6-only guarantee (rejects IPv4, no fallback, exits only through dedicated IPv6 addresses). `wireguard` selects the userspace WG tunnel (UDP 2408) as an explicit opt-in |
| `health_path` | `/health` | Health endpoint path. Must start with `/` |
| `log_path` | *(next to the binary)* | Where log lines are mirrored (`warp-minimal.log` beside the executable by default). Use an absolute path when the install directory is not writable |

### Overriding values

To create your own `config.json` (optional): copy `config.example.json` next to the
binary and keep only the fields you want to change. Restart the process afterwards.

The file is an **override**, not a requirement:

- A field you omit keeps its default, so a one-line file is valid: `{"pool_size": 4}`.
- Setting a field to its zero value (`""`, `0`) also falls back to the default.
- A wrong type is a hard error at startup (`json: cannot unmarshal ...`), while an
  **unknown key is silently ignored** — print the effective config instead of
  hand-typing field names to avoid that trap.
- The file is read **once at startup**; restart to apply changes. Only one process
  can hold `listen`.

```bash
./warp-minimal -print-config        # effective config as JSON (defaults, or defaults + file)
./warp-minimal -config my.json      # override from a file
./warp-minimal -version
```

Copy [`config.example.json`](config.example.json) as a starting point. The startup
log always states which source won: `config: config file: <path>`, or
`config: config file: none at <path>; using built-in defaults`.

---

## Usage (Any HTTP Client)

```bash
# cURL
curl -x http://127.0.0.1:8789 https://httpbin.org/ip
# {"origin": "2a09:bac5:xxxx:xxxx::xxxx"}  ← Cloudflare WARP IPv6

# wget
wget -e use_proxy=yes -e https_proxy=http://127.0.0.1:8789 https://example.com

# Python
requests.get("https://api.example.com", proxies={"https": "http://127.0.0.1:8789"})

# Node.js
fetch("https://api.example.com", { dispatcher: new ProxyAgent("http://127.0.0.1:8789") })
```

---

## Health Check

```bash
curl http://127.0.0.1:8789/health
```

```json
{
  "ok": true,
  "service": "warp-minimal",
  "stack": "masque",
  "pool_size": 2,
  "active": 2,
  "healthy": 2,
  "cooling_down": 0,
  "recycling": false,
  "exits": [
    "warp-18e5118a93b5c804 (in_use, served=7, streams=2)",
    "warp-18e5118b232db280 (healthy, served=0, streams=0)"
  ]
}
```

Each entry has a fixed shape, `<full id> (<state>, served=N, streams=N)`, with
no optional fields. The states are `starting`, `healthy`, `in_use`, `draining`,
`cooldown`; `draining` outranks `cooldown`, so an exit being swapped stays
visible even if its tunnel dies mid-swap.

> Exit ids are full-length: two enrollments made seconds apart share their
> leading hex digits, so a truncated prefix cannot tell a rotation from no
> change. Compare the whole id when you need to confirm a fresh egress.

`served` counts **tunnels**, not requests: a client reuses one `CONNECT` for
many requests, so three fetches over the same connection increment it once. It
exists for callers whose runtime hides the `CONNECT` reply and cannot read
`X-Warp-Exit`; they attribute a failure by taking a snapshot before and after
the request and looking at which exit moved. One increment is not proof by
itself — an unrelated concurrent tunnel moves the same counter — so trust the
diff only for an exit whose state and tunnel are still valid.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Requests hang, `/health` shows exits but proxies dead | Old process with a zombie QUIC session still listening | `taskkill /F /IM warp-minimal.exe` and start again (auto-replace now also handles session death in-process) |
| `healthy: 0` at startup | UDP 443 to `162.159.198.2` blocked, or register/enroll failed | Check firewall; look for `enroll failed` in logs |
| `PROTOCOL_VIOLATION (remote)` on some connects | Transient backend behavior (seen when CID length not set) | Fixed by `ConnectionIDLength: 20`; occasional races still occur and pool retries |
| Handshakes never arrive, only WG | You are hitting the WireGuard path | MASQUE is the default; the WG path only runs if explicitly configured |

---

## Network Requirements

| Requirement | Detail |
|-------------|--------|
| **UDP 443 outbound** | To `162.159.198.2` (or the enroll-assigned endpoint) — plain QUIC, no special ports |
| **HTTPS outbound** | To `api.cloudflareclient.com` (registration + enrollment) |
| **No root / TUN** | 100% userspace (quic-go + gVisor) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    warp-minimal :8789                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Exit 1     │  │  Exit 2     │  │  Exit N     │  Pool   │
│  │  IPv6 /64   │  │  IPv6 /64   │  │  IPv6 /64   │  (2+)   │
│  │  MASQUE     │  │  MASQUE     │  │  MASQUE     │         │
│  │  gVisor     │  │  gVisor     │  │  gVisor     │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          ▼                                  │
│              ┌─────────────────────┐                        │
│              │   HTTP Proxy        │                        │
│              │   (uTLS Bun)        │                        │
│              └──────────┬──────────┘                        │
└─────────────────────────┼───────────────────────────────────┘
                          │ HTTP CONNECT / forward
                          ▼
┌─────────────────────────────────────────────────────────────┐
│          Cloudflare WARP MASQUE (QUIC / UDP 443)             │
│  • Anonymous device registration (X25519)                    │
│  • MASQUE key enrollment (ECDSA P-256, PATCH /reg/<id>)      │
│  • CONNECT-IP over HTTP/3 :protocol=cf-connect-ip            │
│  • Raw IPv4/IPv6 packets as QUIC datagrams (context ID 0)    │
└─────────────────────────────────────────────────────────────┘
```

---

## Protocol reference

The MASQUE implementation was clean-roomed from public observations and the
protocol notes of [`Diniboy1123/usque`](https://github.com/Diniboy1123/usque)
(MIT) and its `connect-ip-go` fork:

| Piece | Value |
|-------|-------|
| Enrollment API | `PATCH api.cloudflareclient.com/v0a*/reg/<id>` |
| Client key | ECDSA P-256, DER/base64, cert self-signed (24 h client auth) |
| UP | `162.159.198.2:443` (from `peers[0].endpoint`) |
| SNI | `consumer-masque.cloudflareclient.com`, ALPN `h3` |
| QUIC | CID length 20, datagrams + `0x276`, InitialPacketSize 1242 + PMTUD, keepalive 30 s |
| CONNECT | `:protocol: cf-connect-ip`, `:authority: cloudflareaccess.com`, UA `` (empty), CF-Client-Version `a-6.35-4471` |
| Framing | Raw IP packets as QUIC datagrams with 1-byte context ID `0` |

> **TODO (security):** the endpoint certificate is currently not pinned.
> The pinning key arrives PEM-encoded in `peers[0].public_key` at enrollment;
> wire it into `tls.Config.VerifyPeerCertificate` like usque does.

---

## Fingerprint scope

| Layer | Technique |
|-------|-----------|
| Client → target | uTLS Bun ClientHello (JA4 `t13d1713h1`) |
| Local → Cloudflare | Go TLS (not fingerprinted against real browsers by design — Cloudflare only checks that the client cert matches the enrolled key) |

---

## License

**MIT** — see [LICENSE](LICENSE).

**NOTICE**: attribution for:
- Cloudflare WARP MASQUE protocol (reverse-engineered from 1.1.1.1 client; clean-room)
- `github.com/Diniboy1123/connect-ip-go` (protocol notes + datagram framing; check NOTICE)
- `github.com/quic-go/quic-go` (MIT, pinned v0.60.0 for the fork's API)
- `golang.zx2c4.com/wireguard` (MIT)
- `gvisor.dev/gvisor` (Apache-2.0)
- `github.com/refraction-networking/utls` (MIT)

---

## Contributing

1. Fork → feature branch → PR
2. `go test ./...`    (`inject_test.go` covers the inbound transport regression)
3. `go vet ./...`
4. Conventional commits: `feat:`, `fix:`, `docs:`, etc.

---

## Changelog

### Unreleased
- **`POST /swap` rotates one exit instead of the whole pool**: the target exit is marked `draining` (no new requests), its live streams finish up to a 120s cap, and only that exit is re-enrolled. `/recycle` still replaces every exit and cuts streams in flight; a swap burns one enrollment instead of one per exit. `409 no_standby` when the swap would leave no usable exit, `404 unknown_exit` for an id the pool does not have
- **`CONNECT` replies carry `X-Warp-Exit: <full exit id>`**: for HTTPS the proxy only tunnels ciphertext and can never read the upstream status, so the reply is the only place it can attribute a request to an exit. A caller that sees a rate limit can now rotate the exit that caused it
- **`/health` reports a `draining` exit** and stops counting it as healthy, since it is not available for new work
- **Pool bootstrap no longer gives up**: enrollment is owned by a single reconciler that retries forever with exponential backoff (10s → 60s cap, logging thinned after 5 attempts), driven by `pool_size`. Previously each slot retried 3 times and then stopped for the life of the process, which is how a `pool_size: 2` pool ended up serving on one exit until a restart
- **One goroutine fills the pool**, which also removes the positional append/overwrite race: two concurrent slots could append one exit and overwrite it with the other, leaving `active: 1` while `healthy` still reported 2
- **Pool counters are derived, never hand-adjusted**: `healthy` and `cooling_down` are recomputed from the exits themselves (`recountLocked`) and `Fail` is idempotent, so a double fail can no longer report a negative `healthy`
- **`/health` exit labels carry the full exit id**: the previous 8-character truncation made two enrollments created nanoseconds apart read `warp-18e` twice, so a rotation was indistinguishable from no change
- `internal/warp/pool_test.go` adds the first pool tests (fill, retry after transient enrollment failure, counter truthfulness, id distinctness) through an injectable `exitFactory`, so pool behavior is pinned without WARP enrollment or a listening port
- **`Acquire` no longer reads the pool slice unlocked**: the header was shared with the goroutine appending an exit, so a live request could see a torn slice (detected by `-race`); the scan now holds the pool mutex, and `p.mu` → `t.mu` is the only lock order in play
- **An enrollment that finishes after `Close()` is torn down** instead of being appended to a closed pool with nobody left to close its tunnel
- **A permanently unreplaceable exit releases its seat**: after the bounded replacement retries are exhausted the exit is dropped and its tunnel closed, so the fill reconciler owns that slot again — previously a dead exit stayed in cooldown, occupied one of the `pool_size` seats, and the pool served degraded until a manual `POST /recycle`

### v0.2.3 (2026-11-03)
- **Config is now optional and the defaults are the working configuration**: `stack` defaults to MASQUE (`ipv6`), so a binary with no `config.json` starts on QUIC/UDP 443 instead of the WireGuard stack that silent-fails on networks blocking UDP 2408 (`acquire failed ... 10s` while `/health` still answered `ok`)
- Defaults moved into one source of truth (`defaultConfig`) and applied by the loader, so a partial `config.json` overrides only the fields it sets and explicit zero values fall back instead of running degraded
- `-print-config` prints the effective configuration as JSON and exits
- Startup log states the config source (`config file: <path>` or `none at <path>; using built-in defaults`) and the effective values
- `config.json` renamed to `config.example.json` (reference only) with a drift test pinning it to the built-in defaults
- Docs corrected: `log_path` documented, pool acquisition described as first-healthy-exit (exits are shared; there is no round-robin), MASQUE enrols the whole pool at start while WireGuard preloads half
- `-version` reports `v0.2.3`

### v0.2.1 (2026-11-02)
- **Large MASQUE uploads fixed (≥64KB no longer stall ~15s)**: QUIC path-MTU discovery enabled (1242B floor instead of fixed Mickey-Mouse packets), ICMP Packet-Too-Big relayed into the gVisor netstack, keepalive 10s → 30s; quic-go pinned v0.60.0
- **Self-healing pools made robust**: failed exit replacements retry registration with exponential backoff (10s → 60s, 20 attempts) — a transient failure (e.g. DNS blip during re-registration) can no longer leave the pool empty until restart
- Stack switch hardened: `masque` / `ipv6` / `warp` all select the MASQUE pool (previously `stack: "ipv6"` silently fell back to WireGuard)
- Idempotent `POST /recycle` MASQUE pool recycle (matches the WG pool behavior)
- Verified end-to-end through pi-free-bridge: relay `lastEgress: warp`, `cdn-cgi/trace` exits from the WARP reserved range (`2a09:bac1:...`), 200KB/1MB uploads OK

### v0.1.1 (2026-10-31)
- **Egress switched to MASQUE (QUIC Connect-IP) by default** — WireGuard falls back only if explicitly configured
- Registration captured `id`+`token`; MASQUE enrollment (ECDSA P-256 key, PATCH)
- Live endpoint from enrollment response; UA/CID/H3 settings replicated from the official client
- gVisor inbound bridge fixed (`ReserveHeaderBytes` + `buffer.NewViewWithData`) with regression test
- Self-healing pool: dead MASQUE sessions auto-replace exits
- Verified live: `cdn-cgi/trace` → `warp=on`, Google 200 via proxy

### v0.1.0 (2026-10-29)
- Functional skeleton: pool, health, config, graceful shutdown
- Stubs ready for: Cloudflare registration, WireGuard tunnel, uTLS proxy
- Release workflow: 6 targets + checksums + registry.json
- MIT license + NOTICE

---

## Documentación en español

Consulta la guía completa en español: [README.es.md](README.es.md)

