# warp-minimal

> **Minimal WARP egress proxy** — Rotating IPv6 exits via **Cloudflare WARP MASQUE** (QUIC Connect-IP), zero GPL dependencies, works on DPI-filtered networks.

[![Release](https://img.shields.io/github/v/release/Deury08/warp-minimal?label=latest)](https://github.com/Deury08/warp-minimal/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](go.mod)
[![Build](https://github.com/Deury08/warp-minimal/actions/workflows/release.yml/badge.svg)](https://github.com/Deury08/warp-minimal/actions)

---

## What is it?

`warp-minimal` is a **minimal HTTP/HTTPS proxy** that routes outbound traffic through **Cloudflare WARP MASQUE tunnels** (userspace, no root, no TUN). Each request exits via a **different IPv6 /64**, automatically rotating when the upstream responds **429 (rate limit)**.

It has **zero dependencies on any specific project** — use it with any HTTP client.

### Why MASQUE (and not WireGuard)?

Many ISPs (e.g. WISP / CGNAT access networks) apply DPI that drops generic
WireGuard UDP handshakes. The official 1.1.1.1/WARP client solves this by
tunneling over **QUIC + HTTP/3 CONNECT-IP (MASQUE, port 443)** — the same
protocol `warp-minimal` implements since this release. WireGuard (`stack = wg`)
remains available as a fallback where UDP 2408 works.

---

## Features

| Feature | Detail |
|---------|--------|
| **MASQUE egress** | Register → ECDSA P-256 enroll → QUIC/HTTP3 → CONNECT-IP, clean-room implementation |
| **DPI-resistant** | QUIC datagrams on UDP 443; passes WISP DPI filters that kill WireGuard |
| **IP rotation** | Pool of WARP exits (default 2), 30 min cooldown after 429 |
| **Self-healing** | A dead MASQUE session fails its exit and is auto-replaced |
| **Userspace** | No root, no TUN, no `NET_ADMIN` — quic-go + gVisor netstack |
| **TLS fingerprint** | uTLS with Bun ClientHello (JA4 `t13d1713h1`) to pass fingerprint gates |
| **Health endpoint** | `GET /health` → JSON pool status |
| **License** | **MIT** (deps: quic-go MIT, gVisor Apache-2.0, wireguard-go MIT, utls MIT) |

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
   `InitialPacketSize 1242`, keepalive 10 s.
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
   fresh registration (intentional `Close()` never triggers it).

---

## Quick Start

### Build from source
```bash
# Requires Go 1.26+
git clone https://github.com/Deury08/warp-minimal.git
cd warp-minimal
go build -ldflags="-s -w" -o warp-minimal ./cmd/warp-minimal
./warp-minimal -config config.json
```

### Verify the egress
```bash
curl -x http://127.0.0.1:8789 https://cloudflare.com/cdn-cgi/trace
# ip=104.28.xx.xx        ← Cloudflare edge
# warp=on                ← egress goes through the WARP tunnel ✅
```

```bash
curl -x http://127.0.0.1:8789 https://www.google.com -o /dev/null -w "%{http_code}\n"
# 200
```

---

## Configuration (`config.json`)

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
| `pool_size` | `2` | Concurrent WARP exits |
| `stack` | `ipv6` | Egress preference (Cloudflare assigns both a v4 and a v6 to every MASQUE device) |
| `health_path` | `/health` | Health endpoint path |

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
  "pool_size": 2,
  "active": 2,
  "healthy": 2,
  "cooling_down": 0,
  "ex": ["warp-a1b2c3d4 (healthy)", "warp-e5f6g7h8 (healthy)"]
}
```

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
| QUIC | CID length 20, datagrams + `0x276`, IPP 1242, keepalive 10 s |
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
- `github.com/quic-go/quic-go` (MIT, pinned v0.59.0 for the fork's API)
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
