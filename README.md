# warp-minimal

> **Minimal WARP egress proxy** — Rotating exits via **Cloudflare WARP MASQUE** (QUIC Connect-IP over UDP 443), zero GPL dependencies, pool with preload and auto-rotation so tunnels don't drop under real traffic.

[![Release](https://img.shields.io/github/v/release/Deury08/warp-minimal?label=latest)](https://github.com/Deury08/warp-minimal/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](go.mod)
[![Build](https://github.com/Deury08/warp-minimal/actions/workflows/release.yml/badge.svg)](https://github.com/Deury08/warp-minimal/actions)

**Idioma / Language:** [Español](#configuración-y-uso-español) | [English](#english)

---

## What is it? <a name="english"></a>

`warp-minimal` is a **minimal HTTP/HTTPS proxy** that routes outbound traffic through **Cloudflare WARP MASQUE tunnels** (userspace, no root, no TUN). Each request exits via a **different IPv6 /64**, automatically rotating when the upstream responds **429 (rate limit)**.

It has **zero dependencies on any specific project** — use it with any HTTP client.

### Why MASQUE (UDP 443)?

MASQUE (QUIC Connect-IP) is the default egress: it is the same transport the
official 1.1.1.1 client uses, it survives networks where WireGuard handshakes
are killed by DPI (many residential ISPs selectively drop UDP 2408), and it
runs fully in userspace (quic-go + gVisor netstack — no root, no TUN). QUIC
path-MTU discovery (with initial packet size 1242 as floor) plus ICMP
Packet-Too-Big feedback into the netstack keep large uploads (64KB+) flowing.
The pool preloads half its size (minimum 1 hot exit), rotates immediately on
HTTP 429/403 or socket errors, and self-heals: a dead tunnel fails its exit and
a replacement registers automatically, retrying with backoff (10s → 60s, 20
attempts) so a transient registration failure cannot leave the pool empty.

The userspace WireGuard stack (UDP 2408, 25s keepalive) remains available as
`"stack": "wireguard"` for networks where WG handshakes are not dropped.

---

## Features

| Feature | Detail |
|---------|--------|
| **MASQUE egress (QUIC / UDP 443)** | Register → ECDSA P-256 device enrollment → QUIC Connect-IP tunnel (quic-go + gVisor). WireGuard (UDP 2408) remains as `stack: "wireguard"` fallback |
| **Pool with preload** | Half the pool (min 1) hot before first traffic; round-robin acquisition |
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
   /recycle` forces an idempotent pool-wide recycle.

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

### Verify the egress (IPv6-only)
```bash
curl -x http://127.0.0.1:8789 https://cloudflare.com/cdn-cgi/trace
# ip=2a09:bac5:xxxx:xxxx::xxxx   ← Cloudflare WARP IPv6 (never 104.28.x.x)
# warp=on                        ← egress goes through the WARP tunnel ✅
```

> **IPv6-only guarantee:** with `stack: "ipv6"` the proxy rejects IPv4 addresses and never falls back to IPv4. If a domain has no AAAA record, the connection is refused instead of using the burned 104.28.x.x IPv4 gate range.

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
| `stack` | `ipv6` | Egress stack: `masque` / `ipv6` / `warp` all select the MASQUE (QUIC) pool; `wireguard` selects the userspace WG tunnel. `ipv6` forces IPv6-only egress (rejects IPv4, no fallback, avoids 104.28.x.x gate range) |
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

## Configuración y uso (Español) <a name="español"></a>

### ¿Qué hace?

`warp-minimal` es un **proxy HTTP/HTTPS mínimo** que envía el tráfico saliente a través de túneles **Cloudflare WARP MASQUE** (userspace, sin root, sin TUN). Cada petición sale por una **IPv6 /64 distinta**, rotando automáticamente cuando el upstream responde **429 (rate limit)**.

Con `stack: "ipv6"` el egress es **solo IPv6**: rechaza direcciones IPv4 y nunca hace fallback a IPv4, evitando el rango quemado `104.28.x.x` del gate IPv4.

### Configuración rápida (`config.json`)

```json
{
  "listen": "127.0.0.1:8789",
  "pool_size": 2,
  "stack": "ipv6",
  "health_path": "/health"
}
```

| Campo | Por defecto | Descripción |
|-------|-------------|-------------|
| `listen` | `127.0.0.1:8789` | Dirección de escucha del proxy HTTP |
| `pool_size` | `2` | Cantidad de salidas WARP concurrentes |
| `stack` | `ipv6` | Pila de egress: `masque` / `ipv6` / `warp` usan el pool MASQUE (QUIC); `wireguard` usa el túnel WG en userspace. `ipv6` fuerza egress solo IPv6 (rechaza IPv4, sin fallback, evita 104.28.x.x) |
| `health_path` | `/health` | Ruta del endpoint de salud |

### Construir y ejecutar

```bash
# Requiere Go 1.26+
git clone https://github.com/Deury08/warp-minimal.git
cd warp-minimal
go build -ldflags="-s -w" -o warp-minimal ./cmd/warp-minimal
./warp-minimal -config config.json
```

### Verificar el egress (IPv6 solo)

```bash
curl -x http://127.0.0.1:8789 https://cloudflare.com/cdn-cgi/trace
# ip=2a09:bac5:xxxx:xxxx::xxxx   ← IPv6 de Cloudflare WARP (nunca 104.28.x.x)
# warp=on                        ← egress por el túnel WARP ✅
```

> **Garantía IPv6-only:** con `stack: "ipv6"` el proxy rechaza direcciones IPv4 y nunca falla a IPv4. Si un dominio no tiene registro AAAA, la conexión se rechaza en lugar de usar el rango IPv4 quemado `104.28.x.x`.

### Uso con cualquier cliente HTTP

```bash
# cURL
curl -x http://127.0.0.1:8789 https://httpbin.org/ip
# {"origin": "2a09:bac5:xxxx:xxxx::xxxx"}  ← IPv6 de Cloudflare WARP

# wget
wget -e use_proxy=yes -e https_proxy=http://127.0.0.1:8789 https://example.com

# Python
requests.get("https://api.example.com", proxies={"https": "http://127.0.0.1:8789"})

# Node.js
fetch("https://api.example.com", { dispatcher: new ProxyAgent("http://127.0.0.1:8789") })
```

### Health check

```bash
curl http://127.0.0.1:8789/health
```

Respuesta esperada:

```json
{
  "ok": true,
  "service": "warp-minimal",
  "pool_size": 2,
  "active": 2,
  "healthy": 2,
  "cooling_down": 0
}
```

### Requisitos de red

| Requisito | Detalle |
|-----------|---------|
| **UDP 443 saliente** | A `162.159.198.2` (o el endpoint asignado por el enrolamiento) — QUIC simple, sin puertos especiales |
| **HTTPS saliente** | A `api.cloudflareclient.com` (registro + enrolamiento) |
| **Sin root / TUN** | 100% userspace (quic-go + gVisor) |

### Solución de problemas

| Síntoma | Causa | Solución |
|---------|-------|----------|
| Las peticiones cuelgan, `/health` muestra salidas pero el proxy está muerto | Proceso viejo con sesión QUIC zombie todavía escuchando | `taskkill /F /IM warp-minimal.exe` y arrancar de nuevo |
| `healthy: 0` al iniciar | UDP 443 a `162.159.198.2` bloqueado, o falló registro/enrolamiento | Revisar firewall; buscar `enroll failed` en los logs |
| `PROTOCOL_VIOLATION (remote)` | Comportamiento transitorio del backend | Fixed by `ConnectionIDLength: 20`; el pool reintenta automáticamente |

[⬆️ Volver a English](#english)

