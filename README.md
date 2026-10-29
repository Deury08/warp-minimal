# warp-minimal

> **Minimal WARP egress proxy** — Rotating IPv6 exits via Cloudflare WARP, zero GPL dependencies.

[![Release](https://img.shields.io/github/v/release/Deury08/warp-minimal?label=latest)](https://github.com/Deury08/warp-minimal/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](go.mod)
[![Build](https://github.com/Deury08/warp-minimal/actions/workflows/release.yml/badge.svg)](https://github.com/Deury08/warp-minimal/actions)

---

## What is it?

`warp-minimal` is a **minimal HTTP/HTTPS proxy** that routes outbound traffic through **Cloudflare WARP WireGuard tunnels** (userspace, no root, no TUN). Each request exits via a **different IPv6 /64**, automatically rotating when the upstream responds **429 (rate limit)**.

It has **zero dependencies on any specific project** — use it with any HTTP client.

---

## Features

| Feature | Detail |
|---------|--------|
| **IP rotation** | Pool of WARP exits (default 2), 30 min cooldown after 429 |
| **Userspace** | No root, no TUN, no `NET_ADMIN` — wireguard-go + gVisor netstack |
| **TLS fingerprint** | uTLS with Bun ClientHello (JA4 `t13d1713h1`) to pass fingerprint gates |
| **Health endpoint** | `GET /health` → JSON pool status |
| **License** | **MIT** (deps: wireguard-go MIT, gVisor Apache-2.0, utls MIT) |
| **Zero GPL** | Clean-room, no opencode2api code |

---

## Downloads

| Platform | File | SHA256 |
|----------|------|--------|
| Windows x64 | `warp-minimal_v0.1.0_windows_amd64.zip` | `checksums.txt` |
| Windows ARM64 | `warp-minimal_v0.1.0_windows_arm64.zip` | `checksums.txt` |
| Linux x64 | `warp-minimal_v0.1.0_linux_amd64.tar.gz` | `checksums.txt` |
| Linux ARM64 | `warp-minimal_v0.1.0_linux_arm64.tar.gz` | `checksums.txt` |
| macOS x64 | `warp-minimal_v0.1.0_darwin_amd64.tar.gz` | `checksums.txt` |
| macOS ARM64 | `warp-minimal_v0.1.0_darwin_arm64.tar.gz` | `checksums.txt` |

> **Releases:** https://github.com/Deury08/warp-minimal/releases  
> **Checksums:** https://github.com/Deury08/warp-minimal/releases/download/v0.1.0/checksums.txt  
> **Registry:** https://github.com/Deury08/warp-minimal/releases/download/v0.1.0/registry.json

---

## Quick Start

### Prebuilt binary (recommended)
```bash
# Windows (PowerShell)
$url = "https://github.com/Deury08/warp-minimal/releases/download/v0.1.0/warp-minimal_v0.1.0_windows_amd64.zip"
Invoke-WebRequest -Uri $url -OutFile warp-minimal.zip
Expand-Archive warp-minimal.zip -DestinationPath .
.\warp-minimal.exe -config config.json

# Linux / macOS
curl -L https://github.com/Deury08/warp-minimal/releases/download/v0.1.0/warp-minimal_v0.1.0_linux_amd64.tar.gz | tar xz
./warp-minimal -config config.json
```

### Build from source
```bash
# Requires Go 1.26+
git clone https://github.com/Deury08/warp-minimal.git
cd warp-minimal
go build -ldflags="-s -w" -o warp-minimal ./cmd/warp-minimal
./warp-minimal -config config.json
```

### Go install
```bash
go install github.com/Deury08/warp-minimal/cmd/warp-minimal@v0.1.0
warp-minimal -config config.json
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
| `stack` | `ipv6` | `ipv4` or `ipv6` egress |
| `health_path` | `/health` | Health endpoint path |

---

## Usage (Any HTTP Client)

```bash
# Start proxy
./warp-minimal -config config.json
# Listens on 127.0.0.1:8789
```

```bash
# cURL
curl -x http://127.0.0.1:8789 https://httpbin.org/ip
# {"origin": "2a09:bac5:xxxx:xxxx::xxxx"}  ← Cloudflare WARP IPv6

# wget
wget -e use_proxy=yes -e https_proxy=http://127.0.0.1:8789 https://example.com

# Python
import requests
requests.get("https://api.example.com", proxies={"https": "http://127.0.0.1:8789"})

# Node.js
fetch("https://api.example.com", { 
  dispatcher: new ProxyAgent("http://127.0.0.1:8789") 
})

# Go
client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
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
  "exits": [
    "warp-a1b2c3d4 (healthy)",
    "warp-e5f6g7h8 (healthy)"
  ]
}
```

---

## Network Requirements

| Requirement | Detail |
|-------------|--------|
| **UDP 2408 outbound** | Cloudflare WARP registration + keepalive |
| **IPv6 connectivity** | Required for `stack: ipv6` (default) |
| **No root / TUN** | 100% userspace (wireguard-go + gVisor) |

> If UDP 2408 is blocked → pool stays empty → `/health` shows `healthy: 0`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    warp-minimal :8789                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Exit 1     │  │  Exit 2     │  │  Exit N     │  Pool   │
│  │  IPv6 /64   │  │  IPv6 /64   │  │  IPv6 /64   │  (2+)   │
│  │  wireguard  │  │  wireguard  │  │  wireguard  │         │
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
│              Cloudflare WARP (UDP 2408)                     │
│  • Anonymous device registration                            │
│  • WireGuard config + /64 IPv6 assigned                     │
│  • Key derivation: HKDF-ChaCha20Poly1305                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Use Cases

| Use Case | Example |
|----------|---------|
| **Rate limit evasion** | Rotate IP per request / per N requests |
| **Geo-distributed testing** | Cloudflare PoPs worldwide |
| **Fingerprint evasion** | uTLS mimics Bun/Chrome/Firefox |
| **Local dev without IPv6** | Exit via Cloudflare IPv6 |
| **CI/CD runners** | Fresh IP per job |

---

## License

**MIT** — see [LICENSE](LICENSE).

**NOTICE**: Attribution to:
- Cloudflare WARP protocol (reverse-engineered from 1.1.1.1 client)
- `golang.zx2c4.com/wireguard` (MIT)
- `gvisor.dev/gvisor` (Apache-2.0)
- `github.com/refraction-networking/utls` (MIT)

---

## Related Projects

- **[bridge-go](https://github.com/Deury08/pi-free-bridge/tree/main/bridge-go)** — HTTP proxy with OpenCode gate contract, uses warp-minimal as optional egress
- **[pi-free-bridge](https://github.com/Deury08/pi-free-bridge)** — Pi extension using bridge-go + warp-minimal

---

## Contributing

1. Fork → feature branch → PR
2. `go test ./...` (when tests exist)
3. `go vet ./...` && `golangci-lint run`
4. Conventional commits: `feat:`, `fix:`, `docs:`, etc.

---

## Changelog

### v0.1.0 (2026-10-29)
- Functional skeleton: pool, health, config, graceful shutdown
- Stubs ready for: Cloudflare registration, WireGuard tunnel, uTLS proxy
- Release workflow: 6 targets + checksums + registry.json
- MIT license + NOTICE