# Feature: WireGuard egress for warp-minimal (UDP 2408)

Replace Cloudflare WARP MASQUE (QUIC Connect-IP, UDP 443) with WireGuard userspace (UDP 2408) plus the opencode2api pool improvements so tunnels don't drop under real traffic.

## Specs

- S1: "agregar golang.zx2c4.com/wireguard/device y golang.zx2c4.com/wireguard/tun a go.mod" — WireGuard userspace deps (MIT-like, compatible; only the kernel module is GPLv2 and is NOT used).
- S2: "Crear internal/warp/wg_exit.go: un exit de WireGuard (un túnel por exit) con registro anónimo contra api.cloudflareclient.com, túnel WireGuard en userspace, DialContext, probe de salud (GET a cdn-cgi/trace verificando warp=on), y fallback IPv6→IPv4."
- S3: "Crear internal/warp/wg_pool.go: pool con preload (mitad del tamaño, mínimo 1 exit caliente aunque no haya tráfico), rotación inmediata por HTTP 429 / 403 con 'network' / error de socket (sacar del pool y re-registrar en background), cooldown de 30 min por bloque de egress (/64 IPv6 o /32 IPv4), keepalive persistente 25s."
- S4: "Crear internal/warp/wg_registrar.go: registro anónimo de dispositivo contra Cloudflare (X25519 clave, POST /reg, PATCH para habilitar WARP, GET para leer config)."
- S5: "Modificar internal/warp/proxy.go: usar pool.Acquire()/Release() en lugar de túnel MASQUE directo."
- S6: "Modificar cmd/warp-minimal/main.go: cambiar stack a wireguard en lugar de ipv6 por MASQUE."
- S7: "Modificar pi-free-bridge (C:/Users/Polanco/pi-free-bridge/relay.mjs): en modo 'on', si WARP falla con error de red (no 429), hacer fallback a local para evitar 502."
- S8: Licencia MIT se conserva (wireguard-go es MIT-like, compatible; solo el módulo kernel de WireGuard es GPLv2 y no se usa).

## Tasks

| ID | Spec | Work | Route | Commit |
|----|------|------|-------|--------|
| T1 | S1 | go.mod: add golang.zx2c4.com/wireguard/device + /tun; go mod tidy | inline | feat/wireguard-egress |
| T2 | S4 | internal/warp/wg_registrar.go: anonymous device registration (X25519, POST /reg, PATCH enable WARP, GET config) | inline | feat/wireguard-egress |
| T3 | S2 | internal/warp/wg_exit.go: userspace WG tunnel per exit, DialContext, health probe (cdn-cgi/trace warp=on), IPv6→IPv4 fallback | inline | feat/wireguard-egress |
| T4 | S3 | internal/warp/wg_pool.go: pool preload (half size, ≥1 hot exit), immediate rotation on 429/403 network/socket errors (drop + background re-register), 30 min cooldown per egress block (/64 v6 / /32 v4), persistent 25s keepalive | inline | feat/wireguard-egress |
| T5 | S5 | internal/warp/proxy.go: use pool.Acquire()/Release() instead of direct MASQUE tunnel | inline | feat/wireguard-egress |
| T6 | S6 | cmd/warp-minimal/main.go: stack default to wireguard instead of ipv6 via MASQUE | inline | feat/wireguard-egress |
| T7 | S7 | pi-free-bridge relay.mjs: mode "on", WARP network error (not 429) → fallback to local to avoid 502 | inline | feat/wireguard-egress |
| T8 | S2-S8 | Build, tests, live functional check (cdn-cgi/trace warp=on), README update | inline | feat/wireguard-egress |

## Log

- L1 (verbatim): "Necesito que trabajes en warp-minimal (C:/Users/Polanco/warp-minimal) migrándolo de MASQUE (QUIC Connect-IP) a WireGuard (UDP 2408), aplicando las mejoras de pool que vimos en opencode2api para que los túneles no se caigan con tráfico. Usa Coderap para el trabajo y levanta tu ODD (Organic Driven Development) antes de escribir código."
- Context: warp-minimal currently runs MASQUE (internal/warp/masque.go, tunnel.go) with pool.go; config stack default is "ipv6". pi-free-bridge relay.mjs listens on 8788, warp-minimal on 8789, warpEnabled "on" but tunnels drop under real traffic causing 502s.
- pi-free-bridge odd/tasks: bridge-go.md, bun-relay.md, bun-upgrades.md, pi-free-bridge.md, relay-warp-hot-reload.md, warp-auto-recycle.md (reference for pool/recycle patterns).
- The go.mod already requires golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f; /device and /tun are importable subpackages of that same module (wireguard-go), no go.mod change needed.
- Done: T1..T8 all implemented. warp-minimal: build/vet/tests OK; pi-free-bridge: syntax OK + 53 tests pass.
- Pending: live functional check `curl -x http://127.0.0.1:8789 https://1.1.1.1/cdn-cgi/trace` → `warp=on` (requires real network to api.cloudflareclient.com + UDP 2408; not run here).
- Risk: item 3 (changing a consumed contract: stack flag + proxy path) + item 1 (userspace tunnel, no data persistence, reversible).
