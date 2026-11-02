# Feature: IPv6-only stack for warp-minimal

Force WARP egress exclusively over IPv6 (config `stack: "ipv6"`), reject IPv4 literals, no IPv4 fallback, and avoid the burned 104.28.x.x gate range.

## Specs

- S1: "configurar warp-minimal para salir solo por IPv6 (stack: "ipv6") y evitar las IPs quemadas del rango 104.28.x.x del gate" — config default `stack: "ipv6"`, MASQUE pool selected, IPv6-only egress.
- S2: "reiniciar el binario en el puerto 8789" — service running on 127.0.0.1:8789 with the new stack.
- S3: "verificar con curl -x http://127.0.0.1:8789 https://cloudflare.com/cdn-cgi/trace que salga con warp=on y IP IPv6" — trace shows `warp=on` and an IPv6 address, not 104.28.x.x.
- S4: "necesitamos hacer un push pr y mergear" — feature branch pushed, PR opened to `main` (user performs merge).
- S5: "hasta quiero la relice de warp que todo que de en main, con las accion de github para crear los binarios" — tag `v0.2.2` triggers GitHub Actions release workflow (existing `release.yml`) building binaries for windows/linux/darwin amd64+arm64 and publishing release assets + registry.json.
- S6: "actualiza tambien el readme" — README documents `stack: "ipv6"` behavior and verification command.

## Tasks

| ID | Spec | Work | Route | Commit |
|----|------|------|-------|--------|
| T1 | S1 | config.json `stack: "ipv6"` | inline | auto |
| T2 | S1,S3 | tunnel.go: reject IPv4 literals, no IPv4 fallback, Go-resolver PreferGo for AAAA on Windows, DIAL/RESOLVE diagnostic logs | inline | auto |
| T3 | S2 | Build binary, restart on 127.0.0.1:8789, live verify curl trace warp=on + IPv6 IP | inline | auto |
| T4 | S6 | README: document `stack: "ipv6"` behavior, IPv6-only guarantee, verification command, 104.28.x.x avoidance | inline | auto |
| T5 | S4 | Create feature branch, commit work units (config + code, then README), push to origin | inline | auto |
| T6 | S5 | User opens PR to `main`, reviews, merges | user | user |
| T7 | S5 | Tag `v0.2.2` on `main` to trigger GitHub Actions release binaries | user | user |

## Log

- L1 (verbatim): "preguntale a este orquestador --session 01a19dc2-89c6-76aa-adbf-52efb2a8379e" → user asked via inter-session message to configure warp-minimal for IPv6-only, avoid 104.28.x.x, restart on 8789, verify curl warp=on + IPv6 IP.
- L2 (verbatim): "dale" → user authorized forcing IPv6-only in code after confirming stack=ipv6 still fell back to IPv4 for domains without AAAA.
- 2026-11-03: config.json + tunnel.go modified, binary rebuilt, service running on 8789, curl trace verified `warp=on` + IPv6 `2a09:bac5:d5b1:aa::11:1e8`. Ready for feature branch, commits, push, PR, tag.
