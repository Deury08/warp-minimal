# Feature: MASQUE egress for warp-minimal

Real Cloudflare WARP MASQUE tunnel (QUIC HTTP/3 Connect-IP) to replace the blocked WireGuard path on DPI-filtered networks.

## Specs

- S1: "investigar el warp real y sacar la logica faltante" (user, 2026-10-31) — implement the real client's MASQUE logic.
- S2 (protocol, from Diniboy1123/usque RESEARCH.md):
  - PATCH `api.cloudflareclient.com/v0aXXXX/reg/<id>` with `{"key":"<ECDSA P-256 pubkey, DER base64>","key_type":"secp256r1","tunnel_type":"masque"}`, Bearer token, headers UA `WARP for Android` + `CF-Client-Version: a-6.35-4471`.
  - QUIC dial `162.159.198.1:443`, SNI `consumer-masque.cloudflareclient.com`, ALPN h3, datagrams enabled, InitialPacketSize 1242, client cert self-signed from the enrolled EC key.
  - CONNECT-IP request: `:protocol: cf-connect-ip`, `:authority: cloudflareaccess.com`, `:path: /`, ignore ExtendedCONNECT advertisement.
  - Raw IP packets as QUIC datagrams (RFC 9221); no routes requested.
- S3: local gVisor netstack stays the user-space TCP/IP stack; packets bridge to the MASQUE session in both directions.
- S4: verification — proxy egress IP must be a Cloudflare range and `cdn-cgi/trace` must show `warp=on`.

## Tasks

| ID | Spec | Work | Route | Commit |
|----|------|------|-------|--------|
| T1 | S2 | Registration: token/id capture + EC enrollment PATCH | inline | (done, auto) |
| T2 | S2,S3 | masque.go: QUIC + connect-ip + netstack bridge | inline | (done, auto) |
| T3 | S4 | wire pool to masque, build, live test | inline | (done, auto) |

## Log

- L1 (verbatim): "investigar el war real y sacar la logica faltante"
- Prior context: WG tunnel built (tunnel.go, works off-network), ISP drops WG UDP (19 endpoints probed, 0 handshakes; official client works via MASQUE).

- 2026-10-31: MASQUE egress verified live — trace warp=on, Google 200; commit on feat/masque-egress (single 1016-line slice; next unit commit split beyond it).
