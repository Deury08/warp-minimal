# warp-minimal

> **Proxy de egress WARP minimal** — Salidas rotativas a través de **Cloudflare WARP MASQUE** (QUIC Connect-IP sobre UDP 443), cero dependencias GPL, pool con pre-carga y auto-rotación para que los túneles no caigan bajo tráfico real.

[![Release](https://img.shields.io/github/v/release/Deury08/warp-minimal?label=latest)](https://github.com/Deury08/warp-minimal/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](go.mod)
[![Build](https://github.com/Deury08/warp-minimal/actions/workflows/release.yml/badge.svg)](https://github.com/Deury08/warp-minimal/actions)

**Idioma / Language:** [Español](#readme-es) | [English](README.md)

---

## ¿Qué es? <a name="readme-es"></a>

`warp-minimal` es un **proxy HTTP/HTTPS mínimo** que envía el tráfico saliente a través de túneles **Cloudflare WARP MASQUE** (userspace, sin root, sin TUN). El tráfico sale por el egress IPv6 del pool y rota a una salida nueva cuando el upstream responde **429 (rate limit)**.

No tiene dependencias de ningún proyecto específico — úsalo con cualquier cliente HTTP.

### ¿Por qué MASQUE (UDP 443)?

MASQUE (QUIC Connect-IP) es el egress por defecto: es el mismo transporte que usa el cliente oficial 1.1.1.1, sobrevive a redes donde los handshakes de WireGuard son bloqueados por DPI (muchos ISP residenciales droppean selectivamente UDP 2408), y corre totalmente en userspace (quic-go + gVisor netstack — sin root, sin TUN). El descubrimiento de PMTU de QUIC (con tamaño de paquete inicial 1242 como piso) más el feedback de ICMP Packet-Too-Big al netstack mantienen subidas grandes (64KB+) fluyendo. El pool MASQUE inscribe todas sus salidas al arrancar (el pool WireGuard pre-carga la mitad, mínimo 1), rota inmediatamente ante HTTP 429/403 o errores de socket, y se auto-cura: un túnel muerto falla su salida y una nueva se registra automáticamente, reintentando con backoff exponencial (10s → 60s, 20 intentos) para que una falla transitoria de registro no deje el pool vacío.

El stack WireGuard en userspace (UDP 2408, keepalive 25s) permanece disponible como `"stack": "wireguard"` para redes donde los handshakes WG no son bloqueados.

---

## Características

| Característica | Detalle |
|----------------|---------|
| **Egress MASQUE (QUIC / UDP 443)** | Registro → Enrolamiento de clave ECDSA P-256 → Túnel QUIC Connect-IP (quic-go + gVisor). WireGuard (UDP 2408) permanece como `stack: "wireguard"` fallback |
| **Pool con pre-carga** | MASQUE inscribe el pool completo al arrancar (WireGuard pre-carga la mitad, mínimo 1). La adquisición toma la primera salida sana — las salidas se comparten entre flujos concurrentes, así que `pool_size: 2` es un primario más un respaldo caliente |
| **Auto-rotación** | Descarte inmediato + re-registro en segundo plano ante HTTP 429/403 o error de socket |
| **Cooldown por bloque de egress** | 30 min por /64 IPv6 o /32 IPv4 tras una falla |
| **Keepalive inactivo** | QUIC PING cada 30s para mantener el mapping de NAT vivo bajo tráfico |
| **Control de flujo de subidas grandes** | PMTU de QUIC (piso de 1242B) + feedback ICMP Packet-Too-Big al netstack — subidas ≥64KB ya no se estancan |
| **Pool auto-curable** | Túneles muertos fallan su salida y se auto-reemplazan; fallos de registro reintentan con backoff exponencial (10s → 60s, 20 intentos) en lugar de dejar el pool vacío |
| **Userspace** | Sin root, sin TUN, sin `NET_ADMIN` — quic-go + gVisor netstack |
| **Huella dactilar TLS** | uTLS con ClientHello de Bun (JA4 `t13d1713h1`) para pasar filtros de huella dactilar |
| **Endpoint de salud** | `GET /health` → estado JSON del pool |
| **Licencia** | **MIT** (wireguard-go es MIT-like y compatible; solo el módulo del kernel de WireGuard es GPLv2 y NO se usa) |

---

## Cómo funciona (`internal/warp/masque.go`)

1. **Registro** — dispositivo anónimo contra `api.cloudflareclient.com` (claves X25519, `/v0a2158/reg`, UA de Android). Captura `id` + `token`.
2. **Enrolamiento de clave MASQUE** — PATCH `/reg/<id>` con clave pública ECDSA P-256 (`key_type: secp256r1`, `tunnel_type: masque`) + Bearer token. La respuesta entrega el **endpoint de datos real** (`config.peers[0].endpoint` — ej. `162.159.198.2`, el sufijo `:0` se recorta) y las direcciones asignadas al cliente FL (`172.16.0.2` / un /64 IPv6).
3. **Dial QUIC** — UDP 443 a ese endpoint con autenticación de certificado de cliente usando la clave enrolada (certificado autofirmado, 24h), `ConnectionIDLength: 20` (obligatorio — si no, el backend aborta con `PROTOCOL_VIOLATION`), H3 datagrams + deprecated `SETTINGS_H3_DATAGRAM_00 (0x276)`, `InitialPacketSize 1242` como piso de PMTUD, keepalive 30s.
4. **CONNECT-IP** — variante no-RFC de Cloudflare: protocolo de solicitud `cf-connect-ip`, autoridad `cloudflareaccess.com` (plantilla URI), y críticamente — un encabezado `User-Agent` **explícitamente vacío** en el CONNECT extendido (coincidiendo con el cliente oficial).
5. **IP crudo sobre datagramas** — prefijo de ID de contexto `0` (manejado por el fork `connect-ip-go` de `Diniboy1123/connect-ip-go`).
6. **gVisor netstack** — el mismo stack TCP/IP en userspace de antes puentea paquetes en ambas direcciones. La inyección inbound **requiere** `PacketBufferOptions{ReserveHeaderBytes}` **y** cargas útiles construidas con `buffer.NewViewWithData()` — un `NewView` + `copy` simple descarta silenciosamente el chunk y el stack marca cada paquete como `malformed` (cubierto por la prueba de regresión `inject_test.go`).
7. **Rotación del pool** — fallos de salida (sesión QUIC muerta, errores de dial) disparan el hook `Tunnel.SetOnDead` → `Pool.Fail` → auto-reemplazo con registro nuevo (`Close()` intencional nunca lo dispara). Un registro fallido reintenta en lugar de abandonar el pool; `POST /recycle` obliga un reciclado idempotente de todo el pool.

---

## Inicio rápido

### Construir desde el código fuente

```bash
# Requiere Go 1.26+
git clone https://github.com/Deury08/warp-minimal.git
cd warp-minimal
go build -ldflags="-s -w" -o warp-minimal ./cmd/warp-minimal
./warp-minimal                      # defaults: MASQUE, solo IPv6, pool 2, :8789
```

> **No hace falta ningún archivo de configuración.** Esos defaults ya son la
> configuración que funciona. Si necesitás cambiar algo — otro puerto, más salidas,
> una red WireGuard, una ruta de log — creá un `config.json` junto al binario:
> partí de [`config.example.json`](config.example.json) y editá sólo los campos que te
> importan. Todo campo que omitas conserva su default, así que un archivo de una
> línea es válido. Ver **Configuración** más abajo para la tabla de campos y las
> reglas de override.

### Verificar el egress (solo IPv6)

```bash
curl -x http://127.0.0.1:8789 https://cloudflare.com/cdn-cgi/trace
# ip=2a09:bac5:xxxx:xxxx::xxxx   ← IPv6 de Cloudflare WARP (nunca 104.28.x.x)
# warp=on                        ← egress por el túnel WARP ✅
```

> **Garantía solo IPv6:** con `stack: "ipv6"` el proxy rechaza direcciones IPv4 y nunca falla a IPv4. Si un dominio no tiene registro AAAA, la conexión se rechaza en lugar de salir en silencio por el rango IPv4 compartido de WARP.

```bash
curl -x http://127.0.0.1:8789 https://www.google.com -o /dev/null -w "%{http_code}\n"
# 200
```

---

## Configuración (`config.json` — opcional)

El binario ya trae defaults que funcionan. **No hace falta ningún archivo de
configuración**: sin `config.json` al lado, `warp-minimal` arranca con los
valores de abajo.

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
| `pool_size` | `2` | Salidas WARP concurrentes. MASQUE inscribe todas al arrancar, así que también es la cantidad de inscripciones iniciales; `2` es un primario más un respaldo caliente |
| `stack` | `ipv6` | Pila de egress. `masque` / `ipv6` / `warp` usan el pool MASQUE (QUIC) — hoy equivalentes, con `ipv6` conservado por compatibilidad con configs v0.1.x y por su garantía solo IPv6 (rechaza IPv4, sin fallback, sale sólo por direcciones IPv6 dedicadas). `wireguard` usa el túnel WG en userspace (UDP 2408) como opt-in explícito |
| `health_path` | `/health` | Ruta del endpoint de salud. Debe empezar con `/` |
| `log_path` | *(junto al binario)* | Dónde se espejan los logs (`warp-minimal.log` junto al ejecutable por defecto). Conviene ruta absoluta si el directorio de instalación no es escribible |

### Cómo sobrescribir valores

Para crear tu propio `config.json` (opcional): copiá `config.example.json` junto al
binario y dejá sólo los campos que quieras cambiar. Reiniciá el proceso después.

El archivo es un **override**, no un requisito:

- Un campo que omitís conserva su default, así que un archivo de una línea es válido: `{"pool_size": 4}`.
- Poner un campo en su valor cero (`""`, `0`) también vuelve al default.
- Un tipo equivocado es un error duro al arrancar (`json: cannot unmarshal ...`), mientras que una **clave desconocida se ignora en silencio** — imprimí la configuración efectiva en lugar de tipear nombres de campo a mano.
- El archivo se lee **una sola vez al arrancar**; reiniciá para aplicar cambios. Un solo proceso puede tomar `listen`.

```bash
./warp-minimal -print-config        # config efectiva en JSON (defaults, o defaults + archivo)
./warp-minimal -config mi.json      # override desde un archivo
./warp-minimal -version
```

Copiá [`config.example.json`](config.example.json) como punto de partida. El log de
arranque siempre dice qué fuente ganó: `config: config file: <ruta>`, o
`config: config file: none at <ruta>; using built-in defaults`.

---

## Uso con cualquier cliente HTTP

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

---

## Health check

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

---

## Requisitos de red

| Requisito | Detalle |
|-----------|---------|
| **UDP 443 saliente** | A `162.159.198.2` (o el endpoint asignado por el enrolamiento) — QUIC simple, sin puertos especiales |
| **HTTPS saliente** | A `api.cloudflareclient.com` (registro + enrolamiento) |
| **Sin root / TUN** | 100% userspace (quic-go + gVisor) |

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---------|-------|----------|
| Las peticiones cuelgan, `/health` muestra salidas pero el proxy está muerto | Proceso viejo con sesión QUIC zombie todavía escuchando | `taskkill /F /IM warp-minimal.exe` y arrancar de nuevo |
| `healthy: 0` al iniciar | UDP 443 a `162.159.198.2` bloqueado, o falló registro/enrolamiento | Revisar firewall; buscar `enroll failed` en los logs |
| `PROTOCOL_VIOLATION (remote)` | Comportamiento transitorio del backend | Fixed by `ConnectionIDLength: 20`; el pool reintenta automáticamente |

---

[⬅️ Volver a English](README.md)