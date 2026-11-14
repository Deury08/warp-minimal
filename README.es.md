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
| **Endpoint de salud** | `GET /health` → estado JSON del pool más `build: {commit, built_at}` y `capabilities.exits` |
| **API de hechos por salida** | `GET /exits` y `GET /exit/<id>` → un objeto JSON por salida: estado, `served`, flujos vivos, marcas de tiempo, la IP de egress que Cloudflare ve realmente y el resultado del último trace |
| **Preferencia de salida** | `Proxy-Authorization: Basic base64("<exit-id>:")` fija un pedido a una salida concreta; un id desconocido o no usable cae en la adquisición normal en vez de responder `407` |
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
./warp-minimal -version             # warp-minimal v0.4.0 (<commit corto>)
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

### Fijar un pedido a una salida concreta

La credencial del proxy elige la salida: el id de la salida viaja como **usuario**
de Basic y el password se **ignora** — acá no hay autenticación.

```bash
# Proxy-Authorization: Basic base64("warp-18e5118a93b5c804:")
curl -x http://127.0.0.1:8789 -U 'warp-18e5118a93b5c804:' https://httpbin.org/ip
```

- Tiene que ser un header **de proxy**, no uno normal de la request: en `CONNECT`
  el proxy sólo ve la request de túnel, y los headers de la request real viajan
  cifrados dentro del TLS que él reenvía a ciegas, así que un header custom de tu
  aplicación nunca le llega.
- La forma exacta es `Proxy-Authorization: Basic base64("<exit-id>:")` — id, dos
  puntos, nada después. `-U '<id>:'` en cURL produce exactamente eso.
- Funciona tanto para `CONNECT` como para el reenvío HTTP plano, y el header es
  hop-by-hop: se descarta antes de llegar al destino.
- **No hay fallback con `407`.** Un id desconocido, un id `draining` o en
  `cooldown`, o un stack sin soporte de preferencia se sirve por la adquisición
  normal del pool — en silencio, nunca con `407 Proxy Authentication Required`.
  Tratalo como una preferencia, no como una garantía, y leé `X-Warp-Exit` en la
  respuesta del `CONNECT` (o `served` en `/exits`) para saber qué salida te sirvió.

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
  "stack": "masque",
  "pool_size": 2,
  "active": 2,
  "healthy": 2,
  "cooling_down": 0,
  "recycling": false,
  "build": { "commit": "9a09039", "built_at": "2026-11-14T02:35:54Z" },
  "capabilities": { "exits": true },
  "exits": [
    "warp-18e5118a93b5c804 (in_use, served=7, streams=2)",
    "warp-18e5118b232db280 (healthy, served=0, streams=0)"
  ]
}
```

Cada entrada de `exits` tiene forma fija, `<id completo> (<estado>, served=N, streams=N)`,
sin campos opcionales. Los estados son `starting`, `healthy`, `in_use`, `draining`,
`cooldown`; `draining` gana sobre `cooldown`, así que una salida en pleno swap sigue
visible aunque su túnel muera a mitad del swap.

> Los ids son completos: dos enrolamientos hechos segundos aparte comparten los
> primeros dígitos hex, así que un prefijo truncado no distingue una rotación de
> ningún cambio. Compará el id entero para confirmar un egress nuevo.

`served` cuenta **túneles**, no requests: un cliente reutiliza un `CONNECT` para
muchas requests, así que tres descargas por la misma conexión lo incrementan una
sola vez. Es monótono por salida y nunca se resetea: un reciclado reemplaza las
salidas, así que una salida nueva arranca su propio conteo en `0`.

### `capabilities.exits` — declarada, nunca descubierta

`/health` anuncia las superficies opcionales que este binario puede servir:

```json
"capabilities": { "exits": true }
```

La clave está **ausente**, no en `false`, cuando el build en ejecución no puede
servir `/exits` (el pool WireGuard en userspace no implementa hechos por salida).
La ausencia es el punto: un build que sólo conocía la superficie vieja no puede
mentir sobre lo que soporta.

Detectala con una sola lectura, nunca sondeando el endpoint:

```bash
curl -s http://127.0.0.1:8789/health | jq -e '.capabilities.exits == true'
```

> **No sondees `/exits` para averiguarlo.** Un pedido a una ruta que este binario
> no tiene cae en el catch-all del proxy, el pool culpa a la salida que lo cargó y
> esa salida se queda 30 minutos en cooldown. `/health` responde la misma pregunta
> gratis.

### `build` — qué binario está respondiendo

```json
"build": { "commit": "9a09039", "built_at": "2026-11-14T02:35:54Z" }
```

| Campo | Significado |
|-------|-------------|
| `commit` | SHA corto de git con el que se construyó el binario |
| `built_at` | Momento del build, RFC3339 UTC |

Ambos se inyectan en el link con `-ldflags -X` (`main.buildCommit`, `main.buildAt`)
y ambos valen por defecto el literal **`unknown`** — nunca `""` — cuando el binario
no fue estampado, así un build propio o un `go run` local se leen como "nadie
inyectó esto" en lugar de parecer roto. `-version` imprime la etiqueta junto con
ese mismo commit.

Comando de build reproducible exacto (es el que corre el workflow de release):

```bash
go build -trimpath \
  -ldflags="-s -w -X main.buildCommit=$(git rev-parse --short HEAD) -X main.buildAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o warp-minimal ./cmd/warp-minimal
```

---

## API de hechos por salida

`GET /exits` devuelve un array JSON de hechos por salida; `GET /exit/<id>`
devuelve el mismo objeto para una sola salida (`404` si el pool no tiene ese id).
Ambos son de sólo lectura respecto del pool: pedir hechos nunca inscribe, rota ni
promueve una salida.

```bash
curl http://127.0.0.1:8789/exits
curl http://127.0.0.1:8789/exit/warp-18e5118a93b5c804
```

```json
[
  {
    "id": "warp-18e5118a93b5c804",
    "state": "in_use",
    "served": 7,
    "streams": 1,
    "created_at": 1786001204,
    "cooldown_until": 0,
    "in_use_since": 1786004812,
    "ip": "2a09:bac5:c4d2:1f3a::7b2",
    "family": "v6",
    "observed_at": 1786004901,
    "trace": { "ok": true, "at": 1786004901 }
  },
  {
    "id": "warp-18e5118b232db280",
    "state": "healthy",
    "served": 0,
    "streams": 0,
    "created_at": 1786001210,
    "cooldown_until": 0,
    "in_use_since": 0,
    "trace": {
      "ok": false,
      "error": "trace: request [2606:4700:4700::1111]:443: context deadline exceeded",
      "at": 1786004880
    }
  }
]
```

| Campo | Significado |
|-------|-------------|
| `id` | Id completo de la salida, con forma `warp-<hex>` |
| `state` | Exactamente uno de `healthy`, `in_use`, `draining`, `cooldown`, `starting` |
| `served` | Túneles `CONNECT` que estableció esta salida. Monótono por salida y nunca se resetea |
| `streams` | Flujos TCP en vuelo por esta salida ahora mismo (las salidas se comparten) |
| `created_at` | Cuándo se inscribió la salida, epoch en segundos |
| `cooldown_until` | Epoch en segundos en que se levanta el cooldown; `0` = sin cooldown |
| `in_use_since` | Epoch en segundos de la adquisición actual; `0` = nada en vuelo |
| `ip` | Dirección de egress que Cloudflare ve para este túnel — **ausente si no se conoce** |
| `family` | `v4` o `v6`, derivada de `ip` — **ausente si no se conoce** |
| `observed_at` | Epoch en segundos en que se observó ese `ip` — **ausente si no se conoce** |
| `trace` | Resultado del último intento de trace — **ausente si nunca se intentó** |

Reglas contra las que un consumidor tiene que programar:

- **Las marcas de tiempo son epoch en SEGUNDOS, y `0` significa "no aplica",
  nunca 1970.** Compará `cooldown_until` contra tu propio reloj; un `0` es "sin
  cooldown", no "en cooldown desde la época". La convención del cero es lo que
  permite distinguir "nunca" de "hace 56 años".
- **`ip`, `family` y `observed_at` se omiten cuando no se conocen.** Una salida
  viva cuyo trace falló y que no tiene observación cacheada igual informa estado,
  contadores y marcas de tiempo; los campos de dirección simplemente no están.
  Leé "falta" como "todavía no hay respuesta", no como error ni como string vacío.
- **`healthy` significa ELEGIBLE, no alcanzable.** Dice que el pool le entregaría
  esta salida al próximo pedido — túnel arriba, no draining, sin cooldown. Una
  salida elegible que ya lleva flujos informa `in_use`; son variantes de lo mismo,
  y ninguna es un sondeo de alcanzabilidad: el tráfico por una salida `healthy`
  puede fallar igual en el upstream.
- `state` es exactamente uno de `healthy`, `in_use`, `draining`, `cooldown`,
  `starting`. `draining` gana sobre `cooldown`, así que una salida en swap sigue
  visible como `draining` aunque su túnel muera a mitad del swap.
- **`/exit/<id>` con un id desconocido responde `404` con body de texto plano,
  `404 page not found`.** Leé el código de estado, no el body: un chequeo que
  mira el body va a leer una ruta ausente como éxito.
- **Un método distinto de `GET` sobre `/exits` o `/exit/<id>` responde `405`**
  (`method not allowed; use GET`).
- **Un stack sin esta capacidad responde `404`, no `500`**, en ambas rutas y para
  cualquier método — chequeá `capabilities.exits` en `/health` en vez de
  interpretar el 404.

### `trace` — por qué una salida no tiene IP

`trace` publica el último intento de trace de egress (`GET https://1.1.1.1/cdn-cgi/trace`
por el túnel de la propia salida, cuya línea `ip=` es la única fuente honesta de la
dirección de egress real).

| Campo | Significado |
|-------|-------------|
| `ok` | `true` cuando ese intento salió bien |
| `error` | Mensaje de la falla del último intento — se omite cuando `ok` es `true` |
| `at` | Epoch en segundos de ese intento |

El valor sale de la misma observación por salida que llena `ip`/`family`/`observed_at`,
refrescada como máximo una vez cada **45 segundos**: la primera lectura de hechos
con la cache vencida corre un trace por esa salida (10s por intento, todas las
salidas bajo un presupuesto de 30s), y toda lectura intermedia se responde desde
la cache sin handshake. Un sondeo de hechos es barato, pero no gratis, y `trace`
siempre describe el mismo intento que `ip`.

- **Un trace fallido sigue sirviendo la última IP cacheada junto al error.** Si hay
  un éxito previo en cache, `ip`, `family` y `observed_at` siguen poblados mientras
  `trace.ok` es `false` con el motivo — una dirección vieja es accionable, un
  hueco no. Sólo cuando no hay ninguna observación cacheada desaparecen los campos
  de dirección.
- **Un trace exitoso limpia el error anterior**: `trace.ok` describe el último
  intento, no el peor de la historia.
- **La ausencia de `trace` significa "nunca se intentó"**, que es distinto de un
  intento fallido (`ok: false`): el segundo trae `at`, el primero no trae nada.

### `POST /recycle`

Re-inscribe todo el pool para que cada salida obtenga una dirección de egress WARP
nueva. Asíncrono e idempotente: siempre responde **`202 Accepted`**, tanto para la
llamada que arranca el ciclo como para cualquier llamada que llegue con uno en
curso.

```json
{
  "pool_size": 2,
  "active": 2,
  "healthy": 2,
  "cooling_down": 0,
  "exits": ["warp-18e5118a93b5c804 (healthy, served=7, streams=0)"],
  "recycling": true,
  "ok": true,
  "started": true
}
```

- `recycling` es la bandera **real** del pool, leída del snapshot, así que es
  `true` sólo mientras un ciclo está realmente en vuelo. Ya no la fuerza el
  handler. En el pool WireGuard, que no tiene bandera propia, refleja `started` en
  lugar de inventar una rotación que no empezó.
- `started` es `true` sólo para la llamada que efectivamente arrancó el ciclo — es
  cómo se distingue "lo arranqué yo" de "ya había uno corriendo".
- `ok` **es igual a** `started`: un `202` con `ok: false` significa que el ciclo ya
  estaba en curso, no que el pedido falló.

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

## Registro de cambios

### v0.4.0 (2026-11-14)
- **`GET /exits` y `GET /exit/<id>`: la superficie HTTP ahora publica hechos por salida en JSON**, no sólo los strings `"<id> (<estado>, served=N, streams=N)"` embebidos en `/health`. Cada hecho trae `state`, `served`, `streams`, `created_at`, `cooldown_until`, `in_use_since`, el `ip`/`family`/`observed_at` de egress observado y el último `trace`. Las marcas de tiempo son epoch en SEGUNDOS donde `0` significa "no aplica"; `ip`, `family` y `observed_at` se omiten cuando no se conocen; `/exit/<id>` responde `404` para un id desconocido y `405` para un método distinto de `GET`; un stack sin la capacidad responde `404`, nunca `500`
- **`/health` declara `capabilities.exits`**: la capacidad se anuncia donde leerla es gratis, porque sondear `/exits` contra un build que no tiene la ruta cae en el catch-all del proxy, el pool culpa a la salida que lo cargó y esa salida queda 30 minutos en cooldown. La clave está ausente, no en `false`, cuando no hay soporte
- **`/health` publica la identidad del build**: `build: {commit, built_at}`, inyectada con `-ldflags -X main.buildCommit` / `-X main.buildAt` (defaults `unknown`, nunca `""`), para poder distinguir "corre lo instalado" de "corre algo de hace tres horas en memoria". `buildVersion` pasó a `var` por el mismo motivo de `-X`, y el comando de build reproducible exacto quedó documentado
- **`trace: {ok, error, at}` por salida**: el último intento de trace de egress se publica desde la cache de 45s en vez de descartarse, así el plano de control ve *por qué* una salida no tiene IP. Un trace fallido sigue sirviendo la última IP cacheada junto al error; la ausencia de `trace` significa "nunca se intentó" y un éxito limpia el error anterior
- **Preferencia de salida vía `Proxy-Authorization: Basic base64("<exit-id>:")`**: el id viaja como usuario de Basic y el password se ignora. Un id desconocido, `draining` o en `cooldown` cae en la adquisición normal en silencio — el proxy nunca responde `407`
- **`POST /recycle` ya no miente sobre estar en curso**: publicaba `recycling: true` incondicionalmente, incluso cuando no había arrancado nada. Ahora republica la bandera real `recycling` del pool y agrega `started`, con `ok == started`; el `202` no cambia, así que los llamadores existentes siguen funcionando
- **Los pedidos en origin-form ahora se dialan contra su header `Host`**: `proxyRequest` leía sólo `r.URL.Host`, que viene vacío en origin-form (`GET /path` — lo que mandan los navegadores, los sondeos y los health checks mal apuntados), así que la dirección quedaba en `:80`, el dial fallaba y la falla se le cargaba a la salida: 30 minutos de cooldown más un reemplazo, que con `pool_size: 1` es una caída total. Origin-form ahora cae en `r.Host`, y un pedido sin autoridad alguna responde `400` sin tocar el pool. Una falla de dial real contra un destino bien formado sigue marcando la salida, así que no se silencia la detección de salidas muertas
- `-version` reporta `v0.4.0 (<commit corto>)`

---

[⬅️ Volver a English](README.md)