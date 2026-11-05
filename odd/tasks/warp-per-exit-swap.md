# warp-minimal: rotación por salida (per-exit swap)

Feature branch: `feat/per-exit-swap`
Consumidor: agente del relay en `pi-free-bridge` (sesión `01a1a9c2`)
Estado: implementado y verificado; el binario desplegado sigue viejo hasta que el
operador recompile y reinicie.

> R1 — Reconstrucción: este archivo lo borró un comando accidental durante la
> preparación de los commits (un `mv` a `/tmp`, que se vacía entre invocaciones).
> Se reescribió desde el registro de la sesión. Las specs son un enunciado fiel de
> lo acordado, no citas textuales: si hace falta la frase original del dueño, está
> en la transcripción de la sesión `01a1a9dc`.

## Specs

- **S1 — Rotación de una sola salida.** Un swap afecta exactamente una salida: deja
  de recibir trabajo nuevo, sus streams vivos terminan (tope 120s) y recién ahí se
  re-enrola esa salida. Las demás salidas no se tocan y no se corta nada en vuelo.
- **S2 — Atribución honesta.** El cliente tiene que poder saber qué salida sirvió
  cada túnel. Para HTTPS el proxy no ve el status del upstream (vive dentro del TLS
  que reenvía), así que el CONNECT responde `X-Warp-Exit` con el **id completo**.
- **S3 — Nunca degradar la última sana.** Si el objetivo es la única salida usable,
  el swap no se ejecuta: `409 no_standby`. Ante la duda, se prefiere un pool con una
  salida vieja antes que un pool sin salidas.
- **S4 — Asíncrono e idempotente.** Un swap en vuelo responde `202` y no arranca un
  segundo drenado de la misma salida. Igual que `/recycle`: nunca duplica
  enrolamientos (que están rate-limitados).
- **S5 — `/recycle` no cambia de contrato.** Sigue siendo pool-wide, asíncrono e
  idempotente. El swap es la alternativa quirúrgica, no un reemplazo.

## Contrato para el relay

```
POST /swap                     cuerpo opcional {"exit":"warp-<hex>"}
202  swap iniciado, o ya en vuelo (idempotente). El body trae "target": "<id aceptado>"
409  no_standby    — la swap dejaría el pool sin salida usable
404  unknown_exit  — el id no está en el pool
405  método no POST
501  el stack activo (WireGuard) no soporta swap por salida
```

Cuerpo vacío: se elige la salida con más streams (la más probablemente limitada).

**Formato estable de `exits[]`:** `"<id completo> (<estado>, served=N, streams=N)"` —
siempre esos tres campos, en ese orden, sin campos opcionales. Es lo que el relay parsea.

**Cada enrolamiento emite un id NUEVO** (`warp-<hex>`); un swap no reusa el id, lo
reemplaza. Por eso la rotación se confirma comparando ids completos: si el id cambió,
la salida es nueva. (Corrección de una frase confusa del primer handover, que decía "el
id culpable reaparece": lo que reaparece es el asiento, con id nuevo.)
`GET /health` lista `exits` con el id completo, el estado (`healthy`, `in_use`,
`draining`, `cooldown`, `starting`), `served` (túneles CONNECT establecidos,
monótono) y `streams` (abiertos ahora).

**Atribución sin leer el CONNECT.** Si el cliente arma el CONNECT por dentro (el
`fetch` de Bun lo hace y esconde la respuesta), el header no le llega. En ese caso
la atribución se hace con `served`: snapshot de `/health`, un intento, snapshot de
nuevo; el exit cuyo `served` subió es el que sirvió la request. Vale para intentos
serializados: con varios en vuelo el delta puede nombrar más de un exit y deja de
ser exacto. Y asume que el relay es el único cliente que abre CONNECT contra el
proxy: cualquier otro proceso que use el 8789 también mueve `served` y contamina
el delta (misma ambigüedad, otra fuente).

Además, Bun reusa el CONNECT (medido por el relay: 3 fetches secuenciales → 1 solo
túnel), así que `served` marca la apertura del túnel y no cada request que viaja
por él. Por eso el consumidor cachea túnel→exit y aprende la salida del delta, en
vez de esperar un delta por request. Si algún día hace falta atribución exacta con
concurrencia o con varios clientes, la vía sería un registro de túneles nuevos
(`GET /egress?since=<n>`): hoy no hace falta y no está implementado.

**Reglas del consumidor (acordadas con el relay).** La atribución vive del lado del
relay, porque solo él sabe si su túnel sigue vivo:

1. Aprende únicamente en una ventana donde su propio intento abrió túnel: mapa
   vacío, intento anterior caído a nivel transporte, o swap recién pedido (el drain
   mata ese túnel).
2. En esa ventana exige delta total == 1; 0 o 2+ dejan el mapa dudoso.
3. Con mapa válido y túnel vivo, cualquier delta es de otro cliente: se ignora y
   nunca sobreescribe el mapa. **Esta es la regla que separa**: `delta == 1` solo no
   alcanza, porque un CONNECT ajeno también da 1.
4. Mapa dudoso al decidir → no rota, aplica retry-after puro. El escape manual existe
   fuera de esto (`/free-bridge-warp-recycle`, del lado del relay).
5. Delta sobre su propio exit con su túnel vivo → contradicción → knockout del mapa
   (conservador: cuesta un ciclo sin atribución, que la política ya absorbe).

Costo del error, acotado por diseño: un swap equivocado es 1 enrolamiento y un drain,
sin pérdida de datos ni streams cortados, y `fill` vuelve a `pool_size`. Por eso
"ante duda, no rotar" alcanza y no hace falta superficie nueva en el proxy.

La respuesta CONNECT incluye `X-Warp-Exit: warp-<hex>`.

## Tasks

| ID | Spec | Ruta | Commit |
|----|------|------|--------|
| T1 | S1, S2 | `internal/warp/types.go`, `internal/warp/pool.go` — `draining`, `usableLocked`, `hasStandbyLocked`, `Swap`, `completeSwap`, `waitDrained` | `c34e209` |
| T2 | S3 | `pool.go` — guarda `hasStandbyLocked` → `no_standby` | `c34e209` |
| T3 | S4 | `pool.go` — `swapping` + guarda en `Swap`/`RecycleAll` | `c34e209` |
| T4 | S2 | `internal/warp/proxy.go` — `X-Warp-Exit` en el CONNECT | `209dd95` |
| T5 | S1-S5 | `cmd/warp-minimal/main.go` — `swapHandler` y ruta `/swap` | `209dd95` |
| T6 | S2 | `types.go`, `proxy.go`, `pool.go` — contador `served` por exit en `/health` | este commit |

## Evidencia

- `internal/warp/pool_test.go`: `TestSwapRefusesLastHealthy`, `TestSwapDrainsThenReplacesOnlyTarget`,
  `TestSwapUnknownExit`, `TestSwapIsIdempotentWhileDraining`.
- `internal/warp/proxy_test.go`: `TestConnectReplyCarriesEgressID` (también prueba que un CONNECT suma
  exactamente 1 en `served` del exit que dialeó).
- `internal/warp/pool_test.go`: `TestStatusReportsServedPerExit`.
- Mutaciones del contador: sacar `noteServed()` → el test falla con `served = 0`; cambiar el nombre del
  campo en `/health` → el test falla. Ambas restauradas.
- Mutaciones verificadas (cada una rompe un test y se restauró):
  M1 sin guarda de standby → el pool llega a `healthy:0`; M2 sin espera de drenado → el reemplazo
  ocurre con el stream vivo; M3 sin header → `X-Warp-Exit = ""`.
- `go vet ./...` limpio; `go test ./... -count=2 -race` verde.
- Probe en vivo sobre el puerto aislado 8893 (nunca 8789): `X-Warp-Exit: warp-18e5257c545b2e64`,
  `POST /swap` → `202`, después `warp-18e52584cc62f704` (nueva) y `warp-18e5257cea30a874` (intacta),
  `404`/`405` correctos, log `drained, re-enrolling that exit only`.

## Restricciones operativas (vigentes)

El proxy de `127.0.0.1:8789` y el relay son el transporte de las propias sesiones que
trabajan en esto: cerrar cualquiera de los dos corta a ambos agentes. Regla del dueño:
se construye, pero toda prueba que pueda tumbar uno de los dos queda **pendiente hasta
que él avise**.

- **Permitido contra 8789:** solo `GET /health` (lectura pura).
- **Diferido:** `POST /recycle` (corta los streams en vuelo → tumba el bridge),
  `POST /swap` (drena una salida y quema un enrolamiento), recompilar/reiniciar el
  8789, y levantar otra instancia del binario: no toca el 8789, pero enrola
  dispositivos propios y compite por el mismo rate limit, así que puede dejar al pool
  vivo sin poder reemplazar salidas. Es un riesgo indirecto, no nulo.
- **Permitido siempre:** código, tests, fixtures, `go vet`, `go test` y leer archivos.
- **En la frontera:** si una prueba parece segura pero roza la línea, se pregunta antes
  de correrla. Vale en las dos direcciones (agente ↔ agente).

Consecuencia: la verificación de aceptación 1-4 del relay espera el deploy, y mientras
tanto se hace con fixtures. Las transiciones de estado de `/health` (`draining`,
`healthy` cayendo a 1) son justamente lo que las fixtures no prueban.

## Log

- **L1** Pedido del dueño: que el pool no se quede con una sola salida y que el relay pueda rotar
  una salida sin cortar el tráfico en vuelo.
- **L2** Corrección del relay: la política de rotación la decide el relay con el `retry-after` del 429;
  el proxy solo da la palanca. Se descartó contar fallos en el proxy.
- **L3** Corrección del relay aceptada por el dueño: `/health` no puede garantizar `pool_size`
  (el pool puede estar degradado) y no existe "el exit activo".
- **L4** El relay sostuvo que la atribución por header es imposible por TLS. Corrección: lo imposible
  es leer el status del upstream; el CONNECT sí puede nombrar la salida, y se implementó así.
- **L5** Incidente: durante la preparación de los commits, un `awk`/`mv` sobre `/tmp` (que se vacía
  entre invocaciones) borró la cola de `pool.go`, `proxy_test.go` y este archivo. Se reconstruyeron
  y la suite volvió a verde antes de commitear. Lección: los respaldos van dentro del repo o de
  `$TEMP`, nunca en `/tmp`, y las ediciones frágiles se hacen con edición exacta, no con rangos.
