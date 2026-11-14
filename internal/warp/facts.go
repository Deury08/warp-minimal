package warp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// traceURL revela la dirección de egreso real de un túnel y si está en WARP.
// Es la ÚNICA fuente honesta de la IP de salida: Exit.IPv6 es la dirección
// asignada al device por el enrollment y el endpoint MASQUE es el peer de
// Cloudflare, ninguna de las dos es por dónde sale el tráfico.
const traceURL = "https://1.1.1.1/cdn-cgi/trace"

// traceTargets son las direcciones de 1.1.1.1 para pedir el trace.
//
// v6 primero NO es preferencia estética: el túnel MASQUE de este deploy es
// IPv6-only y dialar el literal IPv4 hace que el netstack rechace el request con
// "IPv4 address rejected in ipv6-only stack", dejando al plano de control sin
// IP de egreso. 2606:4700:4700::1111 es el mismo servicio que 1.1.1.1.
var traceTargets = []string{
	"[2606:4700:4700::1111]:443",
	"1.1.1.1:443",
}

const (
	// traceCacheTTL evita martillar cdn-cgi/trace: el plano de control consulta
	// los hechos por request y sin cache serían dos traces por petición.
	traceCacheTTL = 45 * time.Second
	// traceTimeout acota el trace: un netstack wedged no puede colgar el handler.
	traceTimeout = 10 * time.Second
	// traceBodyLimit corta un body absurdo; el trace real son ~10 líneas.
	traceBodyLimit = 64 << 10
)

// egressObservation es el último resultado conocido del trace de una exit.
type egressObservation struct {
	ip         string
	family     string
	observedAt time.Time
	// traceErr es el error del ÚLTIMO intento de trace fallido; vacío después de
	// uno exitoso. traceAt es cuándo ocurrió ese intento, zero si nunca hubo uno.
	traceErr string
	traceAt  time.Time
}

// TraceFact publica el resultado del último intento de trace de una exit: el
// plano de control necesita saber POR QUÉ una exit no tiene IP, no sólo que no
// la tiene.
type TraceFact struct {
	OK bool `json:"ok"`
	// Error se omite cuando el trace funcionó: un `error:""` obligaría al
	// consumidor a distinguir vacío de ausente sin necesidad.
	Error string `json:"error,omitempty"`
	// At es epoch absoluto del intento, 0 si nunca se intentó.
	At int64 `json:"at"`
}

// traceFact devuelve el resultado del último intento de trace, leído de la
// cache. Es de sólo lectura a propósito: publicar hechos no puede costar un
// handshake TLS por request. El segundo valor es false cuando nunca se intentó,
// y en ese caso el campo `trace` se omite del JSON: ausencia = "no sé".
func (e *Exit) traceFact() (TraceFact, bool) {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()

	if e.obs.traceAt.IsZero() {
		return TraceFact{}, false
	}
	return TraceFact{
		OK:    e.obs.traceErr == "",
		Error: e.obs.traceErr,
		At:    epochSec(e.obs.traceAt),
	}, true
}

// ExitFact son los hechos propios de una exit, con epoch absoluto.
//
// ip/family/observed_at son los únicos campos que vienen de la red y pueden
// faltar: si el trace falla y no hay cache, quedan ausentes y el resto se
// reporta igual. El plano de control decide qué hacer sin IP; warp-minimal no.
type ExitFact struct {
	ID            string     `json:"id"`
	State         string     `json:"state"`
	Served        int64      `json:"served"`
	Streams       int        `json:"streams"`
	CreatedAt     int64      `json:"created_at"`
	CooldownUntil int64      `json:"cooldown_until"`
	InUseSince    int64      `json:"in_use_since"`
	IP            string     `json:"ip,omitempty"`
	Family        string     `json:"family,omitempty"`
	ObservedAt    int64      `json:"observed_at,omitempty"`
	Trace         *TraceFact `json:"trace,omitempty"`
}

// epochSec convierte a epoch absoluto. Zero significa "no aplica", no 1970: el
// plano de control compara contra su propio reset_at y necesita distinguir
// "nunca" de "hace 56 años".
func epochSec(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// ipFamily nombra la familia de una dirección sin adivinar por el contexto.
func ipFamily(ip string) string {
	if strings.Contains(ip, ":") {
		return "v6"
	}
	return "v4"
}

// traceEgressIP pide cdn-cgi/trace por el dialer dado y devuelve el valor de la
// línea `ip=`. Prueba los targets en orden: un stack IPv6-only rechaza el
// literal IPv4, y un stack IPv4-only rechaza el IPv6.
func traceEgressIP(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (string, error) {
	if dial == nil {
		return "", errors.New("trace: no dialer")
	}

	var firstErr error
	for _, target := range traceTargets {
		ip, err := traceEgressIPAt(ctx, dial, target)
		if err == nil {
			return ip, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", firstErr
}

// traceEgressIPAt hace el trace contra UNA dirección concreta.
func traceEgressIPAt(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), addr string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return "", fmt.Errorf("trace: build request: %w", err)
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, addr)
		},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: traceTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	defer tr.CloseIdleConnections()

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return "", fmt.Errorf("trace: request %s: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trace: status %d from %s", resp.StatusCode, addr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, traceBodyLimit))
	if err != nil {
		return "", fmt.Errorf("trace: read body: %w", err)
	}

	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			if ip := strings.TrimSpace(v); ip != "" {
				return ip, nil
			}
		}
	}
	return "", errors.New("trace: body has no ip= line")
}

// ObserveEgressIP devuelve la IP de egreso que Cloudflare ve para el túnel de
// ESTA exit. No activa ni promueve nada: cada exit ya tiene su propio túnel
// vivo, así que observar una no altera el tráfico de las demás.
//
// Serializa por exit (obsMu) a propósito: dos traces concurrentes contra el
// mismo netstack serían dos handshakes TLS sobre el mismo túnel QUIC, y el
// beneficio de paralelizarlos es nulo porque el resultado se cachea. Exits
// distintas siguen observándose en paralelo, cada una sobre su propio túnel.
//
// Valores de retorno: ip y family quedan vacíos sólo cuando no hay trace ni
// cache. Un trace fallido con cache previo devuelve el cache y un error no nil,
// para que el caller pueda distinguir "dato viejo" de "dato fresco".
func (e *Exit) ObserveEgressIP(ctx context.Context) (ip, family string, observedAt time.Time, err error) {
	tun := e.Tunnel()
	var dial func(context.Context, string, string) (net.Conn, error)
	if tun != nil {
		dial = tun.DialContext
	}
	return e.observeEgressIP(ctx, dial)
}

// observeEgressIP es ObserveEgressIP con el transporte inyectado, para que el
// cache y el fallback se puedan probar sin un netstack vivo.
func (e *Exit) observeEgressIP(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (ip, family string, observedAt time.Time, err error) {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()

	if !e.obs.observedAt.IsZero() && time.Since(e.obs.observedAt) < traceCacheTTL {
		return e.obs.ip, e.obs.family, e.obs.observedAt, nil
	}

	if dial == nil {
		if !e.obs.observedAt.IsZero() {
			return e.obs.ip, e.obs.family, e.obs.observedAt, ErrNoTunnel
		}
		return "", "", time.Time{}, ErrNoTunnel
	}

	ctx, cancel := context.WithTimeout(ctx, traceTimeout)
	defer cancel()

	ip, err = traceEgressIP(ctx, dial)
	// El intento cuenta aunque falle: si sólo se guardara el éxito, un trace
	// roto sería indistinguible de uno que nunca se intentó.
	attemptedAt := time.Now()
	e.obs.traceAt = attemptedAt
	if err != nil {
		log.Printf("egress trace failed on exit %s: %v", e.ID, err)
		// El error se guarda como hecho (D6): es lo que el plano de control
		// necesita para saber por qué no hay IP.
		e.obs.traceErr = err.Error()
		// Servir el último valor conocido antes que dejar al plano de control sin
		// dato: una IP vieja es accionable, un agujero no.
		if !e.obs.observedAt.IsZero() {
			return e.obs.ip, e.obs.family, e.obs.observedAt, err
		}
		return "", "", time.Time{}, err
	}

	// Un trace exitoso limpia el error anterior: `trace.ok` describe el último
	// intento, no el peor de la historia.
	e.obs.ip = ip
	e.obs.family = ipFamily(ip)
	e.obs.observedAt = attemptedAt
	e.obs.traceErr = ""
	return e.obs.ip, e.obs.family, e.obs.observedAt, nil
}

// factLocked arma los hechos propios de la exit. Debe llamarse con Pool.mu
// tomado: lee draining y streams, que están guardados por ese mutex.
func (e *Exit) factLocked() ExitFact {
	return ExitFact{
		ID:            e.ID,
		State:         e.stateLocked(),
		Served:        e.servedCount(),
		Streams:       e.streams,
		CreatedAt:     epochSec(e.CreatedAt),
		CooldownUntil: epochSec(e.Cooldown),
		InUseSince:    epochSec(e.InUseSince),
	}
}

// ExitFacts devuelve los hechos de todas las exits, cada una con su IP de
// egreso observada. La red corre FUERA de Pool.mu: nunca se toma el mutex del
// pool durante un trace, para no bloquear Acquire mientras hablamos con 1.1.1.1.
func (p *Pool) ExitFacts(ctx context.Context) []ExitFact {
	p.mu.Lock()
	pairs := make([]struct {
		e *Exit
		f ExitFact
	}, 0, len(p.exits))
	for _, e := range p.exits {
		pairs = append(pairs, struct {
			e *Exit
			f ExitFact
		}{e: e, f: e.factLocked()})
	}
	p.mu.Unlock()

	out := make([]ExitFact, len(pairs))
	for i, pr := range pairs {
		out[i] = pr.f
		if ip, family, at, err := pr.e.ObserveEgressIP(ctx); ip != "" || err == nil {
			out[i].IP = ip
			out[i].Family = family
			out[i].ObservedAt = epochSec(at)
		}
		// traceFact lee la cache (obsMu), nunca dispara un trace: se arma fuera de
		// Pool.mu y DESPUÉS de observar, así describe el mismo intento que la IP.
		if tr, ok := pr.e.traceFact(); ok {
			out[i].Trace = &tr
		}
	}
	return out
}

// ExitFact devuelve los hechos de una exit por ID, con su IP observada. El
// segundo valor es false cuando ese ID no existe en el pool.
func (p *Pool) ExitFact(ctx context.Context, id string) (ExitFact, bool) {
	p.mu.Lock()
	var (
		target *Exit
		f      ExitFact
	)
	for _, e := range p.exits {
		if e.ID == id {
			target, f = e, e.factLocked()
			break
		}
	}
	p.mu.Unlock()

	if target == nil {
		return ExitFact{}, false
	}
	if ip, family, at, err := target.ObserveEgressIP(ctx); ip != "" || err == nil {
		f.IP = ip
		f.Family = family
		f.ObservedAt = epochSec(at)
	}
	if tr, ok := target.traceFact(); ok {
		f.Trace = &tr
	}
	return f, true
}
