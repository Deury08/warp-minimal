package warp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotRegistered se devuelve cuando un exit no tiene registro válido.
	ErrNotRegistered = errors.New("exit not registered")
	// ErrExitClosed se devuelve cuando el exit ya fue cerrado.
	ErrExitClosed = errors.New("exit closed")
)

// HealthURL es el endpoint de Cloudflare que revela si el egress está en WARP.
const HealthURL = "https://1.1.1.1/cdn-cgi/trace"

// healthInterval es cuánto se considera válido un health probe exitoso.
const healthInterval = 30 * time.Second

// exitWG es un exit de WireGuard: un túnel userspace por exit, con su propio
// registro anónimo de dispositivo y health probe.
type exitWG struct {
	mu   sync.Mutex
	cfg  WireGuardConfig
	tun  *Tunnel

	// IPv4/IPv6 de egress asignadas por Cloudflare (para cooldown por bloque).
	IPv4 string
	IPv6 string

	// createdAt marca cuándo se construyó el exit.
	createdAt time.Time
	// healthyUntil marca hasta cuándo el exit pasó el health probe (0 = nunca).
	healthyUntil time.Time
	// failCount cuenta fallos consecutivos de salud/dial.
	failCount int
	// cooldownUntil marca hasta cuándo el exit está en cooldown (0 = ninguno).
	cooldownUntil time.Time
	// closed marca que el exit fue cerrado intencionalmente.
	closed bool
}

// newExitWG registra un dispositivo anónimo y levanta el túnel WireGuard userspace.
func newExitWG(ctx context.Context, reg *WGRegistrar) (*exitWG, error) {
	cfg, err := reg.RegisterDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	tun, err := NewTunnel(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build wireguard tunnel: %w", err)
	}

	e := &exitWG{
		cfg:       cfg,
		tun:       tun,
		IPv4:      cfg.ClientIPv4,
		IPv6:      cfg.ClientIPv6,
		createdAt: time.Now(),
	}
	log.Printf("WARP WG exit %s up: endpoint=%s v4=%s v6=%s", e.ID(), cfg.Endpoint, cfg.ClientIPv4, cfg.ClientIPv6)
	return e, nil
}

// ID devuelve el identificador del dispositivo Cloudflare del exit.
func (e *exitWG) ID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.DeviceID
}

// DialContext diala a través del túnel WireGuard userspace.
func (e *exitWG) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, ErrExitClosed
	}
	tun := e.tun
	e.mu.Unlock()
	if tun == nil {
		return nil, ErrNoTunnel
	}
	return tun.DialContext(ctx, network, addr)
}

// HealthCheck hace GET a cdn-cgi/trace a través del túnel y verifica warp=on.
// Devuelve nil si el egress está vivo y warp=on; error si el túnel está muerto
// o no está por WARP.
func (e *exitWG) HealthCheck(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrExitClosed
	}
	tun := e.tun
	e.mu.Unlock()
	if tun == nil {
		return ErrNoTunnel
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, HealthURL, nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}

	// Transporte HTTP que diala a través del túnel WG userspace.
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tun.DialContext(ctx, network, "1.1.1.1:443")
		},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	defer tr.CloseIdleConnections()

	resp, err := tr.RoundTrip(req)
	if err != nil {
		e.recordFail()
		return fmt.Errorf("health probe: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		e.recordFail()
		return fmt.Errorf("health probe: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.recordFail()
		return fmt.Errorf("read health body: %w", err)
	}

	if !strings.Contains(string(body), "warp=on") {
		e.recordFail()
		return errors.New("health probe: warp=on not found in trace")
	}

	e.mu.Lock()
	e.failCount = 0
	e.healthyUntil = time.Now().Add(healthInterval)
	e.mu.Unlock()
	return nil
}

// recordFail incrementa el contador de fallos consecutivos del exit.
func (e *exitWG) recordFail() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failCount++
}

// FailCount devuelve el número de fallos consecutivos (solo lectura).
func (e *exitWG) FailCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.failCount
}

// HealthyUntil devuelve hasta cuándo el exit se considera sano (0 = nunca).
func (e *exitWG) HealthyUntil() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.healthyUntil
}

// CooldownExpiry devuelve el instante hasta el cual el exit está en cooldown
// (cero si no lo está).
func (e *exitWG) CooldownExpiry() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cooldownUntil
}

// setCooldown marca al exit en cooldown hasta el instante dado.
func (e *exitWG) setCooldown(until time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cooldownUntil = until
}

// clearCooldown quita el cooldown del exit.
func (e *exitWG) clearCooldown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cooldownUntil = time.Time{}
}

// Close cierra el túnel y libera recursos del exit.
func (e *exitWG) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	tun := e.tun
	e.tun = nil
	e.mu.Unlock()
	if tun != nil {
		return tun.Close()
	}
	return nil
}

// IsClosed devuelve true si el exit fue cerrado.
func (e *exitWG) IsClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

// reRegister rota el exit: re-registra el dispositivo y reconstruye el túnel.
// Devuelve un nuevo exitWG (el llamador debe sustituir el viejo en el pool).
func (e *exitWG) reRegister(ctx context.Context, reg *WGRegistrar) (*exitWG, error) {
	// Cerrar el viejo túnel antes de construir el nuevo.
	_ = e.Close()
	return newExitWG(ctx, reg)
}
