package warp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	// wgCooldownDuration es el cooldown por bloque de egress tras un fallo.
	wgCooldownDuration = 30 * time.Minute
	// wgPreloadFraction es el divisor del pool para el preload en caliente.
	wgPreloadFraction = 2
	// wgMinPreload es el mínimo de exits calientes aunque no haya tráfico.
	wgMinPreload = 1
)

// wgPool gestiona una rotación de exits WireGuard (un túnel por exit) con
// preload, rotación inmediata ante 429/403/error de red y cooldown por bloque
// de egress (/64 IPv6 o /32 IPv4, 30 min).
type wgPool struct {
	mu      sync.Mutex
	config  PoolConfig
	reg     *WGRegistrar
	exits   map[string]*exitWG // id -> exit
	order   []string           // orden de inserción para rotación round-robin
	nextIdx int                // índice round-robin

	// blockCooldowns bloquea por bloque de egress hasta el instante dado.
	blockCooldowns map[string]time.Time

	// closed indica que el pool fue cerrado.
	closed bool
}

// NewWGPool construye un pool de exits WireGuard y precarga la mitad del
// tamaño (mínimo 1) en caliente.
func NewWGPool(cfg PoolConfig, reg *WGRegistrar) (*wgPool, error) {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 2
	}

	p := &wgPool{
		config:         cfg,
		reg:            reg,
		exits:          make(map[string]*exitWG),
		blockCooldowns: make(map[string]time.Time),
	}

	// Preload: mitad del pool (mínimo 1) caliente antes del primer tráfico.
	preload := cfg.PoolSize / wgPreloadFraction
	if preload < wgMinPreload {
		preload = wgMinPreload
	}
	if preload > cfg.PoolSize {
		preload = cfg.PoolSize
	}

	ctx := context.Background()
	for i := 0; i < preload; i++ {
		go p.addExit(ctx)
	}

	log.Printf("WARP WG pool created: size=%d preload=%d", cfg.PoolSize, preload)
	return p, nil
}

// addExit crea un exit nuevo, lo registra y lo añade al pool.
func (p *wgPool) addExit(ctx context.Context) {
	exit, err := newExitWG(ctx, p.reg)
	if err != nil {
		log.Printf("WARP WG pool: failed to add exit: %v", err)
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = exit.Close()
		return
	}
	p.exits[exit.ID()] = exit
	p.order = append(p.order, exit.ID())
	p.mu.Unlock()

	log.Printf("WARP WG pool: exit %s added (total=%d)", exit.ID(), p.sizeLocked())
}

// sizeLocked devuelve la cantidad de exits (llamada con mu retenido).
func (p *wgPool) sizeLocked() int { return len(p.exits) }

// Acquire devuelve un exit sano disponible, rotando round-robin. Espera hasta
// que haya uno sano o se cancele el contexto.
func (p *wgPool) Acquire(ctx context.Context) (*exitWG, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("WARP WG pool closed")
		}

		n := p.sizeLocked()
		if n == 0 {
			p.mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			continue
		}

		start := p.nextIdx
		for i := 0; i < n; i++ {
			id := p.order[(start+i)%n]
			e := p.exits[id]
			if e == nil || e.IsClosed() {
				continue
			}
			now := time.Now()
			if !e.CooldownExpiry().IsZero() && now.Before(e.CooldownExpiry()) {
				continue // en cooldown
			}
			p.nextIdx = (start + i + 1) % n
			p.mu.Unlock()
			return e, nil
		}

		p.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
}

// Release devuelve un exit al pool (no-op para WG: los exits son compartidos
// y no se consumen por request).
func (p *wgPool) Release(exit *exitWG) {
	if exit == nil {
		return
	}
	_ = exit
}

// blockKey devuelve la clave de bloque de egress: /32 para IPv4, /64 para IPv6.
func blockKey(ip string) string {
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) >= 4 {
			return strings.Join(parts[:4], ":") + "::/64"
		}
		return ip + "/64"
	}
	return ip + "/32"
}

// isNetworkError informa si err es un error de red/socket (no 429/403 de quota).
func isNetworkError(reason string) bool {
	s := reason
	if strings.Contains(s, "429") || strings.Contains(s, "403") {
		return false
	}
	return strings.Contains(s, "network") ||
		strings.Contains(s, "socket") ||
		strings.Contains(s, "use of closed network connection")
}

// Fail marca un exit como fallido. Si es error de red (429/403/socket) se saca
// del pool y se programa re-registro en background; el bloque de egress entra
// en cooldown 30 min. Errores transitorios solo cuentan fallos.
func (p *wgPool) Fail(exit *exitWG, reason string) {
	if exit == nil {
		return
	}
	exit.recordFail()

	p.mu.Lock()
	_, exists := p.exits[exit.ID()]
	p.mu.Unlock()
	if !exists {
		return
	}

	if isNetworkError(reason) {
		// Rotación inmediata: sacar del pool y re-registrar en background.
		log.Printf("WARP WG pool: exit %s failed with network error (%s); rotating out", exit.ID(), reason)

		p.mu.Lock()
		delete(p.exits, exit.ID())
		for i, id := range p.order {
			if id == exit.ID() {
				p.order = append(p.order[:i], p.order[i+1:]...)
				break
			}
		}
		// Cooldown por bloque de egress (ambos, v4 y v6, si los hay).
		if exit.IPv4 != "" {
			p.blockCooldowns[blockKey(exit.IPv4)] = time.Now().Add(wgCooldownDuration)
		}
		if exit.IPv6 != "" {
			p.blockCooldowns[blockKey(exit.IPv6)] = time.Now().Add(wgCooldownDuration)
		}
		p.mu.Unlock()

		_ = exit.Close()

		// Re-registro en background (no bloquea al llamador).
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			newExit, err := exit.reRegister(ctx, p.reg)
			if err != nil {
				log.Printf("WARP WG pool: background re-register failed for %s: %v", exit.ID(), err)
				return
			}
			p.addExit(context.Background())
			log.Printf("WARP WG pool: exit %s re-registered and added as %s", exit.ID(), newExit.ID())
		}()
		return
	}

	// Error transitorio: si acumula demasiados fallos, cooldown temporal.
	if exit.FailCount() >= 3 {
		log.Printf("WARP WG pool: exit %s repeated failures (%d), cooling down", exit.ID(), exit.FailCount())
		p.mu.Lock()
		exit.setCooldown(time.Now().Add(wgCooldownDuration))
		p.mu.Unlock()
	}
}

// Status devuelve una instantánea del estado del pool.
func (p *wgPool) Status() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()

	exits := make([]string, 0, len(p.exits))
	now := time.Now()
	healthy := 0
	cooling := 0
	for _, id := range p.order {
		e := p.exits[id]
		if e == nil {
			continue
		}
		status := "healthy"
		if e.IsClosed() {
			status = "closed"
		} else if !e.CooldownExpiry().IsZero() && now.Before(e.CooldownExpiry()) {
			status = "cooldown"
			cooling++
		} else {
			healthy++
		}
		exits = append(exits, fmt.Sprintf("%s (%s, fails=%d)", id[:min(8, len(id))], status, e.FailCount()))
	}

	return map[string]any{
		"pool_size":      p.config.PoolSize,
		"active":         len(p.exits),
		"healthy":        healthy,
		"cooling_down":   cooling,
		"stack":          "wireguard",
		"keepalive_s":    25,
		"cooldown_min":   wgCooldownDuration.Minutes(),
		"exits":          exits,
		"block_cooldown": len(p.blockCooldowns),
	}
}

// RecycleAll re-registra todos los exits para obtener IPs de egress frescas.
func (p *wgPool) RecycleAll() (started bool, status map[string]any) {
	p.mu.Lock()
	targets := make([]*exitWG, 0, len(p.exits))
	for _, e := range p.exits {
		if e != nil && !e.IsClosed() {
			targets = append(targets, e)
		}
	}
	snapshot := p.statusSnapshotLocked()
	p.mu.Unlock()

	if len(targets) == 0 {
		return false, snapshot
	}

	var wg sync.WaitGroup
	wg.Add(len(targets))
	for _, e := range targets {
		go func(ex *exitWG) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			newExit, err := ex.reRegister(ctx, p.reg)
			if err != nil {
				log.Printf("WARP WG pool: recycle re-register failed for %s: %v", ex.ID(), err)
				return
			}
			p.mu.Lock()
			delete(p.exits, ex.ID())
			p.exits[newExit.ID()] = newExit
			for i, id := range p.order {
				if id == ex.ID() {
					p.order[i] = newExit.ID()
					break
				}
			}
			_ = ex.Close()
			p.mu.Unlock()
			log.Printf("WARP WG pool: recycled %s -> %s", ex.ID(), newExit.ID())
		}(e)
	}
	go func() {
		wg.Wait()
		log.Print("WARP WG pool recycle complete: fresh egress addresses enrolled")
	}()
	return true, snapshot
}

func (p *wgPool) statusSnapshotLocked() map[string]any {
	exits := make([]string, 0, len(p.exits))
	now := time.Now()
	healthy := 0
	cooling := 0
	for _, id := range p.order {
		e := p.exits[id]
		if e == nil {
			continue
		}
		status := "healthy"
		if e.IsClosed() {
			status = "closed"
		} else if !e.CooldownExpiry().IsZero() && now.Before(e.CooldownExpiry()) {
			status = "cooldown"
			cooling++
		} else {
			healthy++
		}
		exits = append(exits, fmt.Sprintf("%s (%s, fails=%d)", id[:min(8, len(id))], status, e.FailCount()))
	}
	return map[string]any{
		"pool_size":      p.config.PoolSize,
		"active":         len(p.exits),
		"healthy":        healthy,
		"cooling_down":   cooling,
		"stack":          "wireguard",
		"keepalive_s":    25,
		"cooldown_min":   wgCooldownDuration.Minutes(),
		"exits":          exits,
		"block_cooldown": len(p.blockCooldowns),
	}
}

// Close cierra todos los exits y el pool.
func (p *wgPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	exits := make([]*exitWG, 0, len(p.exits))
	for _, e := range p.exits {
		exits = append(exits, e)
	}
	p.exits = make(map[string]*exitWG)
	p.order = nil
	p.mu.Unlock()

	for _, e := range exits {
		_ = e.Close()
	}
	log.Print("WARP WG pool closed")
}
