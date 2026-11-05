package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Deury08/warp-minimal/internal/warp"
)

type Config struct {
	Listen     string `json:"listen"`
	PoolSize   int    `json:"pool_size"`
	Stack      string `json:"stack"`
	HealthPath string `json:"health_path"`
	// LogPath forwards every log line (including exact failure details)
	// to this file in addition to stdout. Appended, created if missing.
	LogPath string `json:"log_path"`
}

// buildVersion identifies the binary. It must move whenever new code could be
// confused with an existing tag: a stale version string is how a WireGuard-only
// build once shipped reporting "v0.1.0" while carrying newer code.
const buildVersion = "v0.2.3"

// Built-in defaults. They mirror config.example.json exactly (guarded by
// TestExampleConfigMatchesDefaults) and describe the configuration this proxy
// ships with: MASQUE over QUIC/UDP 443 with IPv6-only egress.
//
// WireGuard (UDP 2408) is deliberately NOT the default. On the networks this
// tool targets the handshakes are dropped, the pool never fills, and every
// CONNECT times out after 10s while /health still reports ok — a silent failure.
// It stays available as the explicit `"stack": "wireguard"` opt-in.
//
// IPv6-only egress is also an isolation decision: each tunnel gets its own
// dedicated IPv6 exit, so rotating an exit yields a genuinely new egress
// address, while the WARP IPv4 side shares a narrow range across all sessions.
const (
	defaultListen     = "127.0.0.1:8789"
	defaultPoolSize   = 2
	defaultStack      = "ipv6"
	defaultHealthPath = "/health"
)

// defaultConfig returns the built-in defaults as a value the file loader starts
// from, so the loader, -print-config and the documented example all read from a
// single source of truth.
func defaultConfig() Config {
	return Config{
		Listen:     defaultListen,
		PoolSize:   defaultPoolSize,
		Stack:      defaultStack,
		HealthPath: defaultHealthPath,
	}
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	version := flag.Bool("version", false, "Print version and exit")
	printConfig := flag.Bool("print-config", false, "Print the effective config as JSON and exit")
	flag.Parse()

	if *version {
		fmt.Println("warp-minimal " + buildVersion)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if *printConfig {
		out, err := formatConfig(cfg)
		if err != nil {
			log.Fatalf("print config: %v", err)
		}
		fmt.Println(string(out))
		return
	}

	// Persistent failure log: capture every diagnostic line (exact upstream
	// errors, pool failures, tunnel state) to a file next to the binary so a
	// dead console doesn't hide what failed. Default: warp-minimal.log next
	// to the executable; override with log_path in the config.
	logPath := cfg.LogPath
	if logPath == "" {
		if exe, err := os.Executable(); err == nil {
			logPath = filepath.Join(filepath.Dir(exe), "warp-minimal.log")
		} else {
			logPath = "warp-minimal.log"
		}
	}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, f))
		log.Printf("logging to %s", logPath)
	} else {
		log.Printf("ERROR: cannot open log file %s: %v (stdout only)", logPath, err)
	}

	// Say where the values came from. An absent config used to be
	// indistinguishable from a configured one, which turned a broken stack
	// default into a silent failure.
	log.Printf("config: %s", describeConfigSource(*configPath, configFileExists(*configPath)))
	log.Printf("config: stack=%s pool=%d listen=%s health=%s", cfg.Stack, cfg.PoolSize, cfg.Listen, cfg.HealthPath)

	stackLabel, useMasque := stackFamily(cfg.Stack)
	var pool appPool
	var egressPool warp.EgressPool
	if useMasque {
		p, err := warp.NewPool(warp.PoolConfig{PoolSize: cfg.PoolSize})
		if err != nil {
			log.Fatalf("create warp pool: %v", err)
		}
		pool, egressPool = p, warp.MasquePoolEgress(p)
	} else {
		reg := warp.NewWGRegistrar()
		p, err := warp.NewWGPool(warp.PoolConfig{
			PoolSize: cfg.PoolSize,
			Stack:    cfg.Stack,
		}, reg)
		if err != nil {
			log.Fatalf("create warp pool: %v", err)
		}
		pool, egressPool = p, warp.WGPoolEgress(p)
	}
	defer pool.Close()

	proxy := warp.ProxyHandlerEgress(egressPool)

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.HealthPath, healthHandler(pool, stackLabel))
	mux.HandleFunc("/recycle", recycleHandler(pool))
	mux.HandleFunc("/swap", swapHandler(pool))
	mux.HandleFunc("/", proxy)

	// Wrap mux so CONNECT requests (not routed by ServeMux) reach the proxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			proxy(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         cfg.Listen,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutdown signal received")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("warp-minimal listening on %s (pool=%d, stack=%s)", cfg.Listen, cfg.PoolSize, cfg.Stack)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped")
}

// loadConfig resolves the effective configuration: start from the built-in
// defaults, then let the file override only the fields it actually sets. A
// missing file is not an error — the defaults are a supported, working
// configuration — and a partial file is valid too.
func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return &cfg, nil
	}

	// Unmarshalling over the prefilled struct keeps absent keys at their default.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	normalize(&cfg)
	return &cfg, nil
}

// normalize replaces zero values with the defaults. It covers JSON that sets a
// key explicitly to its zero value (`"stack": ""`, `"pool_size": 0`), which
// must behave like an absent key instead of running degraded.
func normalize(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = defaultPoolSize
	}
	if cfg.Stack == "" {
		cfg.Stack = defaultStack
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = defaultHealthPath
	}
}

// stackFamily maps the configured stack value to the pool that serves it. The
// MASQUE family is the default; "ipv6" and "warp" are aliases kept so v0.1.x
// configs keep their meaning. Anything else keeps the WireGuard pool exactly as
// before.
func stackFamily(stack string) (label string, masque bool) {
	switch stack {
	case "", "masque", "ipv6", "warp":
		return "masque", true
	default:
		return "wireguard", false
	}
}

// configFileExists reports whether the config file is present. It only feeds the
// startup diagnostic; read errors are already handled by loadConfig.
func configFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// describeConfigSource renders the startup line that tells the operator whether
// the effective values came from a file or from the built-in defaults.
func describeConfigSource(path string, exists bool) string {
	if exists {
		return "config file: " + path
	}
	return "config file: none at " + path + "; using built-in defaults"
}

// formatConfig renders the effective configuration as JSON for -print-config.
func formatConfig(cfg *Config) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

func healthHandler(pool WGPoolStatuser, stackLabel string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := pool.Status()
		status["ok"] = true
		status["service"] = "warp-minimal"
		// El pool WG reporta su stack fijo; el MASQUE no lo incluye.
		// Se reporta el tipo que construyó main para que el diagnóstico
		// refleje la realidad.
		status["stack"] = stackLabel
		json.NewEncoder(w).Encode(status)
	}
}

// recycleHandler re-enrolls the pool so every exit gets a fresh WARP egress
// IP (the bridge calls this after persistent upstream 429s via warp).
// Always async and idempotent: POST returns 202 with recycling=true both for
// the call that starts the cycle and for any call that arrives while the
// cycle is running, so repeated callers never duplicate enrollment work.
func recycleHandler(pool WGPoolStatuser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed; use POST", http.StatusMethodNotAllowed)
			return
		}
		started, status := pool.RecycleAll()
		log.Printf("recycle requested: started=%v", started)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		status["ok"] = started
		status["recycling"] = true
		json.NewEncoder(w).Encode(status)
	}
}

// swappable es la capacidad opcional de rotar UNA sola salida. Solo *warp.Pool
// la tiene: el pool WireGuard no la implementa y /swap responde 501 ahí.
type swappable interface {
	Swap(targetID string) (started bool, status map[string]any, reason string)
}

// swapHandler rotates exactly one egress exit. The relay uses it after an
// upstream 429 to move traffic onto the other exit without cutting the streams
// in flight — which /recycle cannot avoid — and burning one enrollment instead
// of one per exit.
//
// Async and idempotent: 202 for the call that starts the swap and for any call
// that arrives while it is in flight. The optional body {"exit":"warp-..."}
// selects the target; an empty body picks the exit carrying the most streams.
// 409 means the swap would leave the pool with no usable exit.
func swapHandler(pool appPool) http.HandlerFunc {
	sw, ok := pool.(swappable)
	if !ok {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "per-exit swap is not supported by this stack", http.StatusNotImplemented)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed; use POST", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Exit string `json:"exit"`
		}
		if r.Body != nil {
			// Empty body is valid: pick the busiest exit.
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		started, status, reason := sw.Swap(req.Exit)
		w.Header().Set("Content-Type", "application/json")
		switch reason {
		case "unknown_exit":
			w.WriteHeader(http.StatusNotFound)
			status["ok"] = false
			status["error"] = reason
		case "no_standby":
			w.WriteHeader(http.StatusConflict)
			status["ok"] = false
			status["error"] = reason
		default:
			w.WriteHeader(http.StatusAccepted)
			status["ok"] = started
			status["swapping"] = true
		}
		log.Printf("swap requested: started=%v reason=%q", started, reason)
		json.NewEncoder(w).Encode(status)
	}
}

// WGPoolStatuser es la interfaz que expone wgPool: Status y RecycleAll.
// *warp.Pool la satisface también (Status + RecycleAll).
type WGPoolStatuser interface {
	Status() map[string]any
	RecycleAll() (started bool, status map[string]any)
}

// appPool es lo que main necesita del pool activo: los handlers de
// /health y /recycle más Close para el defer de salida.
type appPool interface {
	WGPoolStatuser
	Close()
}
