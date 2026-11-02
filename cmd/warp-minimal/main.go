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

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	version := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("warp-minimal v0.2.1")
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8789"
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 2
	}
	if cfg.Stack == "" {
		cfg.Stack = "wireguard"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/health"
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

	reg := warp.NewWGRegistrar()
	pool, err := warp.NewWGPool(warp.PoolConfig{
		PoolSize: cfg.PoolSize,
		Stack:    cfg.Stack,
	}, reg)
	if err != nil {
		log.Fatalf("create warp pool: %v", err)
	}
	defer pool.Close()

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.HealthPath, healthHandler(pool))
	mux.HandleFunc("/recycle", recycleHandler(pool))
	mux.HandleFunc("/", warp.ProxyHandler(pool))

	// Wrap mux so CONNECT requests (not routed by ServeMux) reach the proxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			warp.ProxyHandler(pool)(w, r)
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

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func healthHandler(pool WGPoolStatuser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := pool.Status()
		status["ok"] = true
		status["service"] = "warp-minimal"
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

// WGPoolStatuser es la interfaz que expone wgPool: Status y RecycleAll.
type WGPoolStatuser interface {
	Status() map[string]any
	RecycleAll() (started bool, status map[string]any)
}
