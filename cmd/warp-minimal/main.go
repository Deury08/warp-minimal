package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Deury08/warp-minimal/internal/warp"
)

type Config struct {
	Listen      string `json:"listen"`
	PoolSize    int    `json:"pool_size"`
	Stack       string `json:"stack"`
	HealthPath  string `json:"health_path"`
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	version := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("warp-minimal v0.1.0")
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
		cfg.Stack = "ipv6"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/health"
	}

	pool, err := warp.NewPool(warp.PoolConfig{
		PoolSize: cfg.PoolSize,
		Stack:    cfg.Stack,
	})
	if err != nil {
		log.Fatalf("create warp pool: %v", err)
	}
	defer pool.Close()

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.HealthPath, healthHandler(pool))
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

func healthHandler(pool *warp.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := pool.Status()
		status["ok"] = true
		status["service"] = "warp-minimal"
		json.NewEncoder(w).Encode(status)
	}
}
