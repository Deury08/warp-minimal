package main

// warptest probes which WARP endpoints accept a real WireGuard handshake
// from this network. Run: go run ./cmd/warptest

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Deury08/warp-minimal/internal/warp"
	"golang.zx2c4.com/wireguard/conn"
	wgdev "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

var endpoints = []string{
	"162.159.193.10:2408",
	"162.159.192.1:2408",
	"162.159.193.5:500",
	"162.159.193.10:894",
	"162.159.193.10:1701",
	"162.159.193.10:4500",
}

func main() {
	fmt.Println("Registering a WARP device...")
	cfg, err := warp.RegisterDevice(context.Background())
	if err != nil {
		fmt.Println("register:", err)
		os.Exit(1)
	}
	fmt.Printf("Registered: client v6=%s v4=%s\n\n", cfg.ClientIPv6, cfg.ClientIPv4)

	found := ""
	for _, ep := range endpoints {
		if probe(ep, cfg) {
			found = ep
			break
		}
	}
	if found == "" {
		fmt.Println("RESULT: no endpoint responded (ISP likely blocks WARP WireGuard UDP)")
		os.Exit(1)
	}
	fmt.Printf("RESULT: SUCCESS -> %s\n", found)
}

// probe returns true when the peer answers the WG handshake within ~4s.
func probe(endpoint string, cfg warp.WireGuardConfig) bool {
	var mu sync.Mutex
	success := false

	// Custom logger that flags completed handshakes.
	captureLog := func(level string) func(string, ...any) {
		return func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			mu.Lock()
			if strings.Contains(msg, "handshake response") || strings.Contains(msg, "Received handshake") {
				success = true
			}
			mu.Unlock()
			fmt.Printf("  [%s] %s\n", level, strings.TrimSpace(msg))
		}
	}
	log := &wgdev.Logger{
		Verbosef: captureLog("V"),
		Errorf:   captureLog("E"),
	}

	nt := newNoopTun()
	dev := wgdev.NewDevice(nt, conn.NewDefaultBind(), log)
	defer dev.Close()
	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%d\n",
		b64ToHex(cfg.PrivateKey), b64ToHex(cfg.PeerPublicKey), endpoint, 1,
	)); err != nil {
		fmt.Printf("%s: ipc: %v\n", endpoint, err)
		return false
	}

	// keepalive interval=1 forces continuous handshake attempts; watch 4s.
	time.Sleep(4 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("%s -> handshake response: %v\n\n", endpoint, success)
	return success
}

func b64ToHex(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return hex.EncodeToString(raw)
}

// noopTun is a tun.Device that reads forever (blocks) so the wg device only
// services handshakes and keepalives.
type noopTun struct {
	file    os.File
	mu      sync.Mutex
	stopped chan struct{}
}

func newNoopTun() *noopTun { return &noopTun{stopped: make(chan struct{})} }

func (n *noopTun) File() *os.File { return &n.file }

func (n *noopTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Block until the device closes: the probe never sends data-plane traffic.
	<-n.stopped
	return 0, nil
}

func (n *noopTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }

func (n *noopTun) MTU() (int, error) { return 1280, nil }
func (n *noopTun) Name() (string, error) { return "probe0", nil }

func (n *noopTun) Events() <-chan wgtun.Event { return nil }

var _ wgtun.Device = (*noopTun)(nil)

func (n *noopTun) Close() error { close(n.stopped); return nil }

func (n *noopTun) BatchSize() int { return 1 }
