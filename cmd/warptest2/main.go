package main

// warptest2 probes WARP endpoints using the full production tunnel stack,
// detecting handshake completion from the verbose wg logs.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Deury08/warp-minimal/internal/warp"
)

var candidates = []string{
	"162.159.193.10:2408",
	"162.159.192.1:2408",
	"162.159.193.10:443",
	"162.159.192.1:443",
	"162.159.192.1:8443",
	"162.159.193.10:8443",
	"162.159.193.10:500",
	"162.159.192.1:500",
	"162.159.193.10:854",
	"162.159.192.1:894",
	"162.159.193.10:908",
	"162.159.193.10:934",
	"162.159.193.10:945",
	"162.159.193.10:968",
	"162.159.193.10:1090",
	"162.159.193.10:1091",
	"162.159.193.10:1873",
	"162.159.193.10:1701",
	"162.159.193.10:4500",
}

func main() {
	ctx := context.Background()

	fmt.Println("Registering a WARP device...")
	cfgBase, err := warp.RegisterDevice(ctx)
	if err != nil {
		fmt.Println("register:", err)
		os.Exit(1)
	}
	fmt.Println("registered ok (keys reused for every probe)")

	// Collect wg log lines through the hook.
	var logsBuf strings.Builder
	var mu sync.Mutex
	warp.WGLogHook = func(msg string) {
		mu.Lock()
		logsBuf.WriteString(msg + "\n")
		mu.Unlock()
	}

	fmt.Println()
	for _, ep := range candidates {
		cfg := cfgBase
		cfg.Endpoint = ep

		t, err := warp.NewTunnel(ctx, cfg)
		if err != nil {
			fmt.Printf("%-24s -> newTunnel error: %v\n", ep, err)
			continue
		}
		time.Sleep(6 * time.Second)
		_ = t // deliberately not Closed: teardown deadlocks; probes are short-lived

		mu.Lock()
		logs := logsBuf.String()
		mu.Unlock()
		ok := strings.Contains(logs, "Received handshake response")
		fmt.Printf("%-24s -> handshake response: %v\n", ep, ok)
	}

	fmt.Println("done")
}
