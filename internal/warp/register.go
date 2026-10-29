package warp

import (
	"context"
	"fmt"
)

// RegisterDevice registers a new WARP device with Cloudflare (stub).
func RegisterDevice(ctx context.Context) (WireGuardConfig, error) {
	// TODO: Implement actual Cloudflare WARP registration
	// 1. Generate X25519 key pair
	// 2. POST to https://api.cloudflareclient.com/v0a2158/reg
	// 3. Parse response
	// 4. Derive WireGuard keys using HKDF-ChaCha20Poly1305
	// 5. Return WireGuardConfig
	return WireGuardConfig{}, fmt.Errorf("RegisterDevice: not implemented")
}
