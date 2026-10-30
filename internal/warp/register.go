package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	registrationURL   = "https://api.cloudflareclient.com/v0a2158/reg"
	userAgent         = "okhttp/4.9.3"
	cfClientVersion   = "6.23"
	hkdfSalt          = "cloudflare warp"
	hkdfInfo          = "wireguard"
	defaultPeerPublic = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	defaultEndpoint   = "162.159.193.10:2408"
)

// registrationRequest matches the Cloudflare WARP registration API payload.
type registrationRequest struct {
	Key          string `json:"key"`
	InstallID    string `json:"install_id"`
	FcmToken     string `json:"fcm_token"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Locale       string `json:"locale"`
	WarpEnabled  bool   `json:"warp_enabled"`
	Type         string `json:"type"`
	AppVersion   string `json:"app_version"`
	OsVersion    string `json:"os_version"`
}

// registrationResponse matches the Cloudflare WARP registration API response.
type registrationResponse struct {
	Account struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	} `json:"account"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses map[string]string `json:"addresses"`
			PrivateKey string            `json:"private_key"`
		} `json:"interface"`
	} `json:"config"`
}

// RegisterDevice registers a new WARP device with Cloudflare.
func RegisterDevice(ctx context.Context) (WireGuardConfig, error) {
	// 1. Generate X25519 key pair (scalar = private key, curve point = public key).
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return WireGuardConfig{}, fmt.Errorf("generate private key: %w", err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("derive public key: %w", err)
	}

	// 2. Build registration request.
	req := registrationRequest{
		Key:          base64.StdEncoding.EncodeToString(publicKey),
		InstallID:    "",
		FcmToken:     "",
		Model:        "PC",
		SerialNumber: generateSerialNumber(),
		Locale:       "en_US",
		WarpEnabled:  true,
		Type:         "windows",
		AppVersion:   "6.23",
		OsVersion:    "10.0.19045",
	}

	body, err := json.Marshal(req)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("marshal registration request: %w", err)
	}

	// 3. POST to https://api.cloudflareclient.com/v0a2158/reg.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewReader(body))
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("create registration request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", userAgent)
	httpReq.Header.Set("Cf-Client-Version", cfClientVersion)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("POST registration: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("read registration response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return WireGuardConfig{}, fmt.Errorf("registration failed: status %d: %s", resp.StatusCode, string(respBody))
	}

	var regResp registrationResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return WireGuardConfig{}, fmt.Errorf("parse registration response: %w", err)
	}

	// 4. Extract Cloudflare peer public key and endpoint.
	peerPublicKey := defaultPeerPublic
	endpoint := defaultEndpoint
	if len(regResp.Config.Peers) > 0 && regResp.Config.Peers[0].PublicKey != "" {
		peerPublicKey = regResp.Config.Peers[0].PublicKey
		addr := regResp.Config.Peers[0].Endpoint.Address
		port := regResp.Config.Peers[0].Endpoint.Port
		if addr != "" && port != 0 {
			endpoint = addrPort(addr, port)
		}
	}

	// Determine client IPv6 from interface addresses (map of ipv4/ipv6 -> CIDR).
	clientIPv6 := ""
	for _, cidr := range regResp.Config.Interface.Addresses {
		if strings.Contains(cidr, ":") {
			clientIPv6 = strings.Split(cidr, "/")[0]
			break
		}
	}

	// 5. HKDF-ChaCha20Poly1305 key derivation.
	// Shared secret via X25519 DH: client private key * server public key.
	peerKeyBytes, err := base64.StdEncoding.DecodeString(peerPublicKey)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("decode peer public key: %w", err)
	}
	if len(peerKeyBytes) != 32 {
		return WireGuardConfig{}, fmt.Errorf("peer public key has %d bytes, expected 32", len(peerKeyBytes))
	}

	var peerKeyArray [32]byte
	copy(peerKeyArray[:], peerKeyBytes)
	sharedSecret, err := curve25519.X25519(privateKey, peerKeyArray[:])
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("compute X25519 shared secret: %w", err)
	}

	derivedKey := hkdfDeriveKey(sharedSecret)

	// Use first 4 bytes of derived key material as the WireGuard reserved bytes.
	reserved := make([]int, 4)
	for i := 0; i < 4 && i < len(derivedKey); i++ {
		reserved[i] = int(derivedKey[i])
	}

	// WireGuard private key is the client's private key (echoed in account or generated locally).
	privateKeyB64 := regResp.Account.PrivateKey
	if privateKeyB64 == "" {
		privateKeyB64 = base64.StdEncoding.EncodeToString(privateKey)
	}

	return WireGuardConfig{
		PrivateKey:   privateKeyB64,
		PeerPublicKey: peerPublicKey,
		Endpoint:      endpoint,
		ClientIPv6:    clientIPv6,
		Reserved:      reserved,
	}, nil
}

// generateSerialNumber produces a 16-character hex serial number.
func generateSerialNumber() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "0000000000000000"
	}
	return fmt.Sprintf("%x", buf)
}

// hkdfDeriveKey derives key material using HKDF-SHA256 with the WARP salt and info.
func hkdfDeriveKey(sharedSecret []byte) []byte {
	keyMaterial := make([]byte, 32)
	reader := hkdf.New(sha256.New, sharedSecret, []byte(hkdfSalt), []byte(hkdfInfo))
	if _, err := io.ReadFull(reader, keyMaterial); err != nil {
		return nil
	}
	return keyMaterial
}

// addrPort formats host:port.
func addrPort(addr string, port int) string {
	return fmt.Sprintf("%s:%d", addr, port)
}
