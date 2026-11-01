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
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	registrationURL   = "https://api.cloudflareclient.com/v0a2158/reg"
	userAgent         = "WARP for Android"
	cfClientVersion   = "a-6.35-4471"
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
	ID      string `json:"id"`
	Token   string `json:"token"`
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
			Addresses  map[string]string `json:"addresses"`
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
		Type:         "Android",
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

	if os.Getenv("WARP_DEBUG_REG") != "" {
		fmt.Printf("WARP_REG_DEBUG: %s", respBody)
		fmt.Println()
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

	// Client IPv4/IPv6 from interface addresses (map of v4/v6 -> CIDR).
	clientIPv4 := ""
	clientIPv6 := ""
	for key, cidr := range regResp.Config.Interface.Addresses {
		ip := strings.Split(cidr, "/")[0]
		switch key {
		case "v4":
			clientIPv4 = ip
		case "v6":
			clientIPv6 = ip
		default:
			if clientIPv6 == "" && strings.Contains(cidr, ":") {
				clientIPv6 = ip
			}
			if clientIPv4 == "" && !strings.Contains(cidr, ":") {
				clientIPv4 = ip
			}
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

	// Use first 3 bytes of derived key material as the WireGuard reserved bytes.
	reserved := make([]int, 3)
	for i := 0; i < 3 && i < len(derivedKey); i++ {
		reserved[i] = int(derivedKey[i])
	}

	// WireGuard private key is the client's private key (echoed in account or generated locally).
	privateKeyB64 := regResp.Account.PrivateKey
	if privateKeyB64 == "" {
		privateKeyB64 = base64.StdEncoding.EncodeToString(privateKey)
	}

	return WireGuardConfig{
		PrivateKey:    privateKeyB64,
		PeerPublicKey: peerPublicKey,
		Endpoint:      endpoint,
		ClientIPv4:    clientIPv4,
		ClientIPv6:    clientIPv6,
		Reserved:      reserved,
		Token:         regResp.Token,
		DeviceID:      regResp.ID,
	}, nil
}

// enrollResponse carries the interface addresses Cloudflare assigns after
// switching the device to MASQUE (they differ from the WireGuard ones).
type enrollResponse struct {
	Config struct {
		Interface struct {
			Addresses map[string]string `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			Endpoint struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
			PublicKey string `json:"public_key"`
		} `json:"peers"`
	} `json:"config"`
}

// EnrollAndAddresses switches the registered device to the MASQUE tunnel type
// (ECDSA P-256 key enrollment, mirroring the official client) and returns the
// post-enrollment interface addresses.
func EnrollAndAddresses(ctx context.Context, deviceID, token string, pubDER []byte) (string, string, string, string, error) {
	payload, err := json.Marshal(struct {
		Key     string `json:"key"`
		KeyType string `json:"key_type"`
		TunType string `json:"tunnel_type"`
	}{Key: base64.StdEncoding.EncodeToString(pubDER), KeyType: "secp256r1", TunType: "masque"})
	if err != nil {
		return "", "", "", "", fmt.Errorf("marshal enrollment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		strings.Replace(registrationURL, "/reg", "/reg/"+deviceID, 1), bytes.NewReader(payload))
	if err != nil {
		return "", "", "", "", fmt.Errorf("create enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cf-Client-Version", cfClientVersion)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", "", fmt.Errorf("PATCH enrollment: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", fmt.Errorf("enrollment failed: status %d: %s", resp.StatusCode, string(body))
	}

	var enrollEnrollResponse enrollResponse
	if err := json.Unmarshal(body, &enrollEnrollResponse); err != nil {
		return "", "", "", "", fmt.Errorf("parse enrollment response: %w", err)
	}
	v6, v4 := "", ""
	for key, cidr := range enrollEnrollResponse.Config.Interface.Addresses {
		ip := strings.Split(cidr, "/")[0]
		if key == "v6" || (v6 == "" && strings.Contains(cidr, ":")) {
			v6 = ip
		}
		if key == "v4" || (v4 == "" && !strings.Contains(cidr, ":")) {
			v4 = ip
		}
	}
	// peer endpoint: v4 like "162.159.198.2/32", v6 like "[2606:4700:...]/64"
	epV4, epV6, pin := "", "", ""
	if len(enrollEnrollResponse.Config.Peers) > 0 {
		peer := enrollEnrollResponse.Config.Peers[0]
		// Endpoints arrive as "162.159.198.2:0" and "[2606:4700:103::2]:0".
		epV4 = strings.TrimSuffix(peer.Endpoint.V4, ":0")
		core := peer.Endpoint.V6
		if strings.HasSuffix(core, ":0") {
			core = core[:len(core)-2]
		}
		core = strings.TrimSuffix(core, "]")
		core = strings.TrimPrefix(core, "[")
		epV6 = core
		pin = peer.PublicKey
	}
	log.Printf("masque enroll: v4=%q v6=%q endpoint_v4=%q endpoint_v6=%q pin=%d bytes", v4, v6, epV4, epV6, len(pin))
	return v4, v6, epV4, epV6, nil
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
