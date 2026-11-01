package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	// wgRegistrationURL es el endpoint de registro anónimo de Cloudflare WARP.
	wgRegistrationURL = "https://api.cloudflareclient.com/v0a2158/reg"
	// wgUserAgent imita al cliente oficial de WARP para Android.
	wgUserAgent = "WARP for Android"
	wgCFClientVersion = "a-6.35-4471"
	// wgDefaultPeerPublic es la clave pública por defecto del peer WireGuard de Cloudflare.
	wgDefaultPeerPublic = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	// wgDefaultEndpoint es el endpoint WireGuard de Cloudflare (UDP 2408).
	wgDefaultEndpoint = "162.159.193.10:2408"
)

// wgRegistrationRequest es el payload de POST /reg (registro anónimo de dispositivo WG).
type wgRegistrationRequest struct {
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

// wgRegistrationResponse es la respuesta de POST /reg y GET /reg/<id>.
type wgRegistrationResponse struct {
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

// wgPatchRequest es el payload de PATCH /reg/<id> (habilitar WARP / cambiar túnel).
type wgPatchRequest struct {
	WarpEnabled *bool  `json:"warp_enabled,omitempty"`
	TunnelType  *string `json:"tunnel_type,omitempty"`
}

// WGRegistrar crea y configura un dispositivo anónimo de Cloudflare WARP
// (WireGuard). Devuelve una WireGuardConfig lista para montar un túnel userspace.
type WGRegistrar struct {
	client *http.Client
}

// NewWGRegistrar construye un WGRegistrar con un cliente HTTP con timeout.
func NewWGRegistrar() *WGRegistrar {
	return &WGRegistrar{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// RegisterDevice registra un dispositivo anónimo contra Cloudflare, habilita
// WARP (PATCH) y devuelve la WireGuardConfig (clave privada del par, endpoint
// UDP 2408, IPs de interfaz reservadas).
func (r *WGRegistrar) RegisterDevice(ctx context.Context) (WireGuardConfig, error) {
	// 1. Generar par X25519 (scalar = clave privada, punto = clave pública).
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return WireGuardConfig{}, fmt.Errorf("generate private key: %w", err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("derive public key: %w", err)
	}

	// 2. POST /reg — registro anónimo de dispositivo.
	reqBody := wgRegistrationRequest{
		Key:          base64.StdEncoding.EncodeToString(publicKey),
		InstallID:    "",
		FcmToken:     "",
		Model:        "PC",
		SerialNumber: wgGenerateSerialNumber(),
		Locale:       "en_US",
		WarpEnabled:  true,
		Type:         "Android",
		AppVersion:   "6.23",
		OsVersion:    "10.0.19045",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("marshal registration request: %w", err)
	}

	regResp, err := r.wgPostJSON(ctx, wgRegistrationURL, body)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("POST registration: %w", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(regResp.Body)
		return WireGuardConfig{}, fmt.Errorf("registration failed: status %d: %s", regResp.StatusCode, string(b))
	}

	var parsed wgRegistrationResponse
	if err := json.NewDecoder(regResp.Body).Decode(&parsed); err != nil {
		return WireGuardConfig{}, fmt.Errorf("parse registration response: %w", err)
	}

	// 3. PATCH /reg/<id> — asegurar que WARP esté habilitado (WARP classic).
	if parsed.ID != "" && parsed.Token != "" {
		if err := r.wgEnableWarp(ctx, parsed.ID, parsed.Token); err != nil {
			// No es fatal: el registro ya dio claves e IPs.
			// Continuamos con lo que trajo el registro.
		}
	}

	// 4. GET /reg/<id> — leer la configuración final (peer, endpoint, direcciones).
	cfg, err := r.wgFetchConfig(ctx, parsed.ID, parsed.Token)
	if err != nil {
		// Si GET falla, usamos lo que trajo el registro (puede ser suficiente).
		cfg = wgConfigFromRegistration(parsed, privateKey, publicKey)
	}

	return cfg, nil
}

// wgPostJSON envía un POST con cuerpo JSON y devuelve la *http.Response.
func (r *WGRegistrar) wgPostJSON(ctx context.Context, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", wgUserAgent)
	req.Header.Set("Cf-Client-Version", wgCFClientVersion)
	return r.client.Do(req)
}

// wgEnableWarp hace PATCH /reg/<id> para habilitar WARP (warp_enabled=true).
func (r *WGRegistrar) wgEnableWarp(ctx context.Context, deviceID, token string) error {
	enabled := true
	tunnelType := "wireguard"
	payload, err := json.Marshal(wgPatchRequest{WarpEnabled: &enabled, TunnelType: &tunnelType})
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		strings.Replace(wgRegistrationURL, "/reg", "/reg/"+deviceID, 1), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create patch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", wgUserAgent)
	req.Header.Set("Cf-Client-Version", wgCFClientVersion)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("PATCH enable warp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enable warp failed: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// wgFetchConfig hace GET /reg/<id> y extrae la WireGuardConfig.
func (r *WGRegistrar) wgFetchConfig(ctx context.Context, deviceID, token string) (WireGuardConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.Replace(wgRegistrationURL, "/reg", "/reg/"+deviceID, 1), nil)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("create get request: %w", err)
	}
	req.Header.Set("User-Agent", wgUserAgent)
	req.Header.Set("Cf-Client-Version", wgCFClientVersion)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.client.Do(req)
	if err != nil {
		return WireGuardConfig{}, fmt.Errorf("GET config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return WireGuardConfig{}, fmt.Errorf("get config failed: status %d: %s", resp.StatusCode, string(b))
	}

	var parsed wgRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return WireGuardConfig{}, fmt.Errorf("parse get config: %w", err)
	}
	return wgConfigFromRegistration(parsed, nil, nil), nil
}

// wgConfigFromRegistration convierte una wgRegistrationResponse en WireGuardConfig.
func wgConfigFromRegistration(parsed wgRegistrationResponse, privateKey, publicKey []byte) WireGuardConfig {
	peerPublicKey := wgDefaultPeerPublic
	endpoint := wgDefaultEndpoint
	if len(parsed.Config.Peers) > 0 && parsed.Config.Peers[0].PublicKey != "" {
		peerPublicKey = parsed.Config.Peers[0].PublicKey
		addr := parsed.Config.Peers[0].Endpoint.Address
		port := parsed.Config.Peers[0].Endpoint.Port
		if addr != "" && port != 0 {
			endpoint = fmt.Sprintf("%s:%d", addr, port)
		}
	}

	clientIPv4 := ""
	clientIPv6 := ""
	for key, cidr := range parsed.Config.Interface.Addresses {
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

	privateKeyB64 := parsed.Account.PrivateKey
	if privateKeyB64 == "" && len(privateKey) > 0 {
		privateKeyB64 = base64.StdEncoding.EncodeToString(privateKey)
	}

	return WireGuardConfig{
		PrivateKey:    privateKeyB64,
		PeerPublicKey: peerPublicKey,
		Endpoint:      endpoint,
		ClientIPv4:    clientIPv4,
		ClientIPv6:    clientIPv6,
		Token:         parsed.Token,
		DeviceID:      parsed.ID,
	}
}

// wgGenerateSerialNumber produce un número de serie hexadecimal de 16 caracteres.
func wgGenerateSerialNumber() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "0000000000000000"
	}
	return fmt.Sprintf("%x", buf)
}
