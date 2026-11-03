package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeConfig materializes a config file in an isolated temp dir so every test
// owns its own inputs and never touches the repository or the operator's config.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	return path
}

// TestLoadConfigMissingFileUsesDefaults pins the whole point of the defaults
// rework: with no config file the binary must still produce a working proxy.
// The regression it guards is the old `stack = "wireguard"` fallback, which is
// dropped by networks that block UDP 2408 (pool stays empty, every CONNECT
// times out while /health still answers ok).
func TestLoadConfigMissingFileUsesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(absent) returned error: %v", err)
	}

	if cfg.Listen != "127.0.0.1:8789" {
		t.Errorf("listen = %q, want %q", cfg.Listen, "127.0.0.1:8789")
	}
	if cfg.PoolSize != 2 {
		t.Errorf("pool_size = %d, want 2", cfg.PoolSize)
	}
	if cfg.Stack != "ipv6" {
		t.Errorf("stack = %q, want %q", cfg.Stack, "ipv6")
	}
	if cfg.HealthPath != "/health" {
		t.Errorf("health_path = %q, want %q", cfg.HealthPath, "/health")
	}
	if cfg.LogPath != "" {
		t.Errorf("log_path = %q, want empty (log next to the executable)", cfg.LogPath)
	}
}

// TestLoadConfigFileOverridesOnlyItsOwnFields keeps the config an override:
// a one-line file must change one field and leave the rest at their defaults.
func TestLoadConfigFileOverridesOnlyItsOwnFields(t *testing.T) {
	path := writeConfig(t, `{"pool_size": 4}`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(partial) returned error: %v", err)
	}

	if cfg.PoolSize != 4 {
		t.Errorf("pool_size = %d, want 4", cfg.PoolSize)
	}
	if cfg.Stack != "ipv6" {
		t.Errorf("stack = %q, want the default %q", cfg.Stack, "ipv6")
	}
	if cfg.Listen != "127.0.0.1:8789" {
		t.Errorf("listen = %q, want the default %q", cfg.Listen, "127.0.0.1:8789")
	}
}

// TestLoadConfigExplicitEmptyValuesFallBackToDefaults covers the JSON that sets
// a key to its zero value: it must behave like an absent key, not like an
// instruction to run with an empty listen address or an empty stack.
func TestLoadConfigExplicitEmptyValuesFallBackToDefaults(t *testing.T) {
	path := writeConfig(t, `{"listen": "", "pool_size": 0, "stack": "", "health_path": ""}`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(empty values) returned error: %v", err)
	}

	if cfg.Listen != "127.0.0.1:8789" || cfg.PoolSize != 2 || cfg.Stack != "ipv6" || cfg.HealthPath != "/health" {
		t.Fatalf("empty values did not fall back to defaults: %+v", *cfg)
	}
}

// TestLoadConfigExplicitWireGuardStillSelectsWG proves the WireGuard opt-in is
// untouched: the default moved to MASQUE, the escape hatch did not move at all.
func TestLoadConfigExplicitWireGuardStillSelectsWG(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `{"stack": "wireguard"}`))
	if err != nil {
		t.Fatalf("loadConfig(wireguard) returned error: %v", err)
	}

	if cfg.Stack != "wireguard" {
		t.Fatalf("stack = %q, want the explicit value to survive", cfg.Stack)
	}
	if label, masque := stackFamily(cfg.Stack); masque || label != "wireguard" {
		t.Fatalf("stackFamily(%q) = (%q, %v), want (wireguard, false)", cfg.Stack, label, masque)
	}
}

// TestLoadConfigRejectsWrongType pins that a mistyped value is an error and
// never a silent fall back to the default.
func TestLoadConfigRejectsWrongType(t *testing.T) {
	if _, err := loadConfig(writeConfig(t, `{"pool_size": "2"}`)); err == nil {
		t.Fatal("loadConfig accepted a string pool_size; want a typed JSON error")
	}
}

// TestStackFamily covers the mapping the pool selection depends on.
func TestStackFamily(t *testing.T) {
	cases := []struct {
		stack  string
		label  string
		masque bool
	}{
		{"ipv6", "masque", true},
		{"masque", "masque", true},
		{"warp", "masque", true},
		{"", "masque", true},
		{"wireguard", "wireguard", false},
		{"something-else", "wireguard", false},
	}
	for _, tc := range cases {
		label, masque := stackFamily(tc.stack)
		if label != tc.label || masque != tc.masque {
			t.Errorf("stackFamily(%q) = (%q, %v), want (%q, %v)", tc.stack, label, masque, tc.label, tc.masque)
		}
	}
}

// TestDescribeConfigSource pins the startup diagnostic, including the exact
// wording that tells the operator no file was found.
func TestDescribeConfigSource(t *testing.T) {
	if got, want := describeConfigSource("config.json", true), "config file: config.json"; got != want {
		t.Errorf("describeConfigSource(exists) = %q, want %q", got, want)
	}
	if got, want := describeConfigSource("config.json", false), "config file: none at config.json; using built-in defaults"; got != want {
		t.Errorf("describeConfigSource(absent) = %q, want %q", got, want)
	}
}

// TestFormatConfigEmitsTheEffectiveConfig keeps -print-config honest: parsing
// its output must reproduce the values the process actually runs with.
func TestFormatConfigEmitsTheEffectiveConfig(t *testing.T) {
	out, err := formatConfig(ptr(defaultConfig()))
	if err != nil {
		t.Fatalf("formatConfig returned error: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("-print-config emitted invalid JSON: %v", err)
	}
	if parsed != defaultConfig() {
		t.Fatalf("round trip = %+v, want %+v", parsed, defaultConfig())
	}
}

// TestExampleConfigMatchesDefaults is the drift guardrail: the documented
// example is the only other place the defaults are written down, so it must
// stay byte-equal in meaning to defaultConfig(). Parsing without normalize is
// deliberate — every defaulted field has to be spelled out in the example.
func TestExampleConfigMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("read config.example.json: %v", err)
	}

	var doc Config
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("config.example.json is not valid config JSON: %v", err)
	}
	if doc != defaultConfig() {
		t.Fatalf("config.example.json = %+v, want the built-in defaults %+v", doc, defaultConfig())
	}
}

func ptr(cfg Config) *Config { return &cfg }
