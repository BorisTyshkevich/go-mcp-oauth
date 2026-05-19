package oauth

import (
	"strings"
	"testing"
)

func TestMode_Normalize(t *testing.T) {
	cases := map[Mode]Mode{
		"forward":  ModeForward,
		"FORWARD":  ModeForward,
		"gating":   ModeGating,
		"":         ModeGating,
		"  Gating ": ModeGating,
	}
	for in, want := range cases {
		if got := in.Normalize(); got != want {
			t.Errorf("(%q).Normalize() = %q, want %q", in, got, want)
		}
	}
}

func TestConfig_Validate_GatingResourceServer(t *testing.T) {
	cfg := Config{
		Mode:    ModeGating,
		Issuer:  "https://idp.example/",
		JWKSURL: "https://idp.example/jwks.json",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid: %v", err)
	}
}

func TestConfig_Validate_GatingForbidsClientSecret(t *testing.T) {
	cfg := Config{
		Mode:         ModeGating,
		Issuer:       "https://idp.example/",
		ClientSecret: "should-be-forbidden",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("err=%v", err)
	}
}

func TestConfig_Validate_BrokerRequiresAllFields(t *testing.T) {
	// Forward mode requires client_id + issuer/{auth,token}_url + signing_secret.
	cfg := Config{Mode: ModeForward}
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected forward without fields to fail")
	}
	cfg = Config{
		Mode:          ModeForward,
		Issuer:        "https://idp.example/",
		ClientID:      "client",
		SigningSecret: []byte("0123456789abcdef0123456789abcdef"),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid forward: %v", err)
	}
}

func TestConfig_Validate_GatingBrokerRequiresClientSecret(t *testing.T) {
	cfg := Config{
		Mode:           ModeGating,
		BrokerUpstream: true,
		Issuer:         "https://idp.example/",
		ClientID:       "client",
		SigningSecret:  []byte("0123456789abcdef0123456789abcdef"),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid: %v", err)
	}
}

func TestConfig_Validate_UnknownModeRejected(t *testing.T) {
	cfg := Config{Mode: Mode("weird")}
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected rejection")
	}
}
