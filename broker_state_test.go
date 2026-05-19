package oauth

import (
	"testing"
	"time"
)

func TestPendingAuth_RoundTrip(t *testing.T) {
	secret := randomSecret(t, 32)
	original := pendingAuth{
		ClientID:             "https://claude.ai/oauth/cimd",
		RedirectURI:          "https://claude.ai/cb",
		Scope:                "openid email",
		ClientState:          "client-state-1",
		CodeChallenge:        "abc123",
		CodeChallengeMethod:  "S256",
		Resource:             "https://mcp.example/",
		UpstreamPKCEVerifier: "verifier-xyz",
		ExpiresAt:            time.Now().Add(time.Minute),
	}
	token, err := encodePendingAuth(secret, original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, ok := decodePendingAuth(secret, token)
	if !ok {
		t.Fatalf("decode failed")
	}
	if got.ClientID != original.ClientID ||
		got.RedirectURI != original.RedirectURI ||
		got.Scope != original.Scope ||
		got.ClientState != original.ClientState ||
		got.CodeChallenge != original.CodeChallenge ||
		got.CodeChallengeMethod != original.CodeChallengeMethod ||
		got.Resource != original.Resource ||
		got.UpstreamPKCEVerifier != original.UpstreamPKCEVerifier {
		t.Errorf("fields mismatch: %#v vs %#v", got, original)
	}
}

func TestAuthCode_RoundTrip(t *testing.T) {
	secret := randomSecret(t, 32)
	original := issuedCode{
		ClientID:             "alice",
		RedirectURI:          "https://x/cb",
		Scope:                "openid",
		CodeChallenge:        "ch",
		CodeChallengeMethod:  "S256",
		Resource:             "https://mcp.example/",
		UpstreamAuthCode:     "upstream-code-xyz",
		UpstreamPKCEVerifier: "verifier",
		ExpiresAt:            time.Now().Add(60 * time.Second),
	}
	token, err := encodeAuthCode(secret, original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, ok := decodeAuthCode(secret, token)
	if !ok {
		t.Fatalf("decode failed")
	}
	if got.UpstreamAuthCode != original.UpstreamAuthCode || got.UpstreamPKCEVerifier != original.UpstreamPKCEVerifier {
		t.Errorf("fields mismatch")
	}
}

func TestPendingAuthVsAuthCode_InfoLabelIsolation(t *testing.T) {
	// A pending-auth token must not decrypt as an auth code (different HKDF info).
	secret := randomSecret(t, 32)
	token, _ := encodePendingAuth(secret, pendingAuth{
		ClientID:  "x",
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if _, ok := decodeAuthCode(secret, token); ok {
		t.Errorf("pending-auth token must not decrypt as auth code")
	}
}

func TestDecode_EmptySecretFails(t *testing.T) {
	if _, ok := decodePendingAuth(nil, "anything"); ok {
		t.Errorf("expected false on empty secret")
	}
	if _, ok := decodeAuthCode(nil, "anything"); ok {
		t.Errorf("expected false on empty secret")
	}
}
