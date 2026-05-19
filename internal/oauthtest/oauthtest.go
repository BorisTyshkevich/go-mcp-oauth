// Package oauthtest holds test helpers shared by package oauth tests:
// inline RSA keypair generation, a small JWKS HTTP server, and a JWT
// signer that mimics an upstream IdP.
package oauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// MockIDP is a tiny upstream IdP: holds an RSA keypair, exposes a JWKS
// endpoint and an OIDC discovery endpoint. Tests use it to mint id_tokens
// the broker can validate.
type MockIDP struct {
	Server *httptest.Server
	Key    *rsa.PrivateKey
	KeyID  string
	Issuer string
}

// New starts a mock IdP. The caller must Close() it.
func New(t *testing.T) *MockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	m := &MockIDP{Key: key, KeyID: "test-kid"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 m.Issuer,
			"authorization_endpoint": m.Issuer + "/authorize",
			"token_endpoint":         m.Issuer + "/token",
			"jwks_uri":               m.Issuer + "/jwks.json",
			"userinfo_endpoint":      m.Issuer + "/userinfo",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: m.KeyID, Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	m.Server = httptest.NewServer(mux)
	m.Issuer = m.Server.URL
	return m
}

// Close shuts down the mock IdP.
func (m *MockIDP) Close() { m.Server.Close() }

// MintIDToken signs a JWT with the IdP's RSA key.
func (m *MockIDP) MintIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), m.KeyID),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	// Inject sensible defaults if caller omits.
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = m.Issuer
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return token
}

// MustField fails the test if claims[key] is missing.
func MustField(t *testing.T, claims map[string]any, key string) any {
	t.Helper()
	v, ok := claims[key]
	if !ok {
		t.Fatalf("claim %q missing", key)
	}
	return v
}

// RandomSecret returns a 32-byte random secret suitable for HKDF.
func RandomSecret(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return out
}

// Failf is a Fatalf alias that doesn't require importing testing in callers
// that just want to surface a helper error.
func Failf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf(format, args...)
}

// AssertNoErr fails the test on a non-nil err.
func AssertNoErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

var _ = fmt.Sprintf
