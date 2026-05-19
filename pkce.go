package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// pkceChallenge returns the RFC 7636 §4.2 S256 challenge for verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newPKCEVerifier generates a 32-byte random PKCE verifier per RFC 7636 §4.1
// (43–128 char URL-safe string). Used for the upstream-IdP leg only — the
// downstream MCP-client supplies its own verifier.
func newPKCEVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
