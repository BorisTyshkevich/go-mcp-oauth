package oauth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/hkdf"
)

const (
	// jweKidV1 is the kid header set on broker-minted JWE artifacts so
	// decoders pick the HKDF-derived key from SigningSecret.
	jweKidV1 = "v1"

	// HKDF info labels per RFC 5869 §3.2. Each label produces an independent
	// 32-byte key from SigningSecret. Bumping the /vN suffix in any single
	// label rotates that one key without disturbing the others.
	hkdfInfoPendingAuth     = "altinity-mcp/oauth/pending-auth/v1"
	hkdfInfoAuthCode        = "altinity-mcp/oauth/auth-code/v2"
	hkdfInfoDownstreamToken = "altinity-mcp/oauth/downstream-token/v1"
)

// deriveKey returns 32 bytes derived from secret via HKDF-SHA256 with the
// given info label (RFC 5869). Different info labels produce independent
// keys, so a single shared secret can safely back multiple cryptographic
// uses without one context's exposure compromising others.
func deriveKey(secret []byte, info string) []byte {
	h := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, 32)
	_, _ = io.ReadFull(h, out) // hkdf.Reader never errors before requested bytes
	return out
}

// encodeJWE emits a compact JWE document of `claims`, encrypted with a key
// HKDF-derived from secret and the per-context info label.
func encodeJWE(secret []byte, info string, claims map[string]any) (string, error) {
	key := deriveKey(secret, info)
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: key},
		(&jose.EncrypterOptions{}).
			WithType("JWE").
			WithContentType("JSON").
			WithHeader(jose.HeaderKey("kid"), jweKidV1),
	)
	if err != nil {
		return "", err
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// decodeJWE decrypts a JWE produced by encodeJWE and validates the standard
// expiry / claim-whitelist invariants.
func decodeJWE(secret []byte, info string, token string) (map[string]any, error) {
	obj, err := jose.ParseEncrypted(token,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, ErrInvalidToken
	}
	if obj.Header.KeyID != jweKidV1 {
		return nil, ErrInvalidToken
	}
	key := deriveKey(secret, info)
	decrypted, err := obj.Decrypt(key)
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if err := validateJWEClaimsWhitelist(claims); err != nil {
		return nil, err
	}
	if err := validateJWEExpiration(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// jweAllowedClaimKeys is the whitelist of claim keys legal inside any broker
// JWE artifact. Anything outside the list is a sign the JWE was minted by
// some other system or by a buggy code path — fail closed.
var jweAllowedClaimKeys = map[string]bool{
	// Standard JWT claims.
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,

	// Broker artifact claims.
	"client_id":                  true,
	"redirect_uri":               true,
	"redirect_uris":              true,
	"scope":                      true,
	"client_state":               true,
	"code_challenge":             true,
	"code_challenge_method":      true,
	"resource":                   true,
	"upstream_auth_code":         true,
	"upstream_pkce_verifier":     true,
	"upstream_bearer_token":      true,
	"upstream_id_token":          true,
	"upstream_refresh_token":     true,
	"upstream_token_type":        true,
	"token_endpoint_auth_method": true,
	"grant_type":                 true,
	"access_token_exp":           true,
	"email":                      true,
	"name":                       true,
	"hd":                         true,
	"email_verified":             true,
}

func validateJWEClaimsWhitelist(claims map[string]any) error {
	for k := range claims {
		if !jweAllowedClaimKeys[k] {
			return fmt.Errorf("invalid token claims format: disallowed claim key %q", k)
		}
	}
	return nil
}

func validateJWEExpiration(claims map[string]any) error {
	exp, ok := claims["exp"]
	if !ok {
		return nil
	}
	var expTime int64
	switch v := exp.(type) {
	case float64:
		expTime = int64(v)
	case int64:
		expTime = v
	case int:
		expTime = int64(v)
	default:
		return ErrInvalidToken
	}
	if time.Now().Unix() > expTime {
		return ErrInvalidToken
	}
	return nil
}

// errInvalidJWEClaims is exposed for callers that want to distinguish a
// claim-whitelist failure from a generic invalid-token error.
var errInvalidJWEClaims = errors.New("invalid token claims")
