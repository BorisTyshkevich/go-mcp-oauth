package oauth

import (
	"time"
)

// downstreamAccessToken wraps an upstream id_token (plus optionally a refresh
// token) in a JWE so backends never see the upstream bearer. Used only in
// gating mode (broker or pure resource server).
//
// The wire format is `<JWE compact serialization>`; consumers treat it as an
// opaque bearer and feed it back to the Validator, which decrypts and
// returns the embedded upstream id_token's claims via the same context
// helpers used by forward mode.

// encodeDownstreamAccessToken JWE-wraps upstreamIDToken with HKDF-derived
// keys. exp is the embedded token's identity-claim exp (so the wrapped JWE
// expires no later than the upstream id_token).
func encodeDownstreamAccessToken(secret []byte, upstreamIDToken string, exp time.Time) (string, error) {
	claims := map[string]any{
		"upstream_id_token": upstreamIDToken,
		"exp":               exp.Unix(),
	}
	return encodeJWE(secret, hkdfInfoDownstreamToken, claims)
}

// decodeDownstreamAccessToken decrypts a JWE produced by
// encodeDownstreamAccessToken and returns the wrapped upstream id_token. The
// JWE's `exp` is the upstream id_token's `exp`; once that passes, decodeJWE
// returns ErrInvalidToken via validateJWEExpiration.
func decodeDownstreamAccessToken(secret []byte, token string) (string, error) {
	claims, err := decodeJWE(secret, hkdfInfoDownstreamToken, token)
	if err != nil {
		return "", err
	}
	idToken, _ := claims["upstream_id_token"].(string)
	if idToken == "" {
		return "", ErrInvalidToken
	}
	return idToken, nil
}
