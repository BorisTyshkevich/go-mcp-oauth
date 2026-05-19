package oauth

import "time"

// pendingAuth is the broker's view of an in-flight /authorize request. It is
// encoded as a stateless JWE (encodePendingAuth) and round-tripped through
// the upstream IdP as the `state` parameter; any replica with the shared
// SigningSecret can decode it at /callback.
type pendingAuth struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	ClientState         string
	CodeChallenge       string
	CodeChallengeMethod string

	// Resource is the RFC 8707 resource indicator the client passed at
	// /authorize. Stored verbatim so the eventual `aud` claim byte-matches
	// what the client requested.
	Resource string

	// UpstreamPKCEVerifier is the broker's PKCE verifier for the upstream-IdP
	// leg (OAuth 2.1 §7.5.2 — second, independent PKCE pair vs the
	// MCP-client→broker leg).
	UpstreamPKCEVerifier string

	ExpiresAt time.Time
}

// issuedCode is the broker's view of a downstream authorization code. Encoded
// as a JWE (encodeAuthCode) and returned to the MCP client; redeemed at
// /oauth/token by the same broker (or any replica with the shared secret),
// at which point the wrapped upstream auth code is exchanged with the IdP.
type issuedCode struct {
	ClientID             string
	RedirectURI          string
	Scope                string
	CodeChallenge        string
	CodeChallengeMethod  string
	Resource             string
	UpstreamAuthCode     string
	UpstreamPKCEVerifier string
	ExpiresAt            time.Time
}

func encodePendingAuth(secret []byte, p pendingAuth) (string, error) {
	claims := map[string]any{
		"client_id":              p.ClientID,
		"redirect_uri":           p.RedirectURI,
		"scope":                  p.Scope,
		"client_state":           p.ClientState,
		"code_challenge":         p.CodeChallenge,
		"code_challenge_method":  p.CodeChallengeMethod,
		"resource":               p.Resource,
		"upstream_pkce_verifier": p.UpstreamPKCEVerifier,
		"exp":                    p.ExpiresAt.Unix(),
	}
	return encodeJWE(secret, hkdfInfoPendingAuth, claims)
}

func decodePendingAuth(secret []byte, token string) (pendingAuth, bool) {
	if len(secret) == 0 {
		return pendingAuth{}, false
	}
	claims, err := decodeJWE(secret, hkdfInfoPendingAuth, token)
	if err != nil {
		return pendingAuth{}, false
	}
	return pendingAuth{
		ClientID:             stringFromClaims(claims, "client_id"),
		RedirectURI:          stringFromClaims(claims, "redirect_uri"),
		Scope:                stringFromClaims(claims, "scope"),
		ClientState:          stringFromClaims(claims, "client_state"),
		CodeChallenge:        stringFromClaims(claims, "code_challenge"),
		CodeChallengeMethod:  stringFromClaims(claims, "code_challenge_method"),
		Resource:             stringFromClaims(claims, "resource"),
		UpstreamPKCEVerifier: stringFromClaims(claims, "upstream_pkce_verifier"),
		ExpiresAt:            unixFromClaims(claims, "exp"),
	}, true
}

func encodeAuthCode(secret []byte, c issuedCode) (string, error) {
	claims := map[string]any{
		"client_id":              c.ClientID,
		"redirect_uri":           c.RedirectURI,
		"scope":                  c.Scope,
		"code_challenge":         c.CodeChallenge,
		"code_challenge_method":  c.CodeChallengeMethod,
		"resource":               c.Resource,
		"upstream_auth_code":     c.UpstreamAuthCode,
		"upstream_pkce_verifier": c.UpstreamPKCEVerifier,
		"exp":                    c.ExpiresAt.Unix(),
	}
	return encodeJWE(secret, hkdfInfoAuthCode, claims)
}

func decodeAuthCode(secret []byte, token string) (issuedCode, bool) {
	if len(secret) == 0 {
		return issuedCode{}, false
	}
	claims, err := decodeJWE(secret, hkdfInfoAuthCode, token)
	if err != nil {
		return issuedCode{}, false
	}
	return issuedCode{
		ClientID:             stringFromClaims(claims, "client_id"),
		RedirectURI:          stringFromClaims(claims, "redirect_uri"),
		Scope:                stringFromClaims(claims, "scope"),
		CodeChallenge:        stringFromClaims(claims, "code_challenge"),
		CodeChallengeMethod:  stringFromClaims(claims, "code_challenge_method"),
		Resource:             stringFromClaims(claims, "resource"),
		UpstreamAuthCode:     stringFromClaims(claims, "upstream_auth_code"),
		UpstreamPKCEVerifier: stringFromClaims(claims, "upstream_pkce_verifier"),
		ExpiresAt:            unixFromClaims(claims, "exp"),
	}, true
}

func stringFromClaims(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func unixFromClaims(claims map[string]any, key string) time.Time {
	v, ok := claims[key]
	if !ok {
		return time.Time{}
	}
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0)
	case int64:
		return time.Unix(t, 0)
	case int:
		return time.Unix(int64(t), 0)
	}
	return time.Time{}
}
