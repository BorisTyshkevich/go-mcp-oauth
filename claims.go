package oauth

import (
	"encoding/json"
	"strings"
)

// Claims represents the claims extracted from an OAuth token.
type Claims struct {
	Subject       string   `json:"sub"`
	Issuer        string   `json:"iss"`
	Audience      []string `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	NotBefore     int64    `json:"nbf,omitempty"`
	Scopes        []string `json:"scope"`
	Email         string   `json:"email,omitempty"`
	Name          string   `json:"name,omitempty"`
	HostedDomain  string   `json:"hd,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Extra         map[string]any
}

// claimsFromRaw projects a raw JSON claim map into a typed Claims struct.
// Unknown keys land in Extra so callers can read provider-specific fields.
func claimsFromRaw(raw map[string]any) *Claims {
	c := &Claims{Extra: make(map[string]any)}

	if sub, ok := raw["sub"].(string); ok {
		c.Subject = sub
	}
	if iss, ok := raw["iss"].(string); ok {
		c.Issuer = iss
	}
	switch v := raw["exp"].(type) {
	case float64:
		c.ExpiresAt = int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			c.ExpiresAt = n
		}
	}
	switch v := raw["iat"].(type) {
	case float64:
		c.IssuedAt = int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			c.IssuedAt = n
		}
	}
	switch v := raw["nbf"].(type) {
	case float64:
		c.NotBefore = int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			c.NotBefore = n
		}
	}
	if email, ok := raw["email"].(string); ok {
		c.Email = email
	}
	if name, ok := raw["name"].(string); ok {
		c.Name = name
	}
	if hd, ok := raw["hd"].(string); ok {
		c.HostedDomain = hd
	}
	if v, ok := raw["email_verified"].(bool); ok {
		c.EmailVerified = v
	} else if s, ok := raw["email_verified"].(string); ok {
		c.EmailVerified = strings.EqualFold(s, "true")
	}

	switch aud := raw["aud"].(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	}

	switch scope := raw["scope"].(type) {
	case string:
		c.Scopes = strings.Fields(scope)
	case []any:
		for _, s := range scope {
			if str, ok := s.(string); ok {
				c.Scopes = append(c.Scopes, str)
			}
		}
	}

	standard := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
		"scope": true, "email": true, "name": true, "hd": true, "email_verified": true,
	}
	for k, v := range raw {
		if !standard[k] {
			c.Extra[k] = v
		}
	}
	return c
}

// claimsFromUserInfo projects an OIDC /userinfo response into Claims. UserInfo
// documents differ from id_tokens: no exp/iat/aud and scope-as-string-list, so
// the typed surface is narrower.
func claimsFromUserInfo(raw map[string]any) *Claims {
	c := &Claims{Extra: make(map[string]any)}
	if sub, ok := raw["sub"].(string); ok {
		c.Subject = sub
	}
	if iss, ok := raw["iss"].(string); ok {
		c.Issuer = iss
	}
	if email, ok := raw["email"].(string); ok {
		c.Email = email
	}
	if name, ok := raw["name"].(string); ok {
		c.Name = name
	}
	if hd, ok := raw["hd"].(string); ok {
		c.HostedDomain = hd
	}
	if v, ok := raw["email_verified"].(bool); ok {
		c.EmailVerified = v
	}
	if scope, ok := raw["scope"].(string); ok {
		c.Scopes = strings.Fields(scope)
	}
	for k, v := range raw {
		switch k {
		case "sub", "iss", "email", "name", "hd", "email_verified", "scope":
		default:
			c.Extra[k] = v
		}
	}
	return c
}

func emailDomain(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func containsDomain(domains []string, target string) bool {
	for _, d := range domains {
		if strings.EqualFold(strings.TrimSpace(d), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

// audienceMatchesResource compares an incoming `aud` list against an expected
// resource URL with trailing-slash tolerance. RFC 9728 canonicalises with a
// trailing slash; upstream IdPs sometimes emit the form without one.
func audienceMatchesResource(claims []string, expected string) bool {
	exp := strings.TrimRight(strings.TrimSpace(expected), "/")
	for _, c := range claims {
		if c == expected {
			return true
		}
		if strings.TrimRight(strings.TrimSpace(c), "/") == exp {
			return true
		}
	}
	return false
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// issuerAllowed enforces the issuer policy used in upstream-token validation:
//   - when allowlist non-empty → iss MUST be in the list
//   - else when singleIssuer set → iss MUST equal it
//   - else → no check
//
// Comparison is slash-normalised on both sides.
func issuerAllowed(got string, allowlist []string, singleIssuer string) bool {
	norm := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
	got = norm(got)
	if len(allowlist) > 0 {
		for _, a := range allowlist {
			if norm(a) == got {
				return true
			}
		}
		return false
	}
	if norm(singleIssuer) != "" {
		return got == norm(singleIssuer)
	}
	return true
}

// hasRequiredScopes returns true iff every required scope is present in token.
func hasRequiredScopes(tokenScopes, required []string) bool {
	set := make(map[string]struct{}, len(tokenScopes))
	for _, s := range tokenScopes {
		set[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
