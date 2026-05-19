package oauth

import (
	"net/http"
	"net/url"
	"strings"
)

func normalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// canonicalResourceURL returns the protected-resource identifier in canonical
// form: trimmed, with exactly one trailing slash. RFC 9728 §3.3 (Bearer-Token
// resource_metadata) and RFC 8707 (resource indicators) treat the resource URL
// as an opaque identifier compared by string match; what matters is a stable
// canonical form. Auth0/Google emit the trailing-slash form in `aud` claims
// and Claude.ai expects to round-trip it. Audience validation accepts either
// form via audienceMatchesResource.
func canonicalResourceURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return strings.TrimRight(trimmed, "/") + "/"
}

func normalizedPath(raw string, fallback string) string {
	path := strings.TrimSpace(raw)
	if path == "" {
		path = fallback
	}
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" {
		return path
	}
	return strings.TrimRight(path, "/")
}

func joinURLPath(base string, path string) string {
	base = normalizeURL(base)
	path = normalizedPath(path, "")
	if path == "" || path == "/" {
		return base
	}
	return base + path
}

func ttlSeconds(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func uniquePaths(paths ...string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = normalizedPath(p, "")
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// suffixPrefix returns the path *before* any of the provided well-known
// markers, normalised. Used to derive a deployment's resource/AS prefix from
// the inbound request path when the operator hasn't configured PublicResourceURL
// explicitly.
func suffixPrefix(path string, markers ...string) string {
	for _, m := range markers {
		if !strings.HasPrefix(path, m) {
			continue
		}
		suffix := strings.TrimSpace(strings.TrimPrefix(path, m))
		if suffix == "" {
			continue
		}
		if !strings.HasPrefix(suffix, "/") {
			suffix = "/" + suffix
		}
		return strings.TrimRight(suffix, "/")
	}
	return ""
}

func pathFromConfiguredURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimRight(parsed.Path, "/")
}

// schemeAndHost derives the scheme://host base for outbound URL composition.
// Library variant: no TLS-config lookup — relies on r.TLS and r.Host.
func schemeAndHost(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = strings.ToLower(proto)
	}
	host := r.Host
	if host == "" || strings.ContainsAny(host, "/<>\"'\\") {
		host = "localhost"
	}
	return scheme + "://" + host
}

// sanitizeScope collapses internal whitespace in a scope string to single spaces.
func sanitizeScope(scope string) string {
	return strings.Join(strings.Fields(scope), " ")
}

// normalizeUpstreamScopeForClient maps Google's URI-form OIDC-equivalent
// scopes back to the standard short names the MCP client requested. Mismatch
// between request scope and response scope causes ChatGPT to surface
// "permissions not granted" warnings even when identity claims are present.
// Unknown values pass through unchanged.
func normalizeUpstreamScopeForClient(scope string) string {
	if scope == "" {
		return ""
	}
	parts := strings.Fields(scope)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		var mapped string
		switch p {
		case "https://www.googleapis.com/auth/userinfo.email":
			mapped = "email"
		case "https://www.googleapis.com/auth/userinfo.profile":
			mapped = "profile"
		case "https://www.googleapis.com/auth/openid":
			mapped = "openid"
		default:
			mapped = p
		}
		if _, dup := seen[mapped]; dup {
			continue
		}
		seen[mapped] = struct{}{}
		out = append(out, mapped)
	}
	return strings.Join(out, " ")
}

// oidcScopesForAdvertisement returns the subset of scopes the library will
// surface to MCP clients via discovery metadata + WWW-Authenticate challenges.
// Only the OIDC identity scopes plus Auth0's offline_access refresh-token gate
// are allowed through; URI-form upstream scopes and resource-server scopes are
// stripped because MCP clients (ChatGPT in particular) treat any unfamiliar
// scope token as a "missing permission."
func oidcScopesForAdvertisement(scopes []string) []string {
	allowed := map[string]struct{}{
		"openid":         {},
		"email":          {},
		"profile":        {},
		"offline_access": {},
	}
	out := make([]string, 0, len(scopes))
	seen := make(map[string]struct{})
	for _, s := range scopes {
		if _, ok := allowed[s]; !ok {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// isGoogleIssuer reports whether the configured issuer is Google's OIDC
// provider. Used to pick between `access_type=offline` (Google) and the
// `offline_access` scope (Auth0 and other RFC 6749 §6 strict providers).
func isGoogleIssuer(issuer string) bool {
	host := strings.ToLower(strings.TrimSpace(issuer))
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host, _, _ = strings.Cut(host, "/")
	return host == "accounts.google.com" || host == "www.google.com"
}

// truncateForLog clips long string fields for log emission.
func truncateForLog(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}
