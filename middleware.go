package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Middleware wraps next so every request must carry a valid Bearer. On
// success the validated *Claims and raw token are attached to the request
// context (read via ClaimsFromContext / RawTokenFromContext). On failure the
// middleware writes an RFC 6750 §3 + RFC 9728 §5 WWW-Authenticate challenge
// and short-circuits the chain.
func (b *Broker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)
		if token == "" {
			b.writeUnauthorized(w, r, ErrMissingToken)
			return
		}
		rawForBackend := token
		// Gating-mode downstream tokens are JWE-wrapped. Try to decrypt; on
		// success swap the validated upstream id_token in for downstream
		// validation. Forward mode skips this path.
		if b.cfg.Mode.IsGating() && len(b.cfg.SigningSecret) > 0 {
			if inner, err := decodeDownstreamAccessToken(b.cfg.SigningSecret, token); err == nil {
				token = inner
			}
		}
		claims, err := b.validator.Validate(token)
		if err != nil {
			b.writeUnauthorized(w, r, err)
			return
		}
		ctx := r.Context()
		ctx = withRawToken(ctx, rawForBackend)
		if claims != nil {
			ctx = withClaims(ctx, claims)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareFunc is a HandlerFunc-friendly variant of Middleware.
func (b *Broker) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	wrapped := b.Middleware(next)
	return wrapped.ServeHTTP
}

// extractBearer pulls the bearer per RFC 6750 §2.1: Authorization request
// header field only (no query string, no body), case-insensitive "Bearer "
// prefix.
func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

func (b *Broker) writeUnauthorized(w http.ResponseWriter, r *http.Request, err error) {
	var (
		status   int
		code     string
		desc     string
	)
	switch {
	case errors.Is(err, ErrInsufficientScopes):
		status, code, desc = http.StatusForbidden, "insufficient_scope", "Insufficient OAuth scopes"
	case errors.Is(err, ErrTokenExpired):
		status, code, desc = http.StatusUnauthorized, "invalid_token", "OAuth token expired"
	case errors.Is(err, ErrMissingToken):
		status, code, desc = http.StatusUnauthorized, "invalid_token", "Authentication required"
	default:
		status, code, desc = http.StatusUnauthorized, "invalid_token", "Authentication required"
	}
	w.Header().Set("WWW-Authenticate", b.challengeHeader(r, code, desc))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func (b *Broker) challengeHeader(r *http.Request, code, desc string) string {
	resourceMetadata := joinURLPath(b.resourceBaseURL(r), defaultProtectedResourceMetadataPath)
	if code == "" {
		code = "invalid_token"
	}
	if desc == "" {
		desc = "Authentication required"
	}
	parts := []string{
		fmt.Sprintf("error=%q", code),
		fmt.Sprintf("error_description=%q", desc),
		fmt.Sprintf("resource_metadata=%q", resourceMetadata),
	}
	scope := strings.Join(oidcScopesForAdvertisement(b.cfg.RequiredScopes), " ")
	if scope == "" {
		scope = strings.Join(oidcScopesForAdvertisement(b.cfg.Scopes), " ")
	}
	if scope != "" {
		parts = append(parts, fmt.Sprintf("scope=%q", scope))
	}
	return "Bearer " + strings.Join(parts, ", ")
}
