package oauth

import "context"

type contextKey int

const (
	rawTokenContextKey contextKey = iota
	claimsContextKey
)

// withRawToken stores the raw bearer string on ctx.
func withRawToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, rawTokenContextKey, token)
}

// withClaims stores the validated Claims on ctx.
func withClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// RawTokenFromContext returns the raw bearer string set by Middleware.
// The second value is false when no token was attached (anonymous request,
// or middleware not in the chain).
func RawTokenFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(rawTokenContextKey).(string)
	return v, ok && v != ""
}

// ClaimsFromContext returns the validated Claims set by Middleware.
// Returns (nil, false) for unvalidated requests or when middleware was
// bypassed. Returns (claims, true) on success; the *Claims may have a zero
// Email/Subject when the token was opaque and validation was soft-passed —
// callers should treat nil-OK as "authenticated, identity unknown."
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	v, ok := ctx.Value(claimsContextKey).(*Claims)
	return v, ok && v != nil
}
