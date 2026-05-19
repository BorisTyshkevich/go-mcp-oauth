package oauth

import "errors"

var (
	// ErrMissingToken is returned when OAuth token is missing.
	ErrMissingToken = errors.New("missing OAuth token")
	// ErrInvalidToken is returned when OAuth token is invalid.
	ErrInvalidToken = errors.New("invalid OAuth token")
	// ErrTokenExpired is returned when OAuth token has expired.
	ErrTokenExpired = errors.New("OAuth token expired")
	// ErrInsufficientScopes is returned when token doesn't have required scopes.
	ErrInsufficientScopes = errors.New("insufficient OAuth scopes")
	// ErrEmailNotVerified is returned when token email is not verified.
	ErrEmailNotVerified = errors.New("OAuth email is not verified")
	// ErrUnauthorizedDomain is returned when token principal domain is not allowed.
	ErrUnauthorizedDomain = errors.New("OAuth identity domain is not allowed")
)
