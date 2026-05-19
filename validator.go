package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// openIDConfiguration captures the subset of the OIDC discovery document the
// library uses.
type openIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// Validator validates inbound bearer JWTs against an upstream JWKS. Safe for
// concurrent use; embeds a JWKS + OIDC discovery cache.
type Validator struct {
	cfg Config

	jwksMu   sync.RWMutex
	jwks     jose.JSONWebKeySet
	jwksURL  string
	jwksTime time.Time

	oidcMu     sync.RWMutex
	oidcCache  openIDConfiguration
	oidcURL    string
	oidcTime   time.Time
	cacheTTL   time.Duration
	clockSkew  int64
	httpClient *http.Client
}

// NewValidator constructs a standalone Validator. Useful for stdio transports
// and tests that don't need the broker endpoints. Returns an error iff the
// Config fails Validate.
func NewValidator(cfg Config) (*Validator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return newValidator(cfg), nil
}

func newValidator(cfg Config) *Validator {
	return &Validator{
		cfg:        cfg,
		cacheTTL:   defaultJWKSCacheTTL,
		clockSkew:  defaultClockSkewSeconds,
		httpClient: cfg.httpClient(),
	}
}

// Validate parses, verifies, and applies identity policy to a raw bearer.
// Returns nil claims with nil error for opaque (non-JWT) bearers in forward
// mode — those are deferred to the backend. In gating mode, opaque bearers
// are rejected.
func (v *Validator) Validate(rawJWT string) (*Claims, error) {
	if rawJWT == "" {
		return nil, ErrMissingToken
	}
	mode := v.cfg.Mode.Normalize()
	if !looksLikeJWT(rawJWT) {
		if mode == ModeGating {
			v.cfg.logger().Error("oauth: bearer is opaque; gating mode requires a signed JWT")
			return nil, ErrInvalidToken
		}
		v.cfg.logger().Debug("oauth: bearer is opaque, skipping local validation")
		return nil, nil
	}
	if strings.TrimSpace(v.cfg.JWKSURL) == "" && strings.TrimSpace(v.cfg.Issuer) == "" {
		v.cfg.logger().Debug("oauth: JWT received but neither issuer nor jwks_url configured; skipping local validation")
		return nil, nil
	}
	claims, err := v.parseAndVerifyJWT(rawJWT, v.cfg.Audience)
	if err != nil {
		v.cfg.logger().Error("oauth: failed to validate bearer", "err", err)
		return nil, err
	}
	return v.applyClaimChecks(claims)
}

// ValidateUpstreamIdentityToken validates an upstream id_token against the
// expected audience and applies identity policy. Used by the broker when it
// receives an id_token directly from the upstream IdP.
func (v *Validator) ValidateUpstreamIdentityToken(token, expectedAudience string) (*Claims, error) {
	claims, err := v.parseAndVerifyJWT(token, expectedAudience)
	if err != nil {
		return nil, err
	}
	if err := v.applyIdentityPolicy(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Validator) applyClaimChecks(claims *Claims) (*Claims, error) {
	if v.cfg.Audience != "" {
		if len(claims.Audience) == 0 {
			v.cfg.logger().Error("oauth: token missing aud", "expected", v.cfg.Audience)
			return nil, ErrInvalidToken
		}
		if !audienceMatchesResource(claims.Audience, v.cfg.Audience) {
			v.cfg.logger().Error("oauth: token aud mismatch", "expected", v.cfg.Audience, "got", claims.Audience)
			return nil, ErrInvalidToken
		}
	}
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+v.clockSkew {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now+v.clockSkew < claims.NotBefore {
		return nil, ErrInvalidToken
	}
	if claims.IssuedAt > 0 && claims.IssuedAt > now+v.clockSkew {
		return nil, ErrInvalidToken
	}
	if len(v.cfg.RequiredScopes) > 0 && !hasRequiredScopes(claims.Scopes, v.cfg.RequiredScopes) {
		return nil, ErrInsufficientScopes
	}
	if err := v.applyIdentityPolicy(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Validator) applyIdentityPolicy(claims *Claims) error {
	if !v.cfg.AllowUnverifiedEmail && claims.Email != "" && !claims.EmailVerified {
		v.cfg.logger().Error("oauth: identity email unverified", "email", claims.Email)
		return ErrEmailNotVerified
	}
	if len(v.cfg.AllowedEmailDomains) > 0 {
		domain := emailDomain(claims.Email)
		if domain == "" || !containsDomain(v.cfg.AllowedEmailDomains, domain) {
			v.cfg.logger().Error("oauth: identity email domain not allowed", "email", claims.Email)
			return ErrUnauthorizedDomain
		}
	}
	if len(v.cfg.AllowedHostedDomains) > 0 {
		if claims.HostedDomain == "" || !containsDomain(v.cfg.AllowedHostedDomains, claims.HostedDomain) {
			v.cfg.logger().Error("oauth: identity hd not allowed", "hd", claims.HostedDomain)
			return ErrUnauthorizedDomain
		}
	}
	return nil
}

func (v *Validator) parseAndVerifyJWT(token, expectedAudience string) (*Claims, error) {
	jwksURI, err := v.resolveJWKSURL()
	if err != nil {
		return nil, err
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return nil, fmt.Errorf("parse signed JWT: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return nil, errors.New("missing JWT header")
	}

	keySet, err := v.fetchJWKS(jwksURI)
	if err != nil {
		return nil, err
	}
	keys := keySet.Keys
	keyID := parsed.Headers[0].KeyID
	if keyID != "" {
		keys = keySet.Key(keyID)
		if len(keys) == 0 {
			// kid absent from cached JWKS — the AS may have rotated. Invalidate
			// and retry once.
			v.jwksMu.Lock()
			v.jwksTime = time.Time{}
			v.jwksMu.Unlock()
			keySet, err = v.fetchJWKS(jwksURI)
			if err != nil {
				return nil, err
			}
			keys = keySet.Key(keyID)
			if len(keys) == 0 {
				return nil, fmt.Errorf("no JWK found for kid %q", keyID)
			}
			v.cfg.logger().Info("oauth: JWKS re-fetched after key rotation", "kid", keyID)
		}
	}

	allowlist := v.cfg.UpstreamIssuerAllowlist
	expectedIssuer := strings.TrimSpace(v.cfg.Issuer)
	var (
		signatureVerified bool
		issuerRejected    bool
		audienceRejected  bool
	)
	for _, k := range keys {
		raw := make(map[string]any)
		if err := parsed.Claims(k.Key, &raw); err != nil {
			continue
		}
		signatureVerified = true
		c := claimsFromRaw(raw)
		if !issuerAllowed(c.Issuer, allowlist, expectedIssuer) {
			issuerRejected = true
			continue
		}
		if expectedAudience != "" && !audienceMatchesResource(c.Audience, expectedAudience) {
			audienceRejected = true
			continue
		}
		return c, nil
	}
	if signatureVerified && (issuerRejected || audienceRejected) {
		return nil, ErrInvalidToken
	}
	return nil, errors.New("failed to verify JWT signature with discovered JWKs")
}

func (v *Validator) resolveJWKSURL() (string, error) {
	if u := strings.TrimSpace(v.cfg.JWKSURL); u != "" {
		return u, nil
	}
	if strings.TrimSpace(v.cfg.Issuer) == "" {
		return "", errors.New("oauth: issuer or jwks_url must be configured")
	}
	d, err := v.fetchOIDCDiscovery(strings.TrimSpace(v.cfg.Issuer))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(d.JWKSURI) == "" {
		return "", errors.New("openid discovery did not return jwks_uri")
	}
	return strings.TrimSpace(d.JWKSURI), nil
}

func (v *Validator) fetchOIDCDiscovery(issuer string) (*openIDConfiguration, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, errors.New("issuer required")
	}
	v.oidcMu.RLock()
	if v.oidcURL == issuer && !v.oidcTime.IsZero() && v.oidcTime.Add(v.cacheTTL).After(time.Now()) && v.oidcCache.Issuer != "" {
		cached := v.oidcCache
		v.oidcMu.RUnlock()
		return &cached, nil
	}
	v.oidcMu.RUnlock()

	candidates := []string{issuer + "/.well-known/openid-configuration"}
	if !strings.Contains(issuer, "/.well-known/") {
		candidates = append(candidates, issuer+"/.well-known/oauth-authorization-server")
	}

	for _, u := range candidates {
		resp, err := v.httpClient.Get(u)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 || readErr != nil {
			continue
		}
		var d openIDConfiguration
		if err := json.Unmarshal(body, &d); err == nil {
			v.oidcMu.Lock()
			v.oidcCache = d
			v.oidcURL = issuer
			v.oidcTime = time.Now()
			v.oidcMu.Unlock()
			return &d, nil
		}
	}
	return nil, fmt.Errorf("failed to discover openid configuration for issuer %q", issuer)
}

func (v *Validator) fetchJWKS(jwksURI string) (*jose.JSONWebKeySet, error) {
	now := time.Now()
	v.jwksMu.RLock()
	if len(v.jwks.Keys) > 0 && v.jwksURL == jwksURI && v.jwksTime.Add(v.cacheTTL).After(now) {
		cached := v.jwks
		v.jwksMu.RUnlock()
		return &cached, nil
	}
	v.jwksMu.RUnlock()

	resp, err := v.httpClient.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read jwks: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	v.jwksMu.Lock()
	v.jwks = keySet
	v.jwksURL = jwksURI
	v.jwksTime = now
	v.jwksMu.Unlock()
	return &keySet, nil
}
