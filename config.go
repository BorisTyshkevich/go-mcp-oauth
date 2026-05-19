package oauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Mode controls how the broker handles tokens issued to MCP clients.
type Mode string

const (
	// ModeForward returns the upstream id_token to the MCP client verbatim.
	// The backend (Grafana / ClickHouse / GitHub / …) is then responsible for
	// validating it against the upstream JWKS. No downstream signing or
	// wrapping is required.
	ModeForward Mode = "forward"

	// ModeGating has the broker mint downstream tokens by JWE-wrapping the
	// upstream id_token with an HKDF-derived secret. The MCP server is the
	// sole validator of downstream tokens; the backend never sees the upstream
	// token. Set BrokerUpstream=true on the Config to additionally have the
	// library act as the AS to MCP clients (otherwise the library is a pure
	// resource server and the operator runs their own AS).
	ModeGating Mode = "gating"
)

// Normalize returns the canonical lowercase form of m. Empty defaults to gating.
func (m Mode) Normalize() Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(string(m)))) {
	case ModeForward:
		return ModeForward
	case ModeGating, "":
		return ModeGating
	default:
		return m
	}
}

// IsForward reports whether m normalises to ModeForward.
func (m Mode) IsForward() bool { return m.Normalize() == ModeForward }

// IsGating reports whether m normalises to ModeGating.
func (m Mode) IsGating() bool { return m.Normalize() == ModeGating }

// Config holds operator-tunable settings for the broker + validator. Nothing
// is read from globals; consumers wire CLI flags / env vars / YAML into this
// struct themselves.
type Config struct {
	// Mode selects forward or gating semantics; see the Mode constants.
	Mode Mode

	// BrokerUpstream applies only when Mode == ModeGating. When true, the
	// library mounts /oauth/{authorize,callback,token} + discovery endpoints
	// and acts as the OAuth AS to MCP clients (otherwise gating is a pure
	// resource server).
	BrokerUpstream bool

	// Issuer is the upstream IdP issuer URL (RFC 8414 §2). Used for OIDC
	// discovery when JWKSURL/AuthURL/TokenURL are not set explicitly.
	Issuer string

	// JWKSURL overrides the upstream JWKS endpoint discovered via Issuer.
	JWKSURL string

	// Audience is the expected `aud` value in upstream id_tokens (RFC 9728
	// §3.3 / RFC 8707 §2). Validation is slash-normalised.
	Audience string

	// ClientID is the OAuth client_id this broker uses against the upstream
	// IdP. Required in broker mode (forward, or gating+BrokerUpstream).
	ClientID string

	// ClientSecret is the upstream OAuth client secret. Required in broker
	// mode unless the upstream supports public-client flows.
	ClientSecret string

	// AuthURL overrides the upstream /authorize endpoint discovered via Issuer.
	AuthURL string

	// TokenURL overrides the upstream /token endpoint discovered via Issuer.
	TokenURL string

	// UserInfoURL overrides the upstream /userinfo endpoint discovered via Issuer.
	UserInfoURL string

	// Scopes lists upstream scopes requested at /authorize.
	Scopes []string

	// RequiredScopes lists scopes the inbound bearer must carry to pass
	// validation. Empty list = no scope check.
	RequiredScopes []string

	// SigningSecret is the HKDF master used to derive keys for every stateless
	// OAuth JWE the broker mints. Required whenever broker mode is active.
	SigningSecret []byte

	// PublicResourceURL is the externally visible base URL the broker
	// advertises in /.well-known/oauth-protected-resource. When empty, it is
	// inferred from inbound request host + path prefix.
	PublicResourceURL string

	// PublicAuthServerURL is the externally visible base URL the broker
	// advertises in /.well-known/oauth-authorization-server. When empty, it is
	// inferred from inbound request host + path prefix.
	PublicAuthServerURL string

	// AllowedEmailDomains constrains accepted principals by email domain.
	AllowedEmailDomains []string

	// AllowedHostedDomains constrains accepted principals by Google-style `hd`
	// hosted/workspace domain claim.
	AllowedHostedDomains []string

	// AllowUnverifiedEmail opts out of the email_verified=true requirement.
	AllowUnverifiedEmail bool

	// UpstreamIssuerAllowlist constrains which upstream identity-token issuers
	// are accepted. When non-empty it takes priority over the singular Issuer
	// for `iss` validation (multi-tenant deployments).
	UpstreamIssuerAllowlist []string

	// UpstreamOfflineAccess requests offline_access (Auth0) or access_type=offline
	// (Google) so the upstream issues a refresh_token usable to extend
	// near-expired id_tokens at /token. v1 does not issue downstream refresh
	// tokens regardless.
	UpstreamOfflineAccess bool

	// UpstreamForceConsent sends `prompt=consent` on every upstream /authorize.
	// Google-family providers only — Auth0 ignores it.
	UpstreamForceConsent bool

	// AccessTokenTTL bounds gating-mode downstream access tokens. Defaults to
	// 1 hour when zero.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL bounds gating-mode downstream refresh tokens. Defaults
	// to 30 days when zero. (v1 still does not actually mint downstream
	// refresh tokens — the field is reserved for the next minor version.)
	RefreshTokenTTL time.Duration

	// AuthorizationPath overrides the default /oauth/authorize path.
	AuthorizationPath string

	// CallbackPath overrides the default /oauth/callback path.
	CallbackPath string

	// TokenPath overrides the default /oauth/token path.
	TokenPath string

	// Logger is used for all library logging. Defaults to slog.Default() when nil.
	Logger *slog.Logger

	// HTTPClient is used for outbound calls to the upstream IdP and JWKS
	// endpoints. Defaults to a client with a 10s timeout when nil.
	HTTPClient *http.Client
}

// Validate runs cross-field invariants. Returns nil on success.
func (c Config) Validate() error {
	m := c.Mode.Normalize()
	if m != ModeForward && m != ModeGating {
		return fmt.Errorf("oauth: unknown mode %q", c.Mode)
	}

	brokerActive := m == ModeForward || (m == ModeGating && c.BrokerUpstream)
	if brokerActive {
		if strings.TrimSpace(c.ClientID) == "" {
			return errors.New("oauth: client_id is required in broker mode")
		}
		if strings.TrimSpace(c.Issuer) == "" &&
			(strings.TrimSpace(c.AuthURL) == "" || strings.TrimSpace(c.TokenURL) == "") {
			return errors.New("oauth: issuer or both auth_url+token_url are required in broker mode")
		}
		if len(c.SigningSecret) == 0 {
			return errors.New("oauth: signing_secret is required in broker mode")
		}
	} else {
		// Pure gating: resource server only. Require either Issuer or JWKSURL
		// so JWT validation has somewhere to fetch keys.
		if strings.TrimSpace(c.Issuer) == "" && strings.TrimSpace(c.JWKSURL) == "" {
			return errors.New("oauth: issuer or jwks_url is required in pure gating mode")
		}
		// Forbid broker-only knobs in pure gating (mirrors altinity's
		// validateOAuthRuntimeConfig — keeps misconfigurations loud at boot).
		forbidden := []struct{ name, val string }{
			{"client_secret", c.ClientSecret},
			{"token_url", c.TokenURL},
			{"auth_url", c.AuthURL},
			{"userinfo_url", c.UserInfoURL},
			{"public_auth_server_url", c.PublicAuthServerURL},
		}
		for _, f := range forbidden {
			if strings.TrimSpace(f.val) != "" {
				return fmt.Errorf("oauth: %s must not be set in pure gating mode (enable broker_upstream first)", f.name)
			}
		}
	}
	return nil
}

func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func (c Config) accessTokenTTL() time.Duration {
	if c.AccessTokenTTL > 0 {
		return c.AccessTokenTTL
	}
	return defaultAccessTokenTTL
}

func (c Config) refreshTokenTTL() time.Duration {
	if c.RefreshTokenTTL > 0 {
		return c.RefreshTokenTTL
	}
	return defaultRefreshTokenTTL
}

// brokerActive reports whether the library will host the AS endpoints.
func (c Config) brokerActive() bool {
	m := c.Mode.Normalize()
	if m == ModeForward {
		return true
	}
	return m == ModeGating && c.BrokerUpstream
}

const (
	defaultHTTPTimeout      = 10 * time.Second
	defaultAccessTokenTTL   = time.Hour
	defaultRefreshTokenTTL  = 30 * 24 * time.Hour
	defaultJWKSCacheTTL     = 5 * time.Minute
	defaultClockSkewSeconds = int64(60)
)
