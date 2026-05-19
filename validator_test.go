package oauth

import (
	"errors"
	"testing"
	"time"

	"github.com/BorisTyshkevich/go-mcp-oauth/internal/oauthtest"
)

func newTestValidator(t *testing.T, idp *oauthtest.MockIDP, modify func(*Config)) *Validator {
	t.Helper()
	cfg := Config{
		Mode:     ModeGating,
		Issuer:   idp.Issuer,
		JWKSURL:  idp.Issuer + "/jwks.json",
		Audience: "https://mcp.example/",
	}
	if modify != nil {
		modify(&cfg)
	}
	v := newValidator(cfg)
	return v
}

func TestValidate_HappyPath(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()

	v := newTestValidator(t, idp, nil)
	tok := idp.MintIDToken(t, map[string]any{
		"sub":            "alice",
		"aud":            "https://mcp.example/",
		"email":          "alice@example.com",
		"email_verified": true,
	})
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("sub: %s", claims.Subject)
	}
}

func TestValidate_MissingToken(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, nil)
	_, err := v.Validate("")
	if !errors.Is(err, ErrMissingToken) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_OpaqueInForwardModeSoftPasses(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, func(c *Config) { c.Mode = ModeForward })
	claims, err := v.Validate("opaque-token")
	if err != nil {
		t.Errorf("expected soft-pass, got %v", err)
	}
	if claims != nil {
		t.Errorf("opaque must yield nil claims")
	}
}

func TestValidate_OpaqueInGatingRejected(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, nil)
	_, err := v.Validate("opaque-token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_WrongAudienceRejected(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, nil)
	tok := idp.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://other.example/",
		"email": "x@example.com", "email_verified": true,
	})
	_, err := v.Validate(tok)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_AudienceTrailingSlashTolerant(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, nil)
	tok := idp.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://mcp.example", // no trailing slash
		"email": "x@example.com", "email_verified": true,
	})
	if _, err := v.Validate(tok); err != nil {
		t.Errorf("expected slash-tolerant accept: %v", err)
	}
}

func TestValidate_ExpiredRejected(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, nil)
	tok := idp.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://mcp.example/",
		"exp":            time.Now().Add(-2 * time.Minute).Unix(),
		"email":          "x@example.com",
		"email_verified": true,
	})
	_, err := v.Validate(tok)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_EmailUnverifiedRejected(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, nil)
	tok := idp.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://mcp.example/",
		"email":          "x@example.com",
		"email_verified": false,
	})
	_, err := v.Validate(tok)
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_AllowedDomain(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, func(c *Config) {
		c.AllowedEmailDomains = []string{"allowed.com"}
	})
	tok := idp.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://mcp.example/",
		"email":          "x@other.com",
		"email_verified": true,
	})
	if _, err := v.Validate(tok); !errors.Is(err, ErrUnauthorizedDomain) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_InsufficientScopes(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	v := newTestValidator(t, idp, func(c *Config) {
		c.RequiredScopes = []string{"mcp:read"}
	})
	tok := idp.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://mcp.example/",
		"email": "x@example.com", "email_verified": true,
		"scope": "openid email",
	})
	_, err := v.Validate(tok)
	if !errors.Is(err, ErrInsufficientScopes) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_UpstreamIssuerAllowlist(t *testing.T) {
	idpA := oauthtest.New(t)
	defer idpA.Close()
	idpB := oauthtest.New(t)
	defer idpB.Close()
	// Validator trusts only IDP-A's JWKS, but the allowlist includes IDP-B's
	// issuer. A token signed by A with iss=B → signature OK, issuer rejected.
	cfg := Config{
		Mode:                    ModeGating,
		Issuer:                  idpA.Issuer,
		JWKSURL:                 idpA.Issuer + "/jwks.json",
		Audience:                "https://mcp.example/",
		UpstreamIssuerAllowlist: []string{idpB.Issuer},
	}
	v := newValidator(cfg)
	tok := idpA.MintIDToken(t, map[string]any{
		"sub": "x", "aud": "https://mcp.example/",
		"iss":            idpA.Issuer, // not in allowlist
		"email":          "x@example.com",
		"email_verified": true,
	})
	if _, err := v.Validate(tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err=%v", err)
	}
}

func TestValidator_NoIssuerOrJWKSConfigured_SoftPassesJWTs(t *testing.T) {
	cfg := Config{Mode: ModeForward}
	if err := cfg.Validate(); err != nil {
		// Forward mode without issuer/jwks should fail Validate.
	}
	// Bypass Validate to test the soft-pass branch directly.
	v := newValidator(Config{Mode: ModeForward})
	claims, err := v.Validate("a.b.c")
	if err != nil {
		t.Errorf("err=%v", err)
	}
	if claims != nil {
		t.Errorf("expected nil claims on soft-pass")
	}
}
