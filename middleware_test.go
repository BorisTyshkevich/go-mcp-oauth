package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BorisTyshkevich/go-mcp-oauth/internal/oauthtest"
)

func newTestBroker(t *testing.T, idp *oauthtest.MockIDP, modify func(*Config)) *Broker {
	t.Helper()
	cfg := Config{
		Mode:          ModeGating,
		Issuer:        idp.Issuer,
		JWKSURL:       idp.Issuer + "/jwks.json",
		Audience:      "https://mcp.example/",
		SigningSecret: oauthtest.RandomSecret(t),
	}
	if modify != nil {
		modify(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestMiddleware_MissingToken_401WithChallenge(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	b := newTestBroker(t, idp, nil)

	handler := b.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("inner handler must not be invoked")
	}))

	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status=%d", rr.Code)
	}
	chal := rr.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(chal, "Bearer ") {
		t.Errorf("challenge=%q", chal)
	}
	if !strings.Contains(chal, "resource_metadata=") {
		t.Errorf("missing resource_metadata: %q", chal)
	}
	if !strings.Contains(chal, "error=") {
		t.Errorf("missing error=: %q", chal)
	}
}

func TestMiddleware_ValidToken_ContextPopulated(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	b := newTestBroker(t, idp, func(c *Config) {
		c.Mode = ModeForward
		c.ClientID = "broker-client"
	})

	tok := idp.MintIDToken(t, map[string]any{
		"sub": "alice", "aud": "https://mcp.example/",
		"email": "alice@example.com", "email_verified": true,
	})

	var sawSubject string
	var sawRaw string
	handler := b.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Errorf("claims missing")
			return
		}
		sawSubject = c.Subject
		raw, _ := RawTokenFromContext(r.Context())
		sawRaw = raw
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sawSubject != "alice" {
		t.Errorf("subject=%q", sawSubject)
	}
	if sawRaw != tok {
		t.Errorf("raw token not propagated")
	}
}

func TestExtractBearer(t *testing.T) {
	cases := map[string]string{
		"Bearer abc": "abc",
		"bearer xyz": "xyz",
		"":           "",
		"Basic abc":  "",
	}
	for in, want := range cases {
		r, _ := http.NewRequest("GET", "/", nil)
		if in != "" {
			r.Header.Set("Authorization", in)
		}
		if got := extractBearer(r); got != want {
			t.Errorf("extract(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMiddleware_GatingMode_DownstreamJWE(t *testing.T) {
	idp := oauthtest.New(t)
	defer idp.Close()
	b := newTestBroker(t, idp, nil) // gating mode

	upstreamTok := idp.MintIDToken(t, map[string]any{
		"sub": "alice", "aud": "https://mcp.example/",
		"email": "alice@example.com", "email_verified": true,
	})
	// Wrap as a downstream token.
	wrapped, err := encodeDownstreamAccessToken(b.cfg.SigningSecret, upstreamTok, timeNowAddOneHour())
	if err != nil {
		t.Fatalf("encode downstream: %v", err)
	}

	var sawSubject string
	handler := b.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if ok {
			sawSubject = c.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+wrapped)
	handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sawSubject != "alice" {
		t.Errorf("expected gating-mode JWE to unwrap into upstream claims, got subject=%q", sawSubject)
	}
}
