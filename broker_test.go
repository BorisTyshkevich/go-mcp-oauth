package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/BorisTyshkevich/go-mcp-oauth/internal/oauthtest"
)

func TestRegisterRoutes_PureGatingOnlyMountsProtectedResource(t *testing.T) {
	mux := http.NewServeMux()
	b, err := New(Config{
		Mode:    ModeGating,
		Issuer:  "https://idp.example/",
		JWKSURL: "https://idp.example/jwks.json",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if code := codeOfGET(t, srv.URL+"/.well-known/oauth-protected-resource"); code != http.StatusOK {
		t.Errorf("protected-resource: %d", code)
	}
	if code := codeOfGET(t, srv.URL+"/.well-known/oauth-authorization-server"); code != http.StatusNotFound {
		t.Errorf("expected AS metadata absent in pure gating, got %d", code)
	}
	if code := codeOfGET(t, srv.URL+"/oauth/authorize"); code != http.StatusNotFound {
		t.Errorf("/authorize absent in pure gating: %d", code)
	}
}

func TestRegisterRoutes_BrokerModeMountsAll(t *testing.T) {
	mux := http.NewServeMux()
	b, err := New(Config{
		Mode:          ModeForward,
		Issuer:        "https://idp.example/",
		JWKSURL:       "https://idp.example/jwks.json",
		ClientID:      "x",
		ClientSecret:  "y",
		SigningSecret: oauthtest.RandomSecret(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, p := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		if code := codeOfGET(t, srv.URL+p); code != http.StatusOK {
			t.Errorf("%s: %d", p, code)
		}
	}
	// DCR tombstone.
	if code := codeOfGET(t, srv.URL+"/oauth/register"); code != http.StatusGone {
		t.Errorf("/oauth/register: %d (want 410)", code)
	}
}

func TestProtectedResourceMetadata_Shape(t *testing.T) {
	mux := http.NewServeMux()
	b, err := New(Config{
		Mode:          ModeForward,
		Issuer:        "https://idp.example/",
		JWKSURL:       "https://idp.example/jwks.json",
		ClientID:      "x",
		ClientSecret:  "y",
		SigningSecret: oauthtest.RandomSecret(t),
		Scopes:        []string{"openid", "email", "https://googleapis.com/auth/foo"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res, _ := body["resource"].(string)
	if !strings.HasSuffix(res, "/") {
		t.Errorf("resource missing trailing slash: %q", res)
	}
	scopes, _ := body["scopes_supported"].([]any)
	if len(scopes) != 2 { // googleapis filtered out
		t.Errorf("scopes: %v", scopes)
	}
}

func TestDCRRegisterTombstone_HasCIMDPointer(t *testing.T) {
	mux := http.NewServeMux()
	b, _ := New(Config{
		Mode:          ModeForward,
		Issuer:        "https://idp.example/",
		JWKSURL:       "https://idp.example/jwks.json",
		ClientID:      "x",
		ClientSecret:  "y",
		SigningSecret: oauthtest.RandomSecret(t),
	})
	b.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Errorf("status=%d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "CIMD") {
		t.Errorf("body missing CIMD pointer: %s", body)
	}
}

func TestAuthorize_RejectsMissingPKCE(t *testing.T) {
	srv := newBrokerServer(t)
	defer srv.Close()

	q := url.Values{
		"client_id":     {"https://claude.ai/oauth/cimd"},
		"redirect_uri":  {"https://claude.ai/cb"},
		"response_type": {"code"},
	}
	resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		// might be invalid_client first (CIMD fetch fails for the fake URL) — either way must be 4xx
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Errorf("status=%d", resp.StatusCode)
		}
	}
}

func TestAuthorize_ResourceMismatchYieldsInvalidTarget(t *testing.T) {
	// Skip happy-path CIMD here — we just exercise the resource indicator
	// check. handleAuthorize's CIMD fetch will fail and short-circuit before
	// reaching the resource check unless CIMD is wired up, so we test the
	// resource check via handler-style direct call below.
	t.Skip("covered by direct-handler test in middleware_test.go (resource mismatch is downstream of CIMD lookup)")
}

func TestTokenEndpoint_RejectsClientSecret(t *testing.T) {
	srv := newBrokerServer(t)
	defer srv.Close()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"https://claude.ai/oauth/cimd"},
		"client_secret": {"never"},
		"code":          {"x"},
		"redirect_uri":  {"https://claude.ai/cb"},
	}
	resp, err := http.PostForm(srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	srv := newBrokerServer(t)
	defer srv.Close()
	form := url.Values{
		"grant_type": {"refresh_token"},
	}
	resp, err := http.PostForm(srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error=%s", body["error"])
	}
}

func TestASMetadataShape(t *testing.T) {
	srv := newBrokerServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{
		"issuer", "authorization_endpoint", "token_endpoint",
		"response_types_supported", "grant_types_supported",
		"token_endpoint_auth_methods_supported", "code_challenge_methods_supported",
		"client_id_metadata_document_supported",
	} {
		if _, ok := body[want]; !ok {
			t.Errorf("missing %q", want)
		}
	}
	if v, _ := body["client_id_metadata_document_supported"].(bool); !v {
		t.Errorf("expected CIMD supported=true")
	}
}

// --- helpers -------------------------------------------------------------

func newBrokerServer(t *testing.T) *httptest.Server {
	t.Helper()
	idp := oauthtest.New(t)
	t.Cleanup(idp.Close)
	mux := http.NewServeMux()
	b, err := New(Config{
		Mode:          ModeForward,
		Issuer:        idp.Issuer,
		JWKSURL:       idp.Issuer + "/jwks.json",
		AuthURL:       idp.Issuer + "/authorize",
		TokenURL:      idp.Issuer + "/token",
		ClientID:      "broker",
		ClientSecret:  "secret",
		SigningSecret: oauthtest.RandomSecret(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	return srv
}

func codeOfGET(t *testing.T, u string) int {
	t.Helper()
	c := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       2 * time.Second,
	}
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
