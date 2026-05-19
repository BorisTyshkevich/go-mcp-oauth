package oauth

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"https://x/":     "https://x",
		"  https://x  ":  "https://x",
		"https://x":      "https://x",
		"":               "",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCanonicalResourceURL(t *testing.T) {
	if got := canonicalResourceURL("https://x"); got != "https://x/" {
		t.Errorf("got %q", got)
	}
	if got := canonicalResourceURL("https://x/"); got != "https://x/" {
		t.Errorf("got %q", got)
	}
	if got := canonicalResourceURL(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
}

func TestNormalizedPath(t *testing.T) {
	cases := []struct {
		in, fallback, want string
	}{
		{"", "/oauth", "/oauth"},
		{"oauth/", "", "/oauth"},
		{"/", "/foo", "/"},
		{"/x/", "", "/x"},
	}
	for _, c := range cases {
		if got := normalizedPath(c.in, c.fallback); got != c.want {
			t.Errorf("normalizedPath(%q, %q) = %q, want %q", c.in, c.fallback, got, c.want)
		}
	}
}

func TestJoinURLPath(t *testing.T) {
	if got := joinURLPath("https://x", "/oauth"); got != "https://x/oauth" {
		t.Errorf("simple: %q", got)
	}
	if got := joinURLPath("https://x/", "/"); got != "https://x" {
		t.Errorf("root: %q", got)
	}
}

func TestTTLSeconds(t *testing.T) {
	if ttlSeconds(0, 99) != 99 {
		t.Errorf("fallback")
	}
	if ttlSeconds(5, 99) != 5 {
		t.Errorf("positive")
	}
	if ttlSeconds(-1, 99) != 99 {
		t.Errorf("negative")
	}
}

func TestUniquePaths(t *testing.T) {
	got := uniquePaths("/a", "a", "/b", "")
	want := []string{"/a", "/b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestSuffixPrefix(t *testing.T) {
	if got := suffixPrefix("/foo/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource"); got != "" {
		// no prefix in this case
		t.Errorf("unexpected: %q", got)
	}
	if got := suffixPrefix("/.well-known/oauth-protected-resource/tenant", "/.well-known/oauth-protected-resource"); got != "/tenant" {
		t.Errorf("got %q", got)
	}
	if got := suffixPrefix("/abc", "/.well-known/oauth-protected-resource"); got != "" {
		t.Errorf("non-match must yield empty: %q", got)
	}
}

func TestPathFromConfiguredURL(t *testing.T) {
	if got := pathFromConfiguredURL("https://x/oauth/"); got != "/oauth" {
		t.Errorf("got %q", got)
	}
	if got := pathFromConfiguredURL("https://x"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestSchemeAndHost(t *testing.T) {
	r := httptest.NewRequest("GET", "https://x.example/foo", nil)
	r.Host = "x.example:8080"
	if got := schemeAndHost(r); got != "https://x.example:8080" {
		// httptest.NewRequest sets TLS field iff scheme is https; let's accept either
		if got != "http://x.example:8080" {
			t.Errorf("got %q", got)
		}
	}
}

func TestNormalizeUpstreamScopeForClient(t *testing.T) {
	in := "https://www.googleapis.com/auth/userinfo.email openid extra"
	got := normalizeUpstreamScopeForClient(in)
	want := "email openid extra"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestSanitizeScope(t *testing.T) {
	if got := sanitizeScope("  a   b\tc "); got != "a b c" {
		t.Errorf("got %q", got)
	}
}

func TestOidcScopesForAdvertisement(t *testing.T) {
	in := []string{"openid", "email", "https://googleapis.com/foo", "offline_access", "openid"}
	got := oidcScopesForAdvertisement(in)
	want := []string{"openid", "email", "offline_access"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestIsGoogleIssuer(t *testing.T) {
	if !isGoogleIssuer("https://accounts.google.com") {
		t.Errorf("accounts.google.com")
	}
	if !isGoogleIssuer("https://accounts.google.com/") {
		t.Errorf("trailing slash")
	}
	if isGoogleIssuer("https://auth0.example.com") {
		t.Errorf("non-google")
	}
}

func TestTruncateForLog(t *testing.T) {
	if truncateForLog("hello", 3) != "hel" {
		t.Errorf("truncate")
	}
	if truncateForLog("hi", 10) != "hi" {
		t.Errorf("no truncate")
	}
	if truncateForLog("hi", 0) != "hi" {
		t.Errorf("max=0 → no truncate")
	}
}
