package oauth

import (
	"reflect"
	"sort"
	"testing"
)

func TestClaimsFromRaw_Basic(t *testing.T) {
	raw := map[string]any{
		"sub":            "alice",
		"iss":            "https://idp.example/",
		"aud":            "https://mcp.example/",
		"exp":            float64(2_000_000_000),
		"iat":            float64(1_000_000_000),
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
		"hd":             "example.com",
		"scope":          "openid email custom",
		"extra_field":    "kept",
	}
	c := claimsFromRaw(raw)
	if c.Subject != "alice" || c.Issuer != "https://idp.example/" {
		t.Fatalf("sub/iss: %+v", c)
	}
	if c.ExpiresAt != 2_000_000_000 || c.IssuedAt != 1_000_000_000 {
		t.Fatalf("exp/iat: %+v", c)
	}
	if c.Email != "alice@example.com" || !c.EmailVerified {
		t.Fatalf("email: %+v", c)
	}
	want := []string{"openid", "email", "custom"}
	if !reflect.DeepEqual(c.Scopes, want) {
		t.Fatalf("scopes: %v vs %v", c.Scopes, want)
	}
	if got, ok := c.Extra["extra_field"].(string); !ok || got != "kept" {
		t.Fatalf("extra: %v", c.Extra)
	}
	if _, dup := c.Extra["email"]; dup {
		t.Fatalf("Extra must not contain whitelisted claim 'email': %v", c.Extra)
	}
}

func TestClaimsFromRaw_AudienceShapes(t *testing.T) {
	asList := claimsFromRaw(map[string]any{"aud": []any{"a", "b"}})
	if !reflect.DeepEqual(asList.Audience, []string{"a", "b"}) {
		t.Errorf("list aud: %v", asList.Audience)
	}
	asString := claimsFromRaw(map[string]any{"aud": "a"})
	if !reflect.DeepEqual(asString.Audience, []string{"a"}) {
		t.Errorf("string aud: %v", asString.Audience)
	}
}

func TestEmailDomain(t *testing.T) {
	cases := map[string]string{
		"alice@example.com": "example.com",
		"  ALICE@EXAMPLE.COM": "example.com",
		"":                  "",
		"noatsign":          "",
		"a@b@c":             "",
	}
	for in, want := range cases {
		if got := emailDomain(in); got != want {
			t.Errorf("emailDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContainsDomain(t *testing.T) {
	domains := []string{"example.com", "  altinity.com  "}
	if !containsDomain(domains, "EXAMPLE.com") {
		t.Errorf("case-insensitive match failed")
	}
	if !containsDomain(domains, "altinity.com") {
		t.Errorf("trim match failed")
	}
	if containsDomain(domains, "other.com") {
		t.Errorf("false positive")
	}
}

func TestAudienceMatchesResource(t *testing.T) {
	if !audienceMatchesResource([]string{"https://mcp.example/"}, "https://mcp.example") {
		t.Errorf("trailing-slash tolerance")
	}
	if !audienceMatchesResource([]string{"https://mcp.example"}, "https://mcp.example/") {
		t.Errorf("trailing-slash tolerance (rev)")
	}
	if audienceMatchesResource([]string{"https://other.example"}, "https://mcp.example") {
		t.Errorf("false positive")
	}
}

func TestIssuerAllowed(t *testing.T) {
	allowlist := []string{"https://idp1/", "https://idp2"}
	if !issuerAllowed("https://idp1", allowlist, "") {
		t.Errorf("allowlist match")
	}
	if !issuerAllowed("https://idp2/", allowlist, "") {
		t.Errorf("allowlist match")
	}
	if issuerAllowed("https://idp3", allowlist, "") {
		t.Errorf("allowlist non-match accepted")
	}
	if !issuerAllowed("https://idp1", nil, "https://idp1") {
		t.Errorf("single-issuer match")
	}
	if !issuerAllowed("https://idp1", nil, "") {
		t.Errorf("no policy → accept")
	}
}

func TestLooksLikeJWT(t *testing.T) {
	if !looksLikeJWT("a.b.c") {
		t.Errorf("3-segment must look like JWT")
	}
	if looksLikeJWT("opaque-token") {
		t.Errorf("opaque must not look like JWT")
	}
	if looksLikeJWT("a.b.c.d") {
		t.Errorf("4-segment must not look like JWT")
	}
}

func TestHasRequiredScopes(t *testing.T) {
	if !hasRequiredScopes([]string{"a", "b"}, []string{"a"}) {
		t.Errorf("subset must pass")
	}
	if hasRequiredScopes([]string{"a"}, []string{"a", "b"}) {
		t.Errorf("missing must fail")
	}
	if !hasRequiredScopes([]string{"a"}, nil) {
		t.Errorf("empty required = no check")
	}
}

func TestClaimsFromUserInfo(t *testing.T) {
	raw := map[string]any{
		"sub":   "alice",
		"email": "alice@example.com",
		"name":  "Alice",
		"x-other": "kept",
	}
	c := claimsFromUserInfo(raw)
	if c.Subject != "alice" {
		t.Errorf("sub: %s", c.Subject)
	}
	if v, ok := c.Extra["x-other"].(string); !ok || v != "kept" {
		t.Errorf("extra: %v", c.Extra)
	}
}

// guard against accidental imports being dropped
var _ = sort.Strings
