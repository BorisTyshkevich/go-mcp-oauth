package oauth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPKCEChallenge_DeterministicS256(t *testing.T) {
	verifier := "abc"
	c1 := pkceChallenge(verifier)
	c2 := pkceChallenge(verifier)
	if c1 != c2 {
		t.Errorf("non-deterministic")
	}
	if _, err := base64.RawURLEncoding.DecodeString(c1); err != nil {
		t.Errorf("not base64url: %v", err)
	}
}

func TestNewPKCEVerifier_Length(t *testing.T) {
	v, err := newPKCEVerifier()
	if err != nil {
		t.Fatalf("newPKCEVerifier: %v", err)
	}
	// 32 bytes → 43 base64url chars (no padding).
	if len(v) != 43 {
		t.Errorf("len=%d", len(v))
	}
}

func TestSafeUpstreamErrorFields(t *testing.T) {
	code, n := safeUpstreamErrorFields([]byte(`{"error":"invalid_grant","error_description":"x"}`))
	if code != "invalid_grant" {
		t.Errorf("code=%q", code)
	}
	if n == 0 {
		t.Errorf("length")
	}
	// malformed body still returns length, code blank
	code, n = safeUpstreamErrorFields([]byte("not-json"))
	if code != "" || n != len("not-json") {
		t.Errorf("malformed: code=%q len=%d", code, n)
	}
}

func TestSanitizeErrorDesc(t *testing.T) {
	got := sanitizeErrorDesc("Token has been\nexpired\tor revoked")
	if !strings.HasPrefix(got, ": ") {
		t.Errorf("prefix: %q", got)
	}
	if strings.Contains(got, "\n") || strings.Contains(got, "\t") {
		t.Errorf("control chars not stripped: %q", got)
	}
	if got := sanitizeErrorDesc(""); got != "" {
		t.Errorf("empty: %q", got)
	}
	// >120 byte input is truncated.
	long := strings.Repeat("a", 200)
	out := sanitizeErrorDesc(long)
	if len(out) > 2+120 { // ": " + 120 max
		t.Errorf("oversize not truncated: %d", len(out))
	}
}

func TestRefreshErrorFields(t *testing.T) {
	code, desc := refreshErrorFields([]byte(`{"error":"invalid_grant","error_description":"expired"}`))
	if code != "invalid_grant" {
		t.Errorf("code=%q", code)
	}
	if !strings.Contains(desc, "expired") {
		t.Errorf("desc=%q", desc)
	}
}
