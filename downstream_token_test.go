package oauth

import (
	"testing"
	"time"
)

func timeNowAddOneHour() time.Time { return time.Now().Add(time.Hour) }

func TestDownstreamToken_RoundTrip(t *testing.T) {
	secret := randomSecret(t, 32)
	upstream := "a.b.c" // any opaque payload — the JWE wrapper doesn't peek inside
	token, err := encodeDownstreamAccessToken(secret, upstream, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeDownstreamAccessToken(secret, token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != upstream {
		t.Errorf("got %q want %q", got, upstream)
	}
}

func TestDownstreamToken_Expired(t *testing.T) {
	secret := randomSecret(t, 32)
	token, _ := encodeDownstreamAccessToken(secret, "x", time.Now().Add(-time.Minute))
	if _, err := decodeDownstreamAccessToken(secret, token); err == nil {
		t.Errorf("expected expiry to fail")
	}
}

func TestDownstreamToken_WrongSecret(t *testing.T) {
	a, b := randomSecret(t, 32), randomSecret(t, 32)
	token, _ := encodeDownstreamAccessToken(a, "x", time.Now().Add(time.Minute))
	if _, err := decodeDownstreamAccessToken(b, token); err == nil {
		t.Errorf("expected secret mismatch to fail")
	}
}
