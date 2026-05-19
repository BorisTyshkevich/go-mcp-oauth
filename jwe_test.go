package oauth

import (
	"crypto/rand"
	"testing"
	"time"
)

func randomSecret(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestEncodeDecodeJWE_RoundTrip(t *testing.T) {
	secret := randomSecret(t, 32)
	claims := map[string]any{
		"client_id":    "alice",
		"redirect_uri": "https://a.example/cb",
		"exp":          time.Now().Add(time.Minute).Unix(),
	}
	token, err := encodeJWE(secret, hkdfInfoPendingAuth, claims)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeJWE(secret, hkdfInfoPendingAuth, token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["client_id"] != "alice" {
		t.Errorf("client_id: %v", got["client_id"])
	}
}

func TestDecodeJWE_WrongInfoFails(t *testing.T) {
	secret := randomSecret(t, 32)
	claims := map[string]any{
		"client_id": "alice",
		"exp":       time.Now().Add(time.Minute).Unix(),
	}
	token, err := encodeJWE(secret, hkdfInfoPendingAuth, claims)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decodeJWE(secret, hkdfInfoAuthCode, token); err == nil {
		t.Errorf("expected info-label isolation to fail decryption")
	}
}

func TestDecodeJWE_WrongSecretFails(t *testing.T) {
	a, b := randomSecret(t, 32), randomSecret(t, 32)
	token, _ := encodeJWE(a, hkdfInfoPendingAuth, map[string]any{"client_id": "x", "exp": time.Now().Add(time.Minute).Unix()})
	if _, err := decodeJWE(b, hkdfInfoPendingAuth, token); err == nil {
		t.Errorf("expected secret mismatch to fail")
	}
}

func TestDecodeJWE_ExpiredFails(t *testing.T) {
	secret := randomSecret(t, 32)
	token, _ := encodeJWE(secret, hkdfInfoPendingAuth, map[string]any{"client_id": "x", "exp": time.Now().Add(-time.Minute).Unix()})
	if _, err := decodeJWE(secret, hkdfInfoPendingAuth, token); err == nil {
		t.Errorf("expected expired token to fail")
	}
}

func TestDecodeJWE_DisallowedClaimFails(t *testing.T) {
	secret := randomSecret(t, 32)
	token, _ := encodeJWE(secret, hkdfInfoPendingAuth, map[string]any{"client_id": "x", "evil": "bad", "exp": time.Now().Add(time.Minute).Unix()})
	if _, err := decodeJWE(secret, hkdfInfoPendingAuth, token); err == nil {
		t.Errorf("expected unknown-claim rejection")
	}
}

func TestDeriveKey_DifferentInfoIndependent(t *testing.T) {
	secret := randomSecret(t, 32)
	k1 := deriveKey(secret, "label-a")
	k2 := deriveKey(secret, "label-b")
	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("len: %d %d", len(k1), len(k2))
	}
	same := true
	for i := range k1 {
		if k1[i] != k2[i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("different info labels produced identical keys")
	}
}

func TestDecodeJWE_BadTokenFails(t *testing.T) {
	secret := randomSecret(t, 32)
	if _, err := decodeJWE(secret, hkdfInfoPendingAuth, "not-a-jwe"); err == nil {
		t.Errorf("expected error on garbage")
	}
}
