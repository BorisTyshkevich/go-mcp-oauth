package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// RFC 7523 §2.2 + RFC 7521 §4.2 client authentication for CIMD clients that
// publish token_endpoint_auth_method=private_key_jwt. The client posts:
//
//   client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//   client_assertion=<JWT signed with the client's private key>
//
// The broker resolves the client's CIMD doc, fetches its published JWKS,
// verifies the JWT signature, and validates the registered claims: iss == sub
// == client_id, aud = our /oauth/token URL, exp/nbf/iat inside their windows.

const (
	clientAssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionMaxLifetime = 10 * time.Minute
	clientAssertionClockSkew   = 60 * time.Second
	jwksMaxBodyBytes           = 64 * 1024
)

var (
	errClientAssertionInvalid = errors.New("client_assertion invalid")
	errJWKSFetch              = errors.New("jwks fetch failed")
)

type cimdJWKSCacheEntry struct {
	keys      *jose.JSONWebKeySet
	err       error
	expiresAt time.Time
}

type cimdJWKSCache struct {
	mu       sync.Mutex
	entries  map[string]*cimdJWKSCacheEntry
	order    []string
	capacity int
}

func newCIMDJWKSCache(capacity int) *cimdJWKSCache {
	if capacity <= 0 {
		capacity = 1
	}
	return &cimdJWKSCache{entries: make(map[string]*cimdJWKSCacheEntry, capacity), capacity: capacity}
}

func (c *cimdJWKSCache) get(key string, now time.Time) (*cimdJWKSCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.After(e.expiresAt) {
		delete(c.entries, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		return nil, false
	}
	return e, true
}

func (c *cimdJWKSCache) put(key string, e *cimdJWKSCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		if len(c.entries) >= c.capacity {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = e
}

func (c *cimdJWKSCache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok {
		return
	}
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

func (r *cimdResolver) fetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	if e, ok := r.jwksCache.get(jwksURI, r.now()); ok {
		if e.err != nil {
			return nil, e.err
		}
		return e.keys, nil
	}
	keys, ttl, err := r.fetchJWKSUncached(ctx, jwksURI)
	now := r.now()
	if err != nil {
		// JWKS fetch failures are not negative-cached.
		return nil, err
	}
	if ttl > 0 {
		r.jwksCache.put(jwksURI, &cimdJWKSCacheEntry{keys: keys, expiresAt: now.Add(ttl)})
	}
	return keys, nil
}

func (r *cimdResolver) fetchJWKSUncached(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cimdFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: build request: %v", errJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", errJWKSFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 {
		return nil, 0, fmt.Errorf("%w: unexpected redirect %d", errJWKSFetch, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: HTTP %d", errJWKSFetch, resp.StatusCode)
	}
	if !isApplicationJSON(resp.Header.Get("Content-Type")) {
		return nil, 0, fmt.Errorf("%w: content-type %q not application/json", errJWKSFetch, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(jwksMaxBodyBytes+1)))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: body read: %v", errJWKSFetch, err)
	}
	if len(body) > jwksMaxBodyBytes {
		return nil, 0, fmt.Errorf("%w: body exceeds %d bytes", errJWKSFetch, jwksMaxBodyBytes)
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, 0, fmt.Errorf("%w: decode: %v", errJWKSFetch, err)
	}
	if len(keys.Keys) == 0 {
		return nil, 0, fmt.Errorf("%w: empty key set", errJWKSFetch)
	}
	return &keys, cacheTTLFromHeader(resp.Header.Get("Cache-Control")), nil
}

var clientAssertionAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// verifyClientAssertion implements RFC 7523 §3 validation for a CIMD client
// whose metadata declared token_endpoint_auth_method=private_key_jwt.
func (r *cimdResolver) verifyClientAssertion(ctx context.Context, client *registeredClient, clientID, assertion, expectedAud string) error {
	if client.JWKSURI == "" {
		return fmt.Errorf("%w: client did not publish jwks_uri", errClientAssertionInvalid)
	}
	if assertion == "" {
		return fmt.Errorf("%w: missing client_assertion", errClientAssertionInvalid)
	}
	parsed, err := jwt.ParseSigned(assertion, clientAssertionAlgs)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", errClientAssertionInvalid, err)
	}
	if len(parsed.Headers) != 1 {
		return fmt.Errorf("%w: expected exactly one JWS signature", errClientAssertionInvalid)
	}
	hdr := parsed.Headers[0]

	keys, err := r.fetchJWKS(ctx, client.JWKSURI)
	if err != nil {
		return fmt.Errorf("%w: jwks unavailable: %v", errClientAssertionInvalid, err)
	}
	jwk := selectJWK(keys, hdr.KeyID, hdr.Algorithm)
	if jwk == nil {
		r.jwksCache.invalidate(client.JWKSURI)
		keys, err = r.fetchJWKS(ctx, client.JWKSURI)
		if err != nil {
			return fmt.Errorf("%w: jwks unavailable: %v", errClientAssertionInvalid, err)
		}
		jwk = selectJWK(keys, hdr.KeyID, hdr.Algorithm)
		if jwk == nil {
			return fmt.Errorf("%w: no matching key for kid=%q alg=%q", errClientAssertionInvalid, hdr.KeyID, hdr.Algorithm)
		}
	}

	var claims jwt.Claims
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return fmt.Errorf("%w: signature: %v", errClientAssertionInvalid, err)
	}

	if claims.Issuer != clientID {
		return fmt.Errorf("%w: iss %q != client_id", errClientAssertionInvalid, claims.Issuer)
	}
	if claims.Subject != clientID {
		return fmt.Errorf("%w: sub %q != client_id", errClientAssertionInvalid, claims.Subject)
	}
	now := r.now()
	if err := claims.ValidateWithLeeway(jwt.Expected{Time: now}, clientAssertionClockSkew); err != nil {
		return fmt.Errorf("%w: time claims: %v", errClientAssertionInvalid, err)
	}
	if !audienceMatches(claims.Audience, expectedAud) {
		return fmt.Errorf("%w: aud %v does not match token endpoint %q", errClientAssertionInvalid, []string(claims.Audience), expectedAud)
	}
	if claims.IssuedAt != nil && claims.Expiry != nil {
		if claims.Expiry.Time().Sub(claims.IssuedAt.Time()) > clientAssertionMaxLifetime {
			return fmt.Errorf("%w: exp - iat > %s", errClientAssertionInvalid, clientAssertionMaxLifetime)
		}
	}
	return nil
}

func selectJWK(set *jose.JSONWebKeySet, kid, alg string) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	if kid != "" {
		for i := range set.Keys {
			if set.Keys[i].KeyID == kid && isSigKey(&set.Keys[i]) {
				return &set.Keys[i]
			}
		}
		return nil
	}
	for i := range set.Keys {
		if !isSigKey(&set.Keys[i]) {
			continue
		}
		if set.Keys[i].Algorithm == alg || set.Keys[i].Algorithm == "" {
			return &set.Keys[i]
		}
	}
	return nil
}

func isSigKey(k *jose.JSONWebKey) bool {
	return k.Use == "" || k.Use == "sig"
}

func audienceMatches(aud jwt.Audience, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}
