package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// brokerIDTokenRefreshThresholdSeconds is the remaining-life floor below
// which we'll use the upstream refresh_token at /token to mint a fresh
// id_token before forwarding. Set at 55 minutes so a freshly-minted Google
// id_token (exp = iat + 1h) is never re-fetched but anything Google reused
// from a warm session is.
const brokerIDTokenRefreshThresholdSeconds = 55 * 60

// refreshUpstreamIDToken exchanges the upstream refresh_token for a fresh
// id_token via the upstream's RFC 6749 §6 refresh-token grant. Used at
// /token when the just-redeemed id_token has a short remaining life.
// Returns the fresh id_token + parsed identity claims. On any failure the
// caller should fall back to the original near-expired id_token rather than
// fail the whole /token call.
func (b *Broker) refreshUpstreamIDToken(refreshToken string) (string, *Claims, error) {
	tokenURL, err := b.resolveUpstreamTokenURL()
	if err != nil {
		return "", nil, fmt.Errorf("resolve token url: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", b.cfg.ClientID)
	if b.cfg.ClientSecret != "" {
		form.Set("client_secret", b.cfg.ClientSecret)
	}
	resp, err := b.cfg.httpClient().PostForm(tokenURL, form)
	if err != nil {
		return "", nil, fmt.Errorf("post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes))
	if err != nil {
		return "", nil, fmt.Errorf("body: %w", err)
	}
	if resp.StatusCode >= 300 {
		errCode, errDesc := refreshErrorFields(body)
		return "", nil, fmt.Errorf("upstream %d: %s%s", resp.StatusCode, errCode, errDesc)
	}
	var parsed struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", nil, fmt.Errorf("decode: %w", err)
	}
	if parsed.Error != "" {
		return "", nil, fmt.Errorf("upstream %s%s", parsed.Error, sanitizeErrorDesc(parsed.ErrorDescription))
	}
	if parsed.IDToken == "" {
		return "", nil, fmt.Errorf("upstream returned no id_token")
	}
	claims, err := b.validator.ValidateUpstreamIdentityToken(parsed.IDToken, b.cfg.ClientID)
	if err != nil {
		return "", nil, fmt.Errorf("validate: %w", err)
	}
	return parsed.IDToken, claims, nil
}

// safeUpstreamErrorFields extracts the RFC 6749 §5.2 `error` code from an
// upstream OAuth error response body and the body length. Used in lieu of
// logging the body verbatim.
func safeUpstreamErrorFields(body []byte) (errCode string, length int) {
	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Error, len(body)
}

// refreshErrorFields surfaces error + sanitised error_description for the
// refresh-token grant. Google's refresh failures are diagnostically richer in
// error_description ("Token has been expired or revoked") than the bare error
// enum ("invalid_grant").
func refreshErrorFields(body []byte) (errCode, errDesc string) {
	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Error, sanitizeErrorDesc(parsed.ErrorDescription)
}

// sanitizeErrorDesc bounds an OAuth error_description for inclusion in our
// own error messages and logs: strips newlines + control chars, caps at 120
// bytes, returns a leading ": " separator if non-empty.
func sanitizeErrorDesc(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 120 {
		s = s[:120]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' {
			out = append(out, ' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
	}
	return ": " + string(out)
}

// maybeRefreshNearExpiredIDToken returns a fresh id_token when the supplied
// one is close to expiry and a refresh_token is available. On any refresh
// failure it returns the original (idToken, claims, nil) so callers don't
// fail the surrounding /token request.
func (b *Broker) maybeRefreshNearExpiredIDToken(idToken, refreshToken string, claims *Claims) (string, *Claims, time.Duration) {
	if refreshToken == "" || claims == nil || claims.ExpiresAt <= 0 {
		return idToken, claims, 0
	}
	remaining := claims.ExpiresAt - time.Now().Unix()
	if remaining >= int64(brokerIDTokenRefreshThresholdSeconds) {
		return idToken, claims, 0
	}
	fresh, freshClaims, err := b.refreshUpstreamIDToken(refreshToken)
	if err != nil {
		b.cfg.logger().Warn("oauth: id_token refresh failed; forwarding original near-expired token",
			"err", err,
			"remaining_seconds", remaining)
		return idToken, claims, 0
	}
	b.cfg.logger().Info("oauth: refreshed near-expired id_token via upstream refresh_token grant",
		"old_remaining_seconds", remaining,
		"new_remaining_seconds", freshClaims.ExpiresAt-time.Now().Unix())
	return fresh, freshClaims, time.Duration(freshClaims.ExpiresAt-time.Now().Unix()) * time.Second
}
