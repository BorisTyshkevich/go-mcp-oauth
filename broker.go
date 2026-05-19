package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	maxOAuthResponseBytes = 1 << 20

	defaultProtectedResourceMetadataPath   = "/.well-known/oauth-protected-resource"
	defaultAuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	defaultOpenIDConfigurationPath         = "/.well-known/openid-configuration"
	defaultRegistrationPath                = "/oauth/register"
	defaultAuthorizationPath               = "/oauth/authorize"
	defaultCallbackPath                    = "/oauth/callback"
	defaultTokenPath                       = "/oauth/token"
	defaultPendingAuthTTLSeconds           = 10 * 60
	defaultAuthCodeTTLSeconds              = 60
	defaultAccessTokenTTLSeconds           = 60 * 60
)

// Broker is the library's stateful surface. Constructed once per process via
// New; safe for concurrent use. Exposes a Validator for stdio paths and an
// HTTP handler tree via RegisterRoutes / Middleware.
type Broker struct {
	cfg          Config
	validator    *Validator
	cimdResolver *cimdResolver
}

// New constructs a Broker. Returns an error iff cfg.Validate fails.
func New(cfg Config) (*Broker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	b := &Broker{
		cfg:          cfg,
		validator:    newValidator(cfg),
		cimdResolver: newCIMDResolver(nil),
	}
	return b, nil
}

// Validator returns the Broker's underlying Validator. Useful for stdio
// transports that don't need the HTTP broker endpoints.
func (b *Broker) Validator() *Validator { return b.validator }

// Config returns the Broker's effective configuration.
func (b *Broker) Config() Config { return b.cfg }

// RegisterRoutes mounts the broker's HTTP endpoints on mux:
//
//   - GET /.well-known/oauth-protected-resource — always
//   - GET /.well-known/oauth-authorization-server, /.well-known/openid-configuration — broker mode only
//   - any-method /oauth/register — broker mode only, returns 410 + CIMD hint
//   - GET /oauth/authorize, /oauth/callback — broker mode only
//   - POST /oauth/token — broker mode only
//
// "Broker mode" means forward, or gating + BrokerUpstream — the same gate as
// Config.brokerActive().
func (b *Broker) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc(defaultProtectedResourceMetadataPath, withCORS(b.handleProtectedResourceMetadata))
	if !b.cfg.brokerActive() {
		return
	}
	for _, p := range uniquePaths(
		defaultAuthorizationServerMetadataPath,
		"/.well-known/oauth-authorization-server/oauth",
		"/oauth/.well-known/oauth-authorization-server",
	) {
		mux.HandleFunc(p, withCORS(b.handleAuthorizationServerMetadata))
	}
	for _, p := range uniquePaths(
		defaultOpenIDConfigurationPath,
		"/.well-known/openid-configuration/oauth",
		"/oauth/.well-known/openid-configuration",
	) {
		mux.HandleFunc(p, withCORS(b.handleOpenIDConfiguration))
	}
	mux.HandleFunc(defaultRegistrationPath, withCORS(handleRegistrationRemoved))
	for _, p := range uniquePaths(b.authorizationPath(), defaultAuthorizationPath) {
		mux.HandleFunc(p, withCORS(b.handleAuthorize))
	}
	for _, p := range uniquePaths(b.callbackPath(), defaultCallbackPath) {
		mux.HandleFunc(p, withCORS(b.handleCallback))
	}
	for _, p := range uniquePaths(b.tokenPath(), defaultTokenPath) {
		mux.HandleFunc(p, withCORS(b.handleToken))
	}
}

func (b *Broker) authorizationPath() string {
	return normalizedPath(b.cfg.AuthorizationPath, defaultAuthorizationPath)
}
func (b *Broker) callbackPath() string {
	return normalizedPath(b.cfg.CallbackPath, defaultCallbackPath)
}
func (b *Broker) tokenPath() string {
	return normalizedPath(b.cfg.TokenPath, defaultTokenPath)
}

func (b *Broker) resourcePrefix(r *http.Request) string {
	if prefix := suffixPrefix(
		r.URL.Path,
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	); prefix != "" {
		return prefix
	}
	if prefix := pathFromConfiguredURL(b.cfg.PublicResourceURL); prefix != "" {
		return prefix
	}
	return pathFromConfiguredURL(b.cfg.Audience)
}

func (b *Broker) authServerPrefix(r *http.Request) string {
	if prefix := suffixPrefix(
		r.URL.Path,
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	); prefix != "" {
		return prefix
	}
	if prefix := pathFromConfiguredURL(b.cfg.PublicAuthServerURL); prefix != "" {
		return prefix
	}
	return pathFromConfiguredURL(b.cfg.Issuer)
}

func (b *Broker) resourceBaseURL(r *http.Request) string {
	if u := normalizeURL(b.cfg.PublicResourceURL); u != "" {
		return u
	}
	return schemeAndHost(r) + b.resourcePrefix(r)
}

func (b *Broker) authServerBaseURL(r *http.Request) string {
	if u := normalizeURL(b.cfg.PublicAuthServerURL); u != "" {
		return u
	}
	return schemeAndHost(r) + b.authServerPrefix(r)
}

func (b *Broker) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	baseURL := b.resourceBaseURL(r)
	var authorizationServers []string
	if b.cfg.brokerActive() {
		authorizationServers = []string{strings.TrimRight(b.authServerBaseURL(r), "/")}
	} else {
		authorizationServers = []string{strings.TrimSpace(b.cfg.Issuer)}
	}
	resp := map[string]any{
		"resource":                 canonicalResourceURL(baseURL),
		"authorization_servers":    authorizationServers,
		"scopes_supported":         oidcScopesForAdvertisement(b.cfg.Scopes),
		"bearer_methods_supported": []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (b *Broker) asMetadata(r *http.Request) map[string]any {
	baseURL := b.authServerBaseURL(r)
	return map[string]any{
		"issuer":                                          strings.TrimRight(baseURL, "/"),
		"authorization_endpoint":                          joinURLPath(baseURL, b.authorizationPath()),
		"token_endpoint":                                  joinURLPath(baseURL, b.tokenPath()),
		"scopes_supported":                                oidcScopesForAdvertisement(b.cfg.Scopes),
		"response_types_supported":                        []string{"code"},
		"grant_types_supported":                           []string{"authorization_code"},
		"token_endpoint_auth_methods_supported":           []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"},
		"code_challenge_methods_supported":                []string{"S256"},
		"client_id_metadata_document_supported":           true,
	}
}

func (b *Broker) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.asMetadata(r))
}

func (b *Broker) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	resp := b.asMetadata(r)
	// Forward mode → upstream id_tokens are RS-signed; advertise their algs is
	// upstream's job, not ours. Gating mode mints a JWE-wrapped downstream
	// token (HS256-equivalent semantics), but we don't sign a JWS — wrapping
	// is JWE-only. To keep ChatGPT happy we still advertise something here.
	if !b.cfg.Mode.IsForward() {
		resp["subject_types_supported"] = []string{"public"}
		resp["id_token_signing_alg_values_supported"] = []string{"HS256"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleRegistrationRemoved(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "registration_not_supported",
		"error_description": "Dynamic Client Registration is no longer supported; clients must use OAuth Client ID Metadata Documents (CIMD). See client_id_metadata_document_supported on /.well-known/oauth-authorization-server.",
	})
}

func (b *Broker) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" || q.Get("response_type") != "code" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing client_id, redirect_uri, or response_type=code")
		return
	}
	client, err := b.cimdResolver.resolve(r.Context(), clientID)
	if err != nil {
		b.cfg.logger().Debug("oauth /authorize: CIMD resolution failed", "client_id", truncateForLog(clientID, 80), "err", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "unknown OAuth client")
		return
	}
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "PKCE S256 is required")
		return
	}
	resource := q.Get("resource")
	if resource != "" {
		want := strings.TrimRight(b.resourceBaseURL(r), "/")
		got := strings.TrimRight(resource, "/")
		if got != want {
			writeTokenError(w, http.StatusBadRequest, "invalid_target", "resource indicator does not identify this MCP server")
			return
		}
	}
	upstreamVerifier, err := newPKCEVerifier()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to generate PKCE verifier")
		return
	}
	stateJWE, err := encodePendingAuth(b.cfg.SigningSecret, pendingAuth{
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		Scope:                sanitizeScope(q.Get("scope")),
		ClientState:          q.Get("state"),
		CodeChallenge:        q.Get("code_challenge"),
		CodeChallengeMethod:  q.Get("code_challenge_method"),
		Resource:             resource,
		UpstreamPKCEVerifier: upstreamVerifier,
		ExpiresAt:            time.Now().Add(time.Duration(defaultPendingAuthTTLSeconds) * time.Second),
	})
	if err != nil {
		b.cfg.logger().Error("oauth /authorize: failed to encode pending-auth JWE", "err", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to initialize OAuth state")
		return
	}

	authURL, err := b.resolveUpstreamAuthURL()
	if err != nil {
		writeTokenError(w, http.StatusBadGateway, "server_error", "failed to resolve upstream authorization endpoint")
		return
	}
	callbackURL := joinURLPath(b.authServerBaseURL(r), b.callbackPath())
	upstream := url.Values{}
	upstream.Set("client_id", b.cfg.ClientID)
	upstream.Set("redirect_uri", callbackURL)
	upstream.Set("response_type", "code")
	scope := strings.Join(b.cfg.Scopes, " ")
	if scope == "" {
		scope = "openid email"
	}
	if b.cfg.UpstreamOfflineAccess {
		if isGoogleIssuer(b.cfg.Issuer) {
			upstream.Set("access_type", "offline")
			if b.cfg.UpstreamForceConsent {
				upstream.Set("prompt", "consent")
			}
		} else if !slices.Contains(strings.Fields(scope), "offline_access") {
			scope = strings.TrimSpace(scope + " offline_access")
		}
	}
	upstream.Set("scope", scope)
	upstream.Set("state", stateJWE)
	upstream.Set("code_challenge", pkceChallenge(upstreamVerifier))
	upstream.Set("code_challenge_method", "S256")
	http.Redirect(w, r, authURL+"?"+upstream.Encode(), http.StatusFound)
}

func (b *Broker) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing state or code on callback")
		return
	}
	pending, ok := decodePendingAuth(b.cfg.SigningSecret, state)
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "unknown or expired authorization request")
		return
	}
	codeJWE, err := encodeAuthCode(b.cfg.SigningSecret, issuedCode{
		ClientID:             pending.ClientID,
		RedirectURI:          pending.RedirectURI,
		Scope:                pending.Scope,
		CodeChallenge:        pending.CodeChallenge,
		CodeChallengeMethod:  pending.CodeChallengeMethod,
		Resource:             pending.Resource,
		UpstreamAuthCode:     code,
		UpstreamPKCEVerifier: pending.UpstreamPKCEVerifier,
		ExpiresAt:            time.Now().Add(time.Duration(defaultAuthCodeTTLSeconds) * time.Second),
	})
	if err != nil {
		b.cfg.logger().Error("oauth /callback: failed to encode auth-code JWE", "err", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue authorization code")
		return
	}
	b.cfg.logger().Info("oauth /callback wrapped upstream auth code; awaiting /token",
		"client_id", truncateForLog(pending.ClientID, 80),
		"mode", string(b.cfg.Mode.Normalize()))

	redirect, err := url.Parse(pending.RedirectURI)
	if err != nil {
		writeTokenError(w, http.StatusBadGateway, "server_error", "pending-auth carried an unparseable redirect_uri")
		return
	}
	params := redirect.Query()
	params.Set("code", codeJWE)
	if pending.ClientState != "" {
		params.Set("state", pending.ClientState)
	}
	redirect.RawQuery = params.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		b.handleTokenAuthCode(w, r)
	default:
		// v1 does not support refresh_token. CIMD clients re-authorize.
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	}
}

func (b *Broker) handleTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	clientID := r.Form.Get("client_id")
	if r.Form.Get("client_secret") != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_secret authentication not supported")
		return
	}
	client, err := b.cimdResolver.resolve(r.Context(), clientID)
	if err != nil {
		b.cfg.logger().Debug("oauth /token: CIMD resolution failed", "err", err, "client_id", truncateForLog(clientID, 80))
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	assertion := r.Form.Get("client_assertion")
	assertionType := r.Form.Get("client_assertion_type")
	switch client.TokenEndpointAuthMethod {
	case "none":
		if assertion != "" || assertionType != "" {
			writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_assertion not accepted for public clients")
			return
		}
	case "private_key_jwt":
		if assertion != "" || assertionType != "" {
			if assertionType != clientAssertionType {
				writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_assertion_type must be jwt-bearer")
				return
			}
			tokenEndpointURL := joinURLPath(b.authServerBaseURL(r), b.tokenPath())
			if err := b.cimdResolver.verifyClientAssertion(r.Context(), client, clientID, assertion, tokenEndpointURL); err != nil {
				b.cfg.logger().Debug("oauth /token: client_assertion invalid", "err", err)
				writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_assertion invalid")
				return
			}
		}
	default:
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "unsupported client auth method")
		return
	}
	requestRedirect := r.Form.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, requestRedirect) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri not registered for this client")
		return
	}
	issued, ok := decodeAuthCode(b.cfg.SigningSecret, r.Form.Get("code"))
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if issued.ClientID != clientID || issued.RedirectURI != requestRedirect {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if issued.CodeChallenge == "" || pkceChallenge(r.Form.Get("code_verifier")) != issued.CodeChallenge {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid PKCE verifier")
		return
	}
	if formResource := r.Form.Get("resource"); formResource != "" && issued.Resource != "" {
		if strings.TrimRight(formResource, "/") != strings.TrimRight(issued.Resource, "/") {
			writeTokenError(w, http.StatusBadRequest, "invalid_target", "resource indicator does not match the one used at /authorize")
			return
		}
	}
	if issued.UpstreamAuthCode == "" || issued.UpstreamPKCEVerifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}

	callbackURL := joinURLPath(b.authServerBaseURL(r), b.callbackPath())
	tokenURL, err := b.resolveUpstreamTokenURL()
	if err != nil {
		b.cfg.logger().Error("oauth /token: failed to resolve upstream token endpoint", "err", err)
		writeTokenError(w, http.StatusBadGateway, "server_error", "failed to resolve upstream token endpoint")
		return
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", issued.UpstreamAuthCode)
	form.Set("client_id", b.cfg.ClientID)
	if b.cfg.ClientSecret != "" {
		form.Set("client_secret", b.cfg.ClientSecret)
	}
	form.Set("redirect_uri", callbackURL)
	form.Set("code_verifier", issued.UpstreamPKCEVerifier)

	upstreamResp, err := b.cfg.httpClient().PostForm(tokenURL, form)
	if err != nil {
		b.cfg.logger().Error("oauth /token: upstream code exchange transport error", "err", err, "token_url", tokenURL)
		writeTokenError(w, http.StatusBadGateway, "server_error", "upstream code exchange failed")
		return
	}
	defer func() { _ = upstreamResp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(upstreamResp.Body, maxOAuthResponseBytes))
	if err != nil {
		writeTokenError(w, http.StatusBadGateway, "server_error", "failed to read upstream token response")
		return
	}
	if upstreamResp.StatusCode >= 300 {
		errCode, bodyLen := safeUpstreamErrorFields(body)
		b.cfg.logger().Warn("oauth /token: upstream code exchange rejected — likely replay",
			"status", upstreamResp.StatusCode,
			"upstream_error", errCode,
			"body_len", bodyLen,
			"client_id", truncateForLog(clientID, 80))
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "upstream rejected the authorization code")
		return
	}
	var tokenResp struct {
		AccessToken      string `json:"access_token"`
		IDToken          string `json:"id_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		writeTokenError(w, http.StatusBadGateway, "server_error", "upstream returned non-JSON response")
		return
	}
	if tokenResp.Error != "" {
		b.cfg.logger().Warn("oauth /token: upstream 2xx with RFC 6749 error body — treat as invalid_grant",
			"status", upstreamResp.StatusCode,
			"upstream_error", tokenResp.Error,
			"client_id", truncateForLog(clientID, 80))
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "upstream rejected the authorization code")
		return
	}
	if tokenResp.AccessToken == "" && tokenResp.IDToken == "" {
		writeTokenError(w, http.StatusBadGateway, "server_error", "upstream returned no usable token")
		return
	}

	var identityClaims *Claims
	if tokenResp.IDToken != "" {
		identityClaims, err = b.validator.ValidateUpstreamIdentityToken(tokenResp.IDToken, b.cfg.ClientID)
		if err != nil {
			b.cfg.logger().Error("oauth /token: upstream identity token validation failed", "err", err)
			writeTokenError(w, http.StatusBadGateway, "server_error", "failed to validate upstream identity token")
			return
		}
	} else if tokenResp.AccessToken != "" {
		identityClaims, err = b.fetchUserInfo(r.Context(), tokenResp.AccessToken)
		if err != nil {
			b.cfg.logger().Error("oauth /token: upstream userinfo validation failed", "err", err)
			writeTokenError(w, http.StatusBadGateway, "server_error", "failed to validate upstream identity")
			return
		}
	}
	// Refresh near-expired upstream id_tokens (Google silent-SSO can return
	// cached tokens with minutes of remaining life).
	if tokenResp.IDToken != "" && tokenResp.RefreshToken != "" {
		var freshDur time.Duration
		tokenResp.IDToken, identityClaims, freshDur = b.maybeRefreshNearExpiredIDToken(tokenResp.IDToken, tokenResp.RefreshToken, identityClaims)
		if freshDur > 0 {
			tokenResp.ExpiresIn = int64(freshDur / time.Second)
		}
	}

	bearerToken := tokenResp.IDToken
	if bearerToken == "" {
		bearerToken = tokenResp.AccessToken
	}

	// Gating mode: JWE-wrap the upstream id_token so the backend never sees
	// the upstream bearer. Forward mode hands back the upstream id_token
	// verbatim; the backend is then responsible for upstream validation.
	if b.cfg.Mode.IsGating() && tokenResp.IDToken != "" {
		expAt := time.Now().Add(b.cfg.accessTokenTTL())
		if identityClaims != nil && identityClaims.ExpiresAt > 0 {
			upstreamExp := time.Unix(identityClaims.ExpiresAt, 0)
			if upstreamExp.Before(expAt) {
				expAt = upstreamExp
			}
		}
		wrapped, err := encodeDownstreamAccessToken(b.cfg.SigningSecret, tokenResp.IDToken, expAt)
		if err != nil {
			b.cfg.logger().Error("oauth /token: failed to mint downstream access token", "err", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint downstream token")
			return
		}
		bearerToken = wrapped
	}

	if tokenResp.Scope == "" {
		tokenResp.Scope = issued.Scope
	}
	if tokenResp.Scope == "" {
		tokenResp.Scope = strings.Join(b.cfg.Scopes, " ")
	}
	tokenType := tokenResp.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	var expiresIn int64
	switch {
	case b.cfg.Mode.IsGating() && tokenResp.IDToken != "":
		expiresIn = int64(b.cfg.accessTokenTTL() / time.Second)
		if identityClaims != nil && identityClaims.ExpiresAt > 0 {
			remaining := identityClaims.ExpiresAt - time.Now().Unix()
			if remaining < expiresIn {
				expiresIn = remaining
			}
		}
	case tokenResp.IDToken != "" && identityClaims != nil && identityClaims.ExpiresAt > 0:
		expiresIn = identityClaims.ExpiresAt - time.Now().Unix()
	case tokenResp.ExpiresIn > 0:
		expiresIn = tokenResp.ExpiresIn
	default:
		expiresIn = int64(defaultAccessTokenTTLSeconds)
	}
	if expiresIn < 0 {
		expiresIn = 0
	}
	response := map[string]any{
		"access_token": bearerToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}
	if s := normalizeUpstreamScopeForClient(tokenResp.Scope); s != "" {
		response["scope"] = s
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (b *Broker) resolveUpstreamAuthURL() (string, error) {
	if u := strings.TrimSpace(b.cfg.AuthURL); u != "" {
		return u, nil
	}
	d, err := b.validator.fetchOIDCDiscovery(strings.TrimSpace(b.cfg.Issuer))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(d.AuthorizationEndpoint) == "" {
		return "", errors.New("authorization endpoint is not configured or discoverable")
	}
	return strings.TrimSpace(d.AuthorizationEndpoint), nil
}

func (b *Broker) resolveUpstreamTokenURL() (string, error) {
	if u := strings.TrimSpace(b.cfg.TokenURL); u != "" {
		return u, nil
	}
	d, err := b.validator.fetchOIDCDiscovery(strings.TrimSpace(b.cfg.Issuer))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(d.TokenEndpoint) == "" {
		return "", errors.New("token endpoint is not configured or discoverable")
	}
	return strings.TrimSpace(d.TokenEndpoint), nil
}

func (b *Broker) fetchUserInfo(ctx context.Context, accessToken string) (*Claims, error) {
	userInfoURL := strings.TrimSpace(b.cfg.UserInfoURL)
	if userInfoURL == "" {
		d, err := b.validator.fetchOIDCDiscovery(strings.TrimSpace(b.cfg.Issuer))
		if err == nil {
			userInfoURL = d.UserInfoEndpoint
		}
	}
	if userInfoURL == "" {
		return nil, errors.New("userinfo endpoint is not configured or discoverable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := b.cfg.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	c := claimsFromUserInfo(raw)
	if c.Issuer == "" {
		c.Issuer = b.cfg.Issuer
	}
	if err := b.validator.applyIdentityPolicy(c); err != nil {
		return nil, err
	}
	return c, nil
}

// writeTokenError writes an RFC 6749 §5.2 JSON error response.
func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, description))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
