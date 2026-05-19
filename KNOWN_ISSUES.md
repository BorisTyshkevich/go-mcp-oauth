# Known issues and follow-ups

Findings from the initial review of the extracted library. None block
shipping; severity is shown in brackets. File:line references are against
the initial commit.

## Security / correctness

### 1. `schemeAndHost` trusts client-supplied headers [medium]

`urls.go:117-119` reads `X-Forwarded-Proto` unconditionally and falls back
to `r.Host`. If the broker is ever reachable without a reverse proxy that
strips client-supplied copies of these headers, an attacker can:

- flip the advertised `authorization_endpoint` / `token_endpoint` scheme to
  `http://` via `X-Forwarded-Proto: http`, and/or
- redirect the OAuth round-trip to an attacker-controlled host by spoofing
  `Host`.

**Mitigation today:** set `PublicResourceURL` and `PublicAuthServerURL`
explicitly in production. The README now calls this out under "Trust model
and deployment."

**Follow-up:** add a `Config.TrustForwardedHeaders bool` (default `false`) so
the proxy contract is opt-in rather than implicit.

---

### 2. Refresh-threshold comment contradicts the threshold [low]

`refresh.go:17` declares `brokerIDTokenRefreshThresholdSeconds = 55 * 60`
and the comment claims "a freshly-minted Google id_token (exp = iat + 1h)
is never re-fetched." But the check is
`if remaining >= 3300 { skip }` — so a Google id_token issued ~5 minutes
ago has `remaining ≈ 3300` and falls *exactly* on the boundary. Reused
warm-session tokens with less than 55 minutes remaining are refreshed every
time `/token` is hit.

**Fix:** lower to ~60–120 seconds (the original intent) or rewrite the
comment to match the 55-min behavior, whichever was actually wanted.

---

### 3. `unixFromClaims` silently zeros malformed `exp` [medium]

`broker_state.go:125-139` returns `time.Time{}` if `exp` is not
`float64 | int64 | int`. `validateJWEExpiration` in `jwe.go:135-155` only
checks `exp` *if it is present*. Together, a JWE with a missing or
non-numeric `exp` claim decodes cleanly with `ExpiresAt = 0` and is
otherwise treated as valid. The whitelist check would still pass because
`exp` is in `jweAllowedClaimKeys`.

**Fix:** in `validateJWEClaimsWhitelist` (or a sibling), require `exp` to
exist and be of an expected numeric type for every JWE artifact the broker
mints. Reject otherwise.

---

### 4. Forward-mode opaque-bearer soft-pass is easy to misuse [low]

`validator.go:73-81` returns `(nil, nil)` for non-JWT bearers in forward
mode. The middleware then sets `withRawToken` on context but not
`withClaims`, so a backend calling `ClaimsFromContext` gets `(nil, false)`
and must know to fall back to `RawTokenFromContext`. The contract is
documented (`context.go:34-37`) but easy to miss.

**Fix options:** add a typed sentinel value, a `WasOpaque` flag on Claims,
or an example test showing the dual-path lookup.

---

### 5. Allowlist failures fall through to generic 401 [intentional?]

`middleware.go:73-82` doesn't have a `case ErrEmailNotVerified` /
`ErrUnauthorizedDomain` arm — both map to the default `invalid_token`.
This is defensible (avoid leaking why the principal was rejected), but the
absence of an explicit branch reads like a bug.

**Action:** add a comment confirming the intent, or surface a distinct
`error="access_denied"` if the deployment trusts the client more.

---

## Code hygiene

### 6. Dead code [low]

- `errInvalidJWEClaims` declared in `jwe.go:159` is never returned;
  `validateJWEClaimsWhitelist` uses `fmt.Errorf` instead.
- `ttlSeconds` in `urls.go:54-59` has no callers.
- `Config.RefreshTokenTTL` + `defaultRefreshTokenTTL` +
  `Config.refreshTokenTTL()` are reserved for the next minor; comments
  acknowledge it but Go convention would be to delete until needed.

**Action:** remove or keep with a `// nolint:unused — reserved for vN+1`
comment, whichever you prefer.

---

### 7. JWKS cache TTL is process-uniform [low]

`defaultJWKSCacheTTL = 5min` (`config.go:246`) is hardcoded. On upstream
JWKS rotation, the broker rejects tokens signed with the new key for up to
the cache TTL minus the `validator.go:184-199` kid-miss retry window. The
retry covers rotation today, but operators with stricter SLOs cannot
shorten the cache.

**Fix:** expose `Config.JWKSCacheTTL time.Duration` (and probably
`Config.ClockSkewSeconds`).

---

## Documentation

### 8. ~~Missing `README.md`, package `doc.go`, example test~~ — fixed

Added in the same commit as this file.

---

## Suggestions (not bugs)

- Move `internal/oauthtest` to a top-level `oauthtest/` package if you want
  downstream consumers to write integration tests against the broker.
- Add a SECURITY.md with the trust model boilerplate from README.
- Add a CI workflow (`go vet`, `go test`, `staticcheck`).
