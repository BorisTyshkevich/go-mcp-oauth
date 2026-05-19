# Forwarding the validated bearer to backends

After `Broker.Middleware` validates an inbound bearer, the raw JWT is
available to the host server via `oauth.RawTokenFromContext`. What the
host does with it is intentionally outside this library — different
backends accept identity in different headers, and the choice has real
operator-visible consequences.

This note documents the three placement options seen in practice, with
their trade-offs, so each integrator can pick the same shape twice in a
row.

## Background

In forward mode the broker hands the *upstream* `id_token` back to the
MCP client verbatim and the MCP client sends it to your MCP server as
`Authorization: Bearer <jwt>`. Your server validates it locally
(signature, audience, expiry, scope) and then needs to talk to a
backend — ClickHouse, Grafana, GitHub, … — on the user's behalf. Where
does the bearer go in the outbound request?

## Options

### A. `Authorization: Bearer <jwt>` — replace the service account

Drop your service-account / API-key auth entirely. The backend
receives the same JWT the MCP client sent, validates it independently
(its own JWKS check), and maps the subject to a backend user.

- **Pros**
  - Identity is intrinsic to the call — backend-side audit logs and
    per-user permissions just work.
  - One credential, one trust boundary.
  - Closest analogue to ClickHouse's `oauth_token` setting; matches the
    altinity-mcp `antalya` deployment shape.
- **Cons**
  - Hard-fails if backend JWT validation rejects the token (audience,
    issuer, signature). No service-account fallback.
  - Backend must be configured to accept *your* IdP's tokens
    (`auth.jwt` block in Grafana, `[users].oauth_token` in
    ClickHouse, etc.). MCP and backend config now have to agree.
  - JWT-driven `auto_sign_up` can create one backend user per JWT
    subject — large user-set proliferation in some backends.

### B. `X-Grafana-Id: <jwt>` — Grafana Cloud OBO

Keep your service-account token in `Authorization` and put the user's
JWT in `X-Grafana-Id`. This is the on-behalf-of header Grafana Cloud's
identity API uses for microservice fan-out.

- **Pros**
  - Service account stays authoritative for API access — never breaks if
    the JWT is rejected.
  - No backend-side JWT validation config needed (assuming Grafana Cloud
    natively honors the header).
- **Cons**
  - Backend-specific: only Grafana Cloud's auth stack honors this; OSS
    Grafana ignores it without custom config. Other backends entirely
    different.
  - Identity is advisory rather than enforced — every call still runs
    as the service account's permission set.

### C. `X-JWT-Assertion: <jwt>` (or similar) — additive identity

Keep your service-account token in `Authorization` and put the user's
JWT in a separate, backend-configurable header. The backend is
configured to validate that header via its own JWT auth path and
augment / override identity from it.

- **Pros**
  - Additive: if the JWT is missing or invalid, the SA token still
    authenticates the call. OAuth misconfiguration degrades identity
    but does not break access.
  - Backend chooses the header name it likes (`X-JWT-Assertion`
    is Grafana's default for `auth.jwt`).
  - Same identity-enforcement model as (A) without the all-or-nothing
    failure mode.
- **Cons**
  - Two headers, two trust paths. The backend must be configured
    correctly for the JWT path to actually map to a user.
  - Slightly more code on the MCP side (a separate RoundTripper layer
    that doesn't fight with `Authorization`).

## Worked example: mcp-grafana

[mcp-grafana](https://github.com/Altinity/mcp-grafana) picked **C**. The
reasoning, copy-paste:

> Option C is safer because it doesn't fight with the Authorization
> header — you can fall back to the SA token if the user's JWT is
> missing or invalid, instead of hard-failing the request.

Concretely:

```go
// mcpgrafana.go (excerpt)
type JWTAssertionRoundTripper struct {
    assertion  string
    underlying http.RoundTripper
}

func (rt *JWTAssertionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    assertion := rt.assertion
    if cfg := GrafanaConfigFromContext(req.Context()); cfg.JWTAssertion != "" {
        assertion = cfg.JWTAssertion
    }
    if assertion == "" {
        return rt.underlying.RoundTrip(req)
    }
    clonedReq := req.Clone(req.Context())
    clonedReq.Header.Set("X-JWT-Assertion", assertion)
    return rt.underlying.RoundTrip(clonedReq)
}
```

The Grafana side is then configured with:

```ini
[auth.jwt]
enabled = true
header_name = X-JWT-Assertion
jwk_set_url = https://<same-IdP>/.well-known/jwks.json
username_claim = email
email_claim = email
auto_sign_up = true
```

## How the library helps

`go-mcp-oauth` deliberately does **not** pick a header for you. It
exposes the raw bearer via `oauth.RawTokenFromContext(ctx)` and lets
the host server's outbound transport layer place it however the
backend expects.

The recommended pattern: after `Broker.Middleware` runs, an MCP
transport-level context-func copies the raw token from the request
context into wherever your outbound HTTP middleware expects it
(typically a per-request config object), and an `http.RoundTripper`
layer sets the header at the wire.

See `examples/hosting/main.go` for the validation half, and the
mcp-grafana `pkg/oauth/wiring.go` + `mcpgrafana.JWTAssertionRoundTripper`
for a real-world Option C wiring.
