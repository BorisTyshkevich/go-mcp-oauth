# go-mcp-oauth

OAuth 2.1 / OIDC broker library for Model Context Protocol (MCP) servers,
written in Go.

`go-mcp-oauth` is a small, embeddable library that lets an MCP server accept
bearer tokens from OAuth-aware MCP clients (Claude.ai, ChatGPT, etc.) without
running a separate auth proxy. It can either pass the upstream IdP's id_token
through to the backend verbatim ("forward" mode), or mint an opaque
JWE-wrapped downstream bearer that hides the upstream token from backends
("gating" mode). Optionally it also acts as the OAuth Authorization Server
that MCP clients talk to, brokering the authorization-code flow against an
upstream IdP (Google, Auth0, …).

> Status: extracted from the Altinity MCP gateway. Public API surface is
> small; semver pre-1.0.

---

## Features

- **OAuth 2.1 broker** — `/oauth/authorize`, `/oauth/callback`, `/oauth/token`
  with PKCE (S256) on both legs (client→broker and broker→upstream).
- **Stateless** — pending-auth, authorization codes, and downstream access
  tokens are JWE artifacts derived from a shared HKDF master secret. Any
  replica with the same secret can decrypt; no Redis required.
- **CIMD instead of DCR** — MCP clients use [OAuth Client ID Metadata
  Documents][cimd-draft] (the URL is the `client_id`); the broker fetches +
  validates the metadata at `/authorize` and `/token`. No registration
  endpoint, no per-(client × server) state.
- **`private_key_jwt` client auth** (RFC 7523) for clients that publish a
  `jwks_uri` in their CIMD doc (ChatGPT).
- **Validator + middleware** for resource-server-only deployments
  (`stdio`, or when the operator runs their own AS).
- **RFC 9728 protected-resource metadata** + `WWW-Authenticate`
  challenges with `resource_metadata` parameter.
- **SSRF-defended CIMD + JWKS fetch**: IANA special-purpose CIDR blocklist,
  post-dial address recheck, no redirects, 5 KiB body cap.
- **Identity policy hooks**: allowed email domains, allowed Google `hd`
  (workspace) domains, optional `email_verified` enforcement.

[cimd-draft]: https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/

---

## Install

```bash
go get github.com/BorisTyshkevich/go-mcp-oauth
```

Requires Go 1.25+.

---

## Quick start

### Gating mode + broker, behind a reverse proxy

```go
package main

import (
    "log"
    "net/http"

    oauth "github.com/BorisTyshkevich/go-mcp-oauth"
)

func main() {
    broker, err := oauth.New(oauth.Config{
        Mode:                oauth.ModeGating,
        BrokerUpstream:      true,
        Issuer:              "https://accounts.google.com",
        ClientID:            "1234.apps.googleusercontent.com",
        ClientSecret:        "GOCSPX-...",
        Audience:            "https://mcp.example.com/",
        PublicResourceURL:   "https://mcp.example.com",
        PublicAuthServerURL: "https://mcp.example.com",
        Scopes:              []string{"openid", "email"},
        SigningSecret:       []byte("at-least-32-bytes-of-random-from-env"),
        AllowedEmailDomains: []string{"example.com"},
    })
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    broker.RegisterRoutes(mux) // /.well-known/* + /oauth/*
    mux.Handle("/mcp", broker.Middleware(myMCPHandler()))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### Resource server only (no broker endpoints)

```go
v, err := oauth.NewValidator(oauth.Config{
    Mode:     oauth.ModeForward,
    Issuer:   "https://accounts.google.com",
    Audience: "https://mcp.example.com/",
})
// Use v.Validate(rawBearer) on inbound JWTs.
```

See `example_test.go` for a runnable example.

---

## Modes

| | **Forward** | **Gating** |
|--|--|--|
| Token returned to MCP client | Upstream `id_token` verbatim | Opaque JWE wrapping the upstream `id_token` |
| Who validates the bearer | The backend (must know upstream JWKS) | The MCP server, via this library only |
| Downstream secret needed | No | Yes (`SigningSecret`) |
| Broker endpoints | Always | Only when `BrokerUpstream: true` |

Gating mode is the safer default: backends never see the upstream token, so
its rotation, audience, and scope are decoupled from the MCP boundary.

---

## Configuration

The full set of knobs is on `oauth.Config`. The required fields by mode:

- **Forward**: `Issuer`, `ClientID`, `ClientSecret`, `Audience`,
  `SigningSecret`.
- **Gating + broker** (`BrokerUpstream: true`): same as forward.
- **Pure gating** (resource server only): `Issuer` *or* `JWKSURL`, plus
  `Audience`. Broker-only knobs (`ClientSecret`, `TokenURL`, …) are rejected
  by `Config.Validate` so misconfigurations fail loud at boot.

`SigningSecret` is the HKDF master used to derive per-purpose keys. Use at
least 32 random bytes from your secrets manager; rotate by bumping the `vN`
suffix in `hkdfInfo*` labels (one purpose at a time, no downtime).

---

## Trust model and deployment

- The broker **trusts `X-Forwarded-Proto` and `Host`** to compute the
  externally visible URL when `PublicResourceURL` / `PublicAuthServerURL`
  are not set. **Run behind a reverse proxy that strips client-supplied
  copies of these headers** or pin `PublicResourceURL` /
  `PublicAuthServerURL` explicitly.
- `SigningSecret` must be shared across all replicas and never logged.
- `internal/oauthtest` is a fake upstream IdP for tests; do **not** import
  from production code.

---

## Documentation

- Package overview and security model: see `doc.go`.
- Runnable usage example: see `example_test.go`.
- Self-contained forward-mode broker example:
  [`examples/hosting/main.go`](examples/hosting/main.go).
- How to forward the validated bearer to backends (Authorization vs
  X-JWT-Assertion vs X-Grafana-Id; pro / con of each):
  [`docs/forwarding-to-backends.md`](docs/forwarding-to-backends.md).
- Known issues / followups from initial review: see [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md).

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
