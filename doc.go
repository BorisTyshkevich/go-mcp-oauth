// Package oauth is an embeddable OAuth 2.1 / OIDC broker for Model Context
// Protocol (MCP) servers.
//
// # Overview
//
// The library covers three deployment shapes:
//
//   - Resource server only ("pure gating"): the operator runs an OAuth
//     Authorization Server elsewhere; this library validates inbound
//     bearers and enforces identity policy. Use [NewValidator].
//
//   - Resource server + broker ("forward"): the library hosts the AS
//     endpoints, brokers the auth-code flow against an upstream IdP, and
//     hands the upstream id_token back to MCP clients verbatim. Backends
//     are responsible for upstream JWKS validation. Use [New] with
//     Config.Mode = ModeForward.
//
//   - Resource server + broker + opaque downstream tokens ("gating +
//     broker_upstream"): the library hosts the AS endpoints and mints
//     JWE-wrapped downstream access tokens that hide the upstream id_token
//     from backends. The MCP server is the sole validator. Use [New] with
//     Config.Mode = ModeGating and Config.BrokerUpstream = true.
//
// # MCP-client registration
//
// Inbound MCP clients (Claude.ai, ChatGPT, …) are not registered via OAuth
// 2.0 Dynamic Client Registration. They identify themselves via an OAuth
// Client ID Metadata Document (CIMD): the client_id is the HTTPS URL of a
// JSON metadata document. The broker fetches and validates the document
// at /oauth/authorize and /oauth/token. See draft-ietf-oauth-client-id-
// metadata-document.
//
// # State model
//
// The broker is stateless. Pending-auth, authorization codes, and
// downstream access tokens are JWE artifacts encrypted with keys derived
// from a shared HKDF master (Config.SigningSecret) using per-purpose info
// labels. Any replica with the same SigningSecret can decrypt; no Redis
// is required. Rotating a single artifact type means bumping its vN
// suffix in the corresponding hkdfInfo* constant.
//
// # PKCE
//
// PKCE S256 is required on both legs of every auth flow:
//
//   - MCP-client → broker: standard PKCE pair carried on /authorize and
//     /token by the MCP client.
//   - broker → upstream IdP: an independent PKCE pair the broker
//     generates per-flow and stores inside the pending-auth JWE (RFC 8252
//     §8.1, OAuth 2.1 §7.5.2).
//
// # Trust model
//
// The library assumes it is deployed behind a reverse proxy that strips
// client-supplied X-Forwarded-Proto and Host headers, or that
// Config.PublicResourceURL and Config.PublicAuthServerURL are set
// explicitly. Otherwise an attacker can flip the advertised AS scheme to
// http:// or redirect the auth round-trip to an attacker host. See
// KNOWN_ISSUES.md.
//
// # Quick start
//
// See [Example] for a runnable wiring of a gating-mode broker with the
// resource-server middleware mounted on /mcp.
package oauth
