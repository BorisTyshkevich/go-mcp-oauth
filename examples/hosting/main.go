// Example "hosting" — a self-contained forward-mode broker over HTTPS.
//
// This is the shape used in production by mcp-grafana and altinity-mcp:
// the binary terminates the OAuth flow from claude.ai / ChatGPT (CIMD,
// no DCR), validates the resulting bearer locally, and exposes a
// protected MCP endpoint whose handler reads the validated identity out
// of the request context.
//
// Run:
//
//	go run ./examples/hosting \
//	    -addr :8080 \
//	    -issuer https://accounts.google.com \
//	    -client-id 1234.apps.googleusercontent.com \
//	    -client-secret-file /etc/secrets/google_client_secret \
//	    -signing-secret-file /etc/secrets/hkdf_master \
//	    -public-url https://mcp.example.com
//
// Then point an MCP client at https://mcp.example.com/mcp.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	oauth "github.com/BorisTyshkevich/go-mcp-oauth"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	issuer := flag.String("issuer", "", "upstream IdP issuer URL")
	clientID := flag.String("client-id", "", "upstream OAuth client ID")
	clientSecretFile := flag.String("client-secret-file", "", "path to upstream OAuth client secret (read at boot)")
	signingSecretFile := flag.String("signing-secret-file", "", "path to >=32-byte HKDF master secret (read at boot)")
	publicURL := flag.String("public-url", "", "externally visible base URL advertised in discovery metadata")
	scopes := flag.String("scopes", "openid,email,profile", "comma-separated upstream scopes requested at /authorize")
	allowedDomains := flag.String("allowed-email-domains", "", "comma-separated email-domain allowlist (empty = no restriction)")
	flag.Parse()

	if *issuer == "" || *clientID == "" || *clientSecretFile == "" || *signingSecretFile == "" || *publicURL == "" {
		fmt.Fprintln(os.Stderr, "all of -issuer, -client-id, -client-secret-file, -signing-secret-file, -public-url are required")
		os.Exit(2)
	}

	clientSecret, err := os.ReadFile(*clientSecretFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read client secret: %v\n", err)
		os.Exit(1)
	}
	signingSecret, err := os.ReadFile(*signingSecretFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read signing secret: %v\n", err)
		os.Exit(1)
	}

	broker, err := oauth.New(oauth.Config{
		Mode:                oauth.ModeForward,
		Issuer:              *issuer,
		Audience:            *publicURL,
		ClientID:            *clientID,
		ClientSecret:        strings.TrimSpace(string(clientSecret)),
		SigningSecret:       []byte(strings.TrimSpace(string(signingSecret))),
		Scopes:              splitCSV(*scopes),
		AllowedEmailDomains: splitCSV(*allowedDomains),
		PublicResourceURL:   *publicURL,
		PublicAuthServerURL: *publicURL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Mount the discovery endpoints + /oauth/{authorize,callback,token}.
	// /oauth/register returns HTTP 410 — CIMD only, no DCR.
	broker.RegisterRoutes(mux)

	// Protect the MCP endpoint with the broker's Middleware. After it runs,
	// the request context carries the validated claims and the raw bearer.
	mux.Handle("/mcp", broker.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := oauth.ClaimsFromContext(r.Context())
		raw, _ := oauth.RawTokenFromContext(r.Context())
		slog.Info("MCP request",
			"subject", claims.Subject,
			"email", claims.Email,
			"bearer_present", raw != "",
		)
		// In a real server you'd dispatch to your MCP transport here. The
		// raw bearer is what you'd forward to the backend — see
		// docs/forwarding-to-backends.md for the three placement options.
		fmt.Fprintf(w, "hello, %s — your raw bearer is %d bytes", claims.Email, len(raw))
	})))

	slog.Info("listening", "addr", *addr, "discovery", *publicURL+"/.well-known/oauth-protected-resource")
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
