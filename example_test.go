package oauth_test

import (
	"fmt"
	"net/http"

	oauth "github.com/BorisTyshkevich/go-mcp-oauth"
)

// Example wires a gating-mode broker that also acts as the Authorization
// Server to MCP clients. The library mounts the discovery + /oauth/* routes
// on the provided mux; the operator wraps the protected MCP handler with
// Broker.Middleware so every request must carry a valid bearer.
func Example() {
	broker, err := oauth.New(oauth.Config{
		Mode:                oauth.ModeGating,
		BrokerUpstream:      true,
		Issuer:              "https://accounts.google.com",
		ClientID:            "1234.apps.googleusercontent.com",
		ClientSecret:        "GOCSPX-redacted",
		Audience:            "https://mcp.example.com/",
		PublicResourceURL:   "https://mcp.example.com",
		PublicAuthServerURL: "https://mcp.example.com",
		Scopes:              []string{"openid", "email"},
		SigningSecret:       []byte("32-bytes-or-more-from-your-secrets-manager"),
		AllowedEmailDomains: []string{"example.com"},
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	broker.RegisterRoutes(mux)

	mcp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := oauth.ClaimsFromContext(r.Context())
		fmt.Fprintf(w, "hello, %s", claims.Email)
	})
	mux.Handle("/mcp", broker.Middleware(mcp))

	// http.ListenAndServe(":8080", mux)
	_ = mux
}

// ExampleNewValidator shows the resource-server-only setup: no broker
// endpoints, just JWT validation against an upstream IdP. Suitable for
// stdio transports or when the operator runs their own AS.
func ExampleNewValidator() {
	v, err := oauth.NewValidator(oauth.Config{
		Mode:     oauth.ModeForward,
		Issuer:   "https://accounts.google.com",
		Audience: "https://mcp.example.com/",
	})
	if err != nil {
		panic(err)
	}

	rawBearer := "eyJhbGciOi..." // from Authorization: Bearer <...>
	claims, err := v.Validate(rawBearer)
	if err != nil {
		// reject with WWW-Authenticate: Bearer error="invalid_token"
		return
	}
	if claims != nil {
		fmt.Println(claims.Subject)
	}
}
