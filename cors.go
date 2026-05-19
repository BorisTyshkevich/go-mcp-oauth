package oauth

import "net/http"

// corsHeaders writes the CORS headers needed for browser-based MCP clients
// (claude.ai requires them on /.well-known/* and /oauth/authorize at minimum).
// We use "*" deliberately: the OAuth metadata endpoints serve public info and
// /authorize/callback/token rely on per-request credentials, not cookies.
func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

// withCORS wraps an HTTP handler with CORS headers + OPTIONS preflight. The
// inner handler doesn't see OPTIONS — it responds 204 directly.
func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		corsHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}
