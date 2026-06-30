// Package behavior implements per-client mock behaviors (simulated latency and
// forced OAuth errors) as HTTP middleware wrapping the OP protocol endpoints.
package behavior

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// Middleware returns an http.Handler middleware that applies the configured
// latency and forced-error behavior for the client referenced in the request,
// but only on the authorize/token endpoints.
func Middleware(store *storage.Storage) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isProtocolEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			clientID := clientIDFromRequest(r)
			if clientID == "" {
				next.ServeHTTP(w, r)
				return
			}
			client, err := store.DB().GetClient(clientID)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if client.LatencyMS > 0 {
				time.Sleep(time.Duration(client.LatencyMS) * time.Millisecond)
			}
			if client.ForceError != "" {
				if isAuthorizeEndpoint(r.URL.Path) {
					redirectAuthorizeError(w, r, client.ForceError)
				} else {
					writeOAuthError(w, client.ForceError)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isProtocolEndpoint(path string) bool {
	return isAuthorizeEndpoint(path) || isTokenEndpoint(path)
}

func isAuthorizeEndpoint(path string) bool {
	return path == "/authorize" || path == "/auth" || strings.HasSuffix(path, "/authorize")
}

func isTokenEndpoint(path string) bool {
	return path == "/oauth/token" || path == "/token" || strings.HasSuffix(path, "/token")
}

// redirectAuthorizeError mimics a real IdP returning an error on the authorize
// endpoint: a 302 back to redirect_uri carrying error/error_description/state.
// When no valid redirect_uri is present it falls back to a JSON error.
func redirectAuthorizeError(w http.ResponseWriter, r *http.Request, code string) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		writeOAuthError(w, code)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, code)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", "forced by mock IdP client behavior configuration")
	if state := r.URL.Query().Get("state"); state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func clientIDFromRequest(r *http.Request) string {
	if v := r.URL.Query().Get("client_id"); v != "" {
		return v
	}
	if id, _, ok := r.BasicAuth(); ok && id != "" {
		return id
	}
	// Best-effort form parse (ParseForm caches; the OP re-parses safely).
	if err := r.ParseForm(); err == nil {
		return r.Form.Get("client_id")
	}
	return ""
}

func writeOAuthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": "forced by mock IdP client behavior configuration",
	})
}
