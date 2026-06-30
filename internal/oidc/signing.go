package oidc

import (
	"net/http"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// SigningAlgMiddleware injects the requesting client's configured token signing
// algorithm into the request context on the authorize and token endpoints, so
// the storage signs id_tokens (and JWT access tokens) with that algorithm.
func SigningAlgMiddleware(store *storage.Storage) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isAuthorizeOrToken(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			clientID := requestClientID(r)
			if clientID != "" {
				if c, err := store.DB().GetClient(clientID); err == nil && c.IDTokenSignAlg != "" {
					alg := jose.SignatureAlgorithm(c.IDTokenSignAlg)
					if storage.IsSupportedAlg(alg) {
						r = r.WithContext(storage.WithSigningAlg(r.Context(), alg))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isAuthorizeOrToken(path string) bool {
	return path == "/authorize" || path == "/auth" || isTokenEndpoint(path)
}

// requestClientID extracts client_id from the query (authorize) or the form /
// basic auth (token), without disturbing later parsing.
func requestClientID(r *http.Request) string {
	if v := r.URL.Query().Get("client_id"); v != "" {
		return v
	}
	if id, _, ok := r.BasicAuth(); ok && id != "" {
		return id
	}
	if err := r.ParseForm(); err == nil {
		return r.Form.Get("client_id")
	}
	return ""
}
