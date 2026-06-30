package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// GrantTypePassword is the (legacy) Resource Owner Password Credentials grant.
// zitadel/oidc does not define it, so we declare it here.
const GrantTypePassword oidc.GrantType = "password"

// ROPCMiddleware intercepts the Resource Owner Password Credentials grant
// (grant_type=password) on the token endpoint and issues tokens directly, since
// zitadel/oidc does not implement this (legacy) grant. All other requests pass
// through to the wrapped OP handler.
//
// As a passwordless test IdP, the password value is NOT checked — only the
// username must resolve to a known user and the client must enable the grant.
func ROPCMiddleware(provider op.OpenIDProvider, store *storage.Storage) func(http.Handler) http.Handler {
	issuerInterceptor := op.NewIssuerInterceptor(provider.IssuerFromRequest)
	return func(next http.Handler) http.Handler {
		handle := issuerInterceptor.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ropcExchange(w, r, provider, store)
		})
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isTokenEndpoint(r.URL.Path) || r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			if err := r.ParseForm(); err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if r.PostForm.Get("grant_type") != string(GrantTypePassword) {
				next.ServeHTTP(w, r)
				return
			}
			handle.ServeHTTP(w, r)
		})
	}
}

func ropcExchange(w http.ResponseWriter, r *http.Request, provider op.OpenIDProvider, store *storage.Storage) {
	clientID, clientSecret := clientCredentials(r)
	if clientID == "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_id missing")
		return
	}
	client, err := store.DB().GetClient(clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client not found")
		return
	}
	// Confidential clients must present the correct secret.
	if client.Secret != "" && client.Secret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client secret")
		return
	}
	if !hasGrantType(client, GrantTypePassword) {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "client may not use the password grant")
		return
	}

	username := r.PostForm.Get("username")
	if username == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "username missing")
		return
	}
	user, err := store.DB().GetUserByUsername(username)
	if err != nil {
		// Password intentionally not checked (passwordless test IdP); unknown user only.
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "unknown user")
		return
	}

	scopes := strings.Fields(r.PostForm.Get("scope"))
	opClient, err := store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client not found")
		return
	}

	request := storage.NewAuthenticatedRequest(clientID, user.ID, scopes)
	resp, err := op.CreateTokenResponse(r.Context(), request, opClient, provider, true, "", "")
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// clientCredentials extracts client_id/secret from HTTP Basic auth or the form.
func clientCredentials(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok && u != "" {
		return u, p
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

func hasGrantType(c *storage.Client, gt oidc.GrantType) bool {
	for _, g := range c.GrantTypeList {
		if g == gt {
			return true
		}
	}
	return false
}

func isTokenEndpoint(path string) bool {
	return path == "/oauth/token" || path == "/token" || strings.HasSuffix(path, "/token")
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
