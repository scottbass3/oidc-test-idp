// Package auth implements the passwordless end-user UI: account selection,
// consent, and device-code verification.
package auth

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/scottbass3/oidc-test-idp/internal/render"
	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// Handler serves the login/consent/device pages.
type Handler struct {
	store    *storage.Storage
	render   *render.Renderer
	callback func(context.Context, string) string // op.AuthCallbackURL
}

// New builds the auth handler. callback maps an auth request id to the OP's
// authorize-callback URL (op.AuthCallbackURL(provider)).
func New(store *storage.Storage, r *render.Renderer, callback func(context.Context, string) string) *Handler {
	return &Handler{store: store, render: r, callback: callback}
}

// Routes mounts the login and consent endpoints. issuerWrap is the OP issuer
// interceptor so the callback redirect carries the issuer (it wraps POST /login
// and POST /consent which call back into the OP).
func (h *Handler) Routes(r chi.Router, issuerWrap func(http.HandlerFunc) http.HandlerFunc) {
	r.Get("/login", h.selectAccount)
	r.Post("/login", issuerWrap(h.doLogin))
	r.Get("/consent", h.consentPage)
	r.Post("/consent", issuerWrap(h.doConsent))
}

func (h *Handler) selectAccount(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	users, _ := h.store.DB().ListUsers()
	h.render.HTML(w, http.StatusOK, "select_account", map[string]any{
		"Title":         "Sign in",
		"AuthRequestID": id,
		"Users":         users,
	})
}

func (h *Handler) doLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("authRequestID")
	userID := r.FormValue("userID")

	req, err := h.store.AuthRequestByID(r.Context(), id)
	if err != nil {
		http.Error(w, "auth request not found", http.StatusBadRequest)
		return
	}
	client, err := h.store.DB().GetClient(req.GetClientID())
	if err != nil {
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	if client.RequireConsent {
		// Record the user, then route through the consent screen.
		if err := h.store.SetAuthRequestUser(id, userID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/consent?authRequestID="+id, http.StatusFound)
		return
	}

	if err := h.store.CompleteAuthRequest(id, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.callback(r.Context(), id), http.StatusFound)
}

func (h *Handler) consentPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	req, err := h.store.AuthRequestByID(r.Context(), id)
	if err != nil {
		http.Error(w, "auth request not found", http.StatusBadRequest)
		return
	}
	username := req.GetSubject()
	if u, err := h.store.DB().GetUser(req.GetSubject()); err == nil {
		username = u.Username
	}
	h.render.HTML(w, http.StatusOK, "consent", map[string]any{
		"Title":         "Authorize",
		"AuthRequestID": id,
		"ClientID":      req.GetClientID(),
		"Username":      username,
		"Scopes":        req.GetScopes(),
	})
}

func (h *Handler) doConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("authRequestID")
	req, err := h.store.AuthRequestByID(r.Context(), id)
	if err != nil {
		http.Error(w, "auth request not found", http.StatusBadRequest)
		return
	}
	if r.FormValue("action") != "allow" {
		_ = h.store.DeleteAuthRequest(r.Context(), id)
		h.render.HTML(w, http.StatusOK, "message", map[string]any{
			"Title": "Denied", "Heading": "Access denied",
			"Body": "You denied the authorization request.",
		})
		return
	}
	if err := h.store.CompleteAuthRequest(id, req.GetSubject()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.callback(r.Context(), id), http.StatusFound)
}
