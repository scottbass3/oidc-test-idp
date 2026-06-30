// Package admin implements the server-rendered administration UI for managing
// users, clients and viewing settings. All changes persist live to SQLite.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/scottbass3/oidc-test-idp/internal/render"
	"github.com/scottbass3/oidc-test-idp/internal/reqlog"
	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// Handler serves the admin UI.
type Handler struct {
	store    *storage.Storage
	render   *render.Renderer
	issuer   string
	keyID    string
	user     string
	password string
	reqlog   *reqlog.Log
}

// New builds the admin handler.
func New(store *storage.Storage, r *render.Renderer, issuer, keyID, user, password string, rlog *reqlog.Log) *Handler {
	return &Handler{store: store, render: r, issuer: issuer, keyID: keyID, user: user, password: password, reqlog: rlog}
}

// Routes mounts the admin endpoints behind HTTP Basic auth.
func (h *Handler) Routes(r chi.Router) {
	r.Use(h.basicAuth)
	r.Get("/", h.dashboard)
	r.Get("/users", h.users)
	r.Post("/users", h.saveUser)
	r.Post("/users/{id}/delete", h.deleteUser)
	r.Get("/clients", h.clients)
	r.Post("/clients", h.saveClient)
	r.Post("/clients/{id}/delete", h.deleteClient)
	r.Get("/keys", h.keys)
	r.Post("/keys/rotate", h.rotateKey)
	r.Get("/logs", h.logs)
	r.Get("/settings", h.settings)
	r.Post("/settings", h.saveSettings)
}

func (h *Handler) logs(w http.ResponseWriter, r *http.Request) {
	var entries []reqlog.Entry
	if h.reqlog != nil {
		entries = h.reqlog.Entries()
	}
	h.render.HTML(w, http.StatusOK, "admin_logs", map[string]any{
		"Title": "Logs", "Entries": entries,
	})
}

func (h *Handler) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(h.user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(h.password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="idp-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	clients, users, _ := h.store.DB().CountConfig()
	h.render.HTML(w, http.StatusOK, "admin_dashboard", map[string]any{
		"Title": "Admin", "Users": users, "Clients": clients, "Issuer": h.issuer,
	})
}

// DiscoveryOverrideKey is the settings key holding the JSON object merged into
// the generated discovery document.
const DiscoveryOverrideKey = "discovery_override"

func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	h.renderSettings(w, http.StatusOK, "")
}

func (h *Handler) renderSettings(w http.ResponseWriter, status int, msg string) {
	override := h.store.DB().GetSetting(DiscoveryOverrideKey, "{}")
	h.render.HTML(w, status, "admin_settings", map[string]any{
		"Title": "Settings", "Issuer": h.issuer, "KeyID": h.keyID,
		"DiscoveryOverride": override, "Error": msg,
	})
}

func (h *Handler) saveSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.FormValue("discovery_override"))
	if raw == "" {
		raw = "{}"
	}
	// Validate it parses as a JSON object before persisting.
	var probe map[string]any
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		h.renderSettings(w, http.StatusBadRequest, "Invalid discovery override JSON: "+err.Error())
		return
	}
	if err := h.store.DB().SetSetting(DiscoveryOverrideKey, raw); err != nil {
		h.renderSettings(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// --- Keys -----------------------------------------------------------------

func (h *Handler) keys(w http.ResponseWriter, r *http.Request) {
	h.renderKeys(w, http.StatusOK, "")
}

func (h *Handler) renderKeys(w http.ResponseWriter, status int, msg string) {
	keys, _ := h.store.DB().ListKeys()
	current := ""
	if k, err := h.store.SigningKey(context.Background()); err == nil {
		current = k.ID()
	}
	h.render.HTML(w, status, "admin_keys", map[string]any{
		"Title": "Keys", "Keys": keys, "Current": current, "Notice": msg,
		"Algorithms": storage.SupportedSignatureAlgorithms,
	})
}

func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	alg := jose.SignatureAlgorithm(r.FormValue("alg"))
	if alg == "" {
		alg = jose.RS256
	}
	if !storage.IsSupportedAlg(alg) {
		h.renderKeys(w, http.StatusBadRequest, "Unsupported algorithm: "+string(alg))
		return
	}
	if _, err := h.store.RotateSigningKey(alg); err != nil {
		h.renderKeys(w, http.StatusInternalServerError, "Rotation failed: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/keys", http.StatusSeeOther)
}

// --- Users ----------------------------------------------------------------

func (h *Handler) users(w http.ResponseWriter, r *http.Request) {
	users, _ := h.store.DB().ListUsers()
	data := map[string]any{"Title": "Users", "Users": users, "ClaimsJSON": "{}", "ConditionalJSON": "[]", "AMRStr": ""}
	if id := r.URL.Query().Get("edit"); id != "" {
		if u, err := h.store.DB().GetUser(id); err == nil {
			data["Edit"] = u
			data["ClaimsJSON"] = prettyJSON(u.Claims)
			data["AMRStr"] = strings.Join(u.AMR, ", ")
			if len(u.ConditionalClaims) > 0 {
				data["ConditionalJSON"] = prettyJSON(u.ConditionalClaims)
			}
		}
	}
	h.render.HTML(w, http.StatusOK, "admin_users", data)
}

func (h *Handler) saveUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	claims := map[string]any{}
	if raw := strings.TrimSpace(r.FormValue("claims")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &claims); err != nil {
			h.usersError(w, "Invalid claims JSON: "+err.Error())
			return
		}
	}
	var conditional []storage.ConditionalClaimRule
	if raw := strings.TrimSpace(r.FormValue("conditional_claims")); raw != "" && raw != "[]" {
		if err := json.Unmarshal([]byte(raw), &conditional); err != nil {
			h.usersError(w, "Invalid conditional claims JSON: "+err.Error())
			return
		}
	}
	id := r.FormValue("id")
	if id == "" {
		id = uuid.NewString()
	}
	u := &storage.User{
		ID:                id,
		Subject:           strings.TrimSpace(r.FormValue("subject")),
		Username:          r.FormValue("username"),
		Email:             r.FormValue("email"),
		EmailVerified:     r.FormValue("email_verified") != "",
		Phone:             r.FormValue("phone"),
		FirstName:         r.FormValue("first_name"),
		LastName:          r.FormValue("last_name"),
		PreferredLanguage: orDefault(r.FormValue("preferred_language"), "en"),
		Claims:            claims,
		ConditionalClaims: conditional,
		ACR:               strings.TrimSpace(r.FormValue("acr")),
		AMR:               splitCommaSpace(r.FormValue("amr")),
	}
	if err := h.store.DB().SaveUser(u); err != nil {
		h.usersError(w, err.Error())
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *Handler) usersError(w http.ResponseWriter, msg string) {
	users, _ := h.store.DB().ListUsers()
	h.render.HTML(w, http.StatusBadRequest, "admin_users", map[string]any{
		"Title": "Users", "Users": users, "Error": msg, "ClaimsJSON": "{}", "ConditionalJSON": "[]", "AMRStr": "",
	})
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	_ = h.store.DB().DeleteUser(chi.URLParam(r, "id"))
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- Clients --------------------------------------------------------------

func (h *Handler) clients(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.store.DB().ListClients()
	data := map[string]any{
		"Title": "Clients", "Clients": clients,
		"AuthMethods":  authMethods(),
		"RedirectURIs": "", "PostLogout": "",
		"ResponseTypes": "code", "GrantTypes": "authorization_code,refresh_token",
		"ATTTL": 300, "RTTTL": 18000, "IDTTL": 3600,
		"CustomClaimsJSON": "{}", "JWKS": "",
	}
	if id := r.URL.Query().Get("edit"); id != "" {
		if c, err := h.store.DB().GetClient(id); err == nil {
			data["Edit"] = c
			data["RedirectURIs"] = strings.Join(c.RedirectURIList, "\n")
			data["PostLogout"] = strings.Join(c.PostLogoutRedirectURIList, "\n")
			data["ResponseTypes"] = joinResponseTypes(c.ResponseTypeList)
			data["GrantTypes"] = joinGrantTypes(c.GrantTypeList)
			data["ATTTL"] = int(c.AccessTokenLifetime.Seconds())
			data["RTTTL"] = int(c.RefreshTokenLifetime.Seconds())
			data["IDTTL"] = int(c.IDTokenLifetimeDuration.Seconds())
			data["CustomClaimsJSON"] = prettyJSON(c.CustomClaims)
			data["JWKS"] = c.JWKS
		}
	}
	h.render.HTML(w, http.StatusOK, "admin_clients", data)
}

func (h *Handler) saveClient(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	customClaims := map[string]any{}
	if raw := strings.TrimSpace(r.FormValue("custom_claims")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &customClaims); err != nil {
			h.clientsError(w, "Invalid custom claims JSON: "+err.Error())
			return
		}
	}
	id := r.FormValue("id")
	if id == "" {
		h.clientsError(w, "Client ID is required")
		return
	}
	// If the id was changed during edit, remove the old record.
	if orig := r.FormValue("orig_id"); orig != "" && orig != id {
		_ = h.store.DB().DeleteClient(orig)
	}

	c := &storage.Client{
		ID:                        id,
		Secret:                    r.FormValue("secret"),
		RedirectURIList:           splitLines(r.FormValue("redirect_uris")),
		PostLogoutRedirectURIList: splitLines(r.FormValue("post_logout")),
		AuthMethodValue:           oidc.AuthMethod(orDefault(r.FormValue("auth_method"), string(oidc.AuthMethodNone))),
		AccessTokenTypeValue:      op.AccessTokenType(atoi(r.FormValue("access_token_type"), 0)),
		ResponseTypeList:          parseResponseTypes(r.FormValue("response_types")),
		GrantTypeList:             parseGrantTypes(r.FormValue("grant_types")),
		AccessTokenLifetime:       time.Duration(atoi(r.FormValue("at_ttl"), 300)) * time.Second,
		RefreshTokenLifetime:      time.Duration(atoi(r.FormValue("rt_ttl"), 18000)) * time.Second,
		IDTokenLifetimeDuration:   time.Duration(atoi(r.FormValue("id_ttl"), 3600)) * time.Second,
		DevModeFlag:               r.FormValue("dev_mode") != "",
		RequireConsent:            r.FormValue("require_consent") != "",
		CustomClaims:              customClaims,
		ForceError:                strings.TrimSpace(r.FormValue("force_error")),
		LatencyMS:                 atoi(r.FormValue("latency_ms"), 0),
		RedirectURIGlobList:       splitLines(r.FormValue("redirect_uris")),
		JWKS:                      strings.TrimSpace(r.FormValue("jwks")),
		IDTokenSignAlg:            strings.TrimSpace(r.FormValue("id_token_sign_alg")),
	}
	if c.IDTokenSignAlg != "" && !storage.IsSupportedAlg(jose.SignatureAlgorithm(c.IDTokenSignAlg)) {
		h.clientsError(w, "Unsupported signing algorithm: "+c.IDTokenSignAlg)
		return
	}
	if c.JWKS != "" && c.JWKS != "{}" {
		var probe map[string]any
		if err := json.Unmarshal([]byte(c.JWKS), &probe); err != nil {
			h.clientsError(w, "Invalid client JWKS JSON: "+err.Error())
			return
		}
	}
	if err := h.store.DB().SaveClient(c); err != nil {
		h.clientsError(w, err.Error())
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

func (h *Handler) clientsError(w http.ResponseWriter, msg string) {
	clients, _ := h.store.DB().ListClients()
	h.render.HTML(w, http.StatusBadRequest, "admin_clients", map[string]any{
		"Title": "Clients", "Clients": clients, "Error": msg,
		"AuthMethods": authMethods(), "RedirectURIs": "", "PostLogout": "",
		"ResponseTypes": "code", "GrantTypes": "authorization_code,refresh_token",
		"ATTTL": 300, "RTTTL": 18000, "IDTTL": 3600, "CustomClaimsJSON": "{}", "JWKS": "",
	})
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
	_ = h.store.DB().DeleteClient(chi.URLParam(r, "id"))
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

// --- helpers --------------------------------------------------------------

func authMethods() []oidc.AuthMethod {
	return []oidc.AuthMethod{
		oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodPrivateKeyJWT,
	}
}

// splitCommaSpace splits on commas and/or whitespace, dropping empties.
func splitCommaSpace(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseResponseTypes(s string) []oidc.ResponseType {
	var out []oidc.ResponseType
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(strings.Trim(p, `"`)); t != "" {
			out = append(out, oidc.ResponseType(t))
		}
	}
	if len(out) == 0 {
		out = []oidc.ResponseType{oidc.ResponseTypeCode}
	}
	return out
}

func parseGrantTypes(s string) []oidc.GrantType {
	var out []oidc.GrantType
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, oidc.GrantType(t))
		}
	}
	if len(out) == 0 {
		out = []oidc.GrantType{oidc.GrantTypeCode}
	}
	return out
}

func joinResponseTypes(rts []oidc.ResponseType) string {
	parts := make([]string, len(rts))
	for i, rt := range rts {
		if strings.Contains(string(rt), " ") {
			parts[i] = `"` + string(rt) + `"`
		} else {
			parts[i] = string(rt)
		}
	}
	return strings.Join(parts, ",")
}

func joinGrantTypes(gts []oidc.GrantType) string {
	parts := make([]string, len(gts))
	for i, gt := range gts {
		parts[i] = string(gt)
	}
	return strings.Join(parts, ",")
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func atoi(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
