// Package server assembles the HTTP router: OIDC protocol endpoints, the
// passwordless login/consent/device UI, the admin UI and static assets.
package server

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	zoidc "github.com/zitadel/oidc/v3/pkg/op"

	"github.com/scottbass3/oidc-test-idp/internal/admin"
	"github.com/scottbass3/oidc-test-idp/internal/auth"
	"github.com/scottbass3/oidc-test-idp/internal/behavior"
	idpoidc "github.com/scottbass3/oidc-test-idp/internal/oidc"
	"github.com/scottbass3/oidc-test-idp/internal/render"
	"github.com/scottbass3/oidc-test-idp/internal/reqlog"
	"github.com/scottbass3/oidc-test-idp/internal/storage"
	"github.com/scottbass3/oidc-test-idp/web"
)

// Options configure the HTTP server build.
type Options struct {
	Issuer        string
	AllowInsecure bool
}

// New builds the root http.Handler.
func New(store *storage.Storage, logger *slog.Logger, opts Options) (http.Handler, error) {
	provider, err := idpoidc.NewProvider(opts.Issuer, store, logger, opts.AllowInsecure)
	if err != nil {
		return nil, err
	}

	r, err := render.New()
	if err != nil {
		return nil, err
	}

	rlog := reqlog.New(200)
	issuerInterceptor := zoidc.NewIssuerInterceptor(provider.IssuerFromRequest)
	authHandler := auth.New(store, r, zoidc.AuthCallbackURL(provider))
	adminHandler := admin.New(store, r, opts.Issuer, signingKeyID(store), rlog)

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)

	// Static assets.
	staticFS, _ := fs.Sub(web.Static, "static")
	router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Default signed-out page.
	router.Get("/logged-out", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Signed out successfully."))
	})

	// Passwordless end-user UI.
	authHandler.Routes(router, issuerInterceptor.HandlerFunc)
	router.Route("/device", authHandler.DeviceRoutes)

	// Administration UI.
	router.Route("/admin", adminHandler.Routes)

	// OIDC protocol endpoints. Middleware order (outermost first): request log →
	// userinfo WWW-Authenticate → discovery overrides → mock behavior → per-client
	// signing algorithm → ROPC interceptor (grant_type=password, not implemented by
	// zitadel) → the OP handler.
	protocol := rlog.Middleware(
		userinfoChallenge(
			behavior.DiscoveryOverride(store)(
				behavior.Middleware(store)(
					idpoidc.SigningAlgMiddleware(store)(
						idpoidc.ROPCMiddleware(provider, store)(
							http.Handler(provider)))))))
	router.Mount("/", protocol)

	return router, nil
}

// userinfoChallenge adds the RFC 6750 WWW-Authenticate header to 401 responses
// on the userinfo endpoint (zitadel omits it).
func userinfoChallenge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/userinfo" {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&bearerChallengeWriter{ResponseWriter: w}, r)
	})
}

type bearerChallengeWriter struct {
	http.ResponseWriter
	wrote bool
}

func (b *bearerChallengeWriter) WriteHeader(code int) {
	if !b.wrote {
		b.wrote = true
		if code == http.StatusUnauthorized && b.Header().Get("WWW-Authenticate") == "" {
			b.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *bearerChallengeWriter) Write(p []byte) (int, error) {
	b.wrote = true
	return b.ResponseWriter.Write(p)
}

func signingKeyID(store *storage.Storage) string {
	if k, err := store.SigningKey(context.Background()); err == nil {
		return k.ID()
	}
	return ""
}
