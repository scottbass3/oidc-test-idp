// Command idp runs the single-container OAuth2/OIDC test identity provider.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/scottbass3/oidc-test-idp/internal/config"
	"github.com/scottbass3/oidc-test-idp/internal/seed"
	"github.com/scottbass3/oidc-test-idp/internal/server"
	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local discovery endpoint and exit (for container healthchecks)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(1)
	}

	if *healthcheck {
		os.Exit(runHealthcheck(cfg.Addr))
	}

	if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			logger.Error("create db dir", "err", err)
			os.Exit(1)
		}
	}

	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		logger.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := seed.ApplyIfEmpty(db, cfg.SeedPath); err != nil {
		logger.Error("seed", "err", err)
		os.Exit(1)
	}

	store, err := storage.NewStorage(db)
	if err != nil {
		logger.Error("storage", "err", err)
		os.Exit(1)
	}

	handler, err := server.New(store, logger, server.Options{
		Issuer:        cfg.Issuer,
		AllowInsecure: cfg.AllowInsecure,
	})
	if err != nil {
		logger.Error("server", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("idp listening", "addr", cfg.Addr, "issuer", cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	logger.Info("idp stopped")
}

// runHealthcheck probes the discovery endpoint on the loopback interface using
// the configured listen port. Returns a process exit code.
func runHealthcheck(addr string) int {
	host := "127.0.0.1" + addr
	if len(addr) > 0 && addr[0] != ':' {
		host = addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + host + "/.well-known/openid-configuration")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
