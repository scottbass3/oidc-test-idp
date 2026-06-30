// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the process-level configuration. Everything that controls how the
// IdP behaves at runtime (clients, users, mock behaviors) lives in the database;
// this struct only covers bootstrapping concerns.
type Config struct {
	// Issuer is the public base URL of the IdP (e.g. http://localhost:9000).
	// It is advertised in the discovery document and used to build endpoint URLs.
	Issuer string

	// Addr is the listen address for the HTTP server.
	Addr string

	// DBPath is the path to the SQLite database file inside the container.
	DBPath string

	// SeedPath is an optional path to a YAML/JSON seed file applied on first boot
	// (when the database is empty).
	SeedPath string

	// AllowInsecure permits an http:// issuer (required for local/test usage).
	AllowInsecure bool
}

// Load reads configuration from the environment, applying sensible defaults for
// a single-container test deployment.
func Load() (*Config, error) {
	c := &Config{
		Issuer:        env("IDP_ISSUER", "http://localhost:9000"),
		Addr:          env("IDP_ADDR", ":9000"),
		DBPath:        env("IDP_DB_PATH", "/data/idp.db"),
		SeedPath:      env("IDP_SEED_PATH", ""),
		AllowInsecure: envBool("IDP_ALLOW_INSECURE", true),
	}
	if c.Issuer == "" {
		return nil, fmt.Errorf("IDP_ISSUER must not be empty")
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}
