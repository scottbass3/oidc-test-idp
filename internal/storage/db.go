// Package storage implements the zitadel/oidc op.Storage interface on top of a
// SQLite database, plus the repository helpers used by the admin UI and seeder.
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)

	"github.com/scottbass3/oidc-test-idp/migrations"
)

// DB wraps the SQL connection and exposes the storage operations.
type DB struct {
	conn *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies all
// embedded migrations. WAL mode and a busy timeout keep concurrent admin writes
// and protocol reads from tripping over each other.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite single-writer; serialize to avoid SQLITE_BUSY
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

// Close closes the underlying connection.
func (db *DB) Close() error { return db.conn.Close() }

func (db *DB) migrate() error {
	if _, err := db.conn.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`,
	); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > 4 && e.Name()[len(e.Name())-4:] == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var applied int
		if err := db.conn.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}
		b, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := db.conn.Exec(string(b)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := db.conn.Exec(`INSERT INTO schema_migrations (name) VALUES (?)`, name); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}
	return nil
}

// --- JSON column helpers -------------------------------------------------

func jsonMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func jsonStrings(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func jsonObject(s string) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}
