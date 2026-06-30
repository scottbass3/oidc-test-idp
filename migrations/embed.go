// Package migrations embeds the SQL schema files applied at startup.
package migrations

import "embed"

// FS holds the ordered .sql migration files.
//
//go:embed *.sql
var FS embed.FS
