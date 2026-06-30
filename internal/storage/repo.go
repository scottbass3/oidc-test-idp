package storage

import (
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")

const clientColumns = `id, secret, redirect_uris, post_logout_redirect_uris, application_type,
	auth_method, response_types, grant_types, access_token_type, dev_mode,
	id_token_userinfo_claims_assertion, clock_skew_seconds, access_token_lifetime_seconds,
	id_token_lifetime_seconds, refresh_token_lifetime_seconds, redirect_uri_globs,
	post_logout_redirect_uri_globs, require_consent, custom_claims, force_error, latency_ms, jwks`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var (
		c                                                          Client
		redirectURIs, postLogout, responseTypes, grantTypes        string
		redirectGlobs, postLogoutGlobs, customClaims               string
		appType, accessTokenType, devMode, idTokenAssert           int
		clockSkew, atLife, idLife, rtLife, requireConsent, latency int
		authMethod, forceError, jwks                               string
	)
	if err := row.Scan(
		&c.ID, &c.Secret, &redirectURIs, &postLogout, &appType,
		&authMethod, &responseTypes, &grantTypes, &accessTokenType, &devMode,
		&idTokenAssert, &clockSkew, &atLife, &idLife, &rtLife, &redirectGlobs,
		&postLogoutGlobs, &requireConsent, &customClaims, &forceError, &latency, &jwks,
	); err != nil {
		return nil, err
	}
	c.JWKS = jwks
	c.RedirectURIList = jsonStrings(redirectURIs)
	c.PostLogoutRedirectURIList = jsonStrings(postLogout)
	c.RedirectURIGlobList = jsonStrings(redirectGlobs)
	c.PostLogoutRedirectGlobList = jsonStrings(postLogoutGlobs)
	c.AppType = op.ApplicationType(appType)
	c.AuthMethodValue = oidc.AuthMethod(authMethod)
	for _, rt := range jsonStrings(responseTypes) {
		c.ResponseTypeList = append(c.ResponseTypeList, oidc.ResponseType(rt))
	}
	for _, gt := range jsonStrings(grantTypes) {
		c.GrantTypeList = append(c.GrantTypeList, oidc.GrantType(gt))
	}
	c.AccessTokenTypeValue = op.AccessTokenType(accessTokenType)
	c.DevModeFlag = devMode != 0
	c.IDTokenUserinfoClaimsAssert = idTokenAssert != 0
	c.ClockSkewDuration = time.Duration(clockSkew) * time.Second
	c.AccessTokenLifetime = time.Duration(atLife) * time.Second
	c.IDTokenLifetimeDuration = time.Duration(idLife) * time.Second
	c.RefreshTokenLifetime = time.Duration(rtLife) * time.Second
	c.RequireConsent = requireConsent != 0
	c.CustomClaims = jsonObject(customClaims)
	c.ForceError = forceError
	c.LatencyMS = latency
	return &c, nil
}

// GetClient returns a client by id.
func (db *DB) GetClient(id string) (*Client, error) {
	row := db.conn.QueryRow(`SELECT `+clientColumns+` FROM clients WHERE id = ?`, id)
	c, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListClients returns all clients ordered by id.
func (db *DB) ListClients() ([]*Client, error) {
	rows, err := db.conn.Query(`SELECT ` + clientColumns + ` FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveClient inserts or replaces a client.
func (db *DB) SaveClient(c *Client) error {
	responseTypes := make([]string, 0, len(c.ResponseTypeList))
	for _, rt := range c.ResponseTypeList {
		responseTypes = append(responseTypes, string(rt))
	}
	grantTypes := make([]string, 0, len(c.GrantTypeList))
	for _, gt := range c.GrantTypeList {
		grantTypes = append(grantTypes, string(gt))
	}
	_, err := db.conn.Exec(`
		INSERT INTO clients (`+clientColumns+`, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
		ON CONFLICT(id) DO UPDATE SET
			secret=excluded.secret, redirect_uris=excluded.redirect_uris,
			post_logout_redirect_uris=excluded.post_logout_redirect_uris,
			application_type=excluded.application_type, auth_method=excluded.auth_method,
			response_types=excluded.response_types, grant_types=excluded.grant_types,
			access_token_type=excluded.access_token_type, dev_mode=excluded.dev_mode,
			id_token_userinfo_claims_assertion=excluded.id_token_userinfo_claims_assertion,
			clock_skew_seconds=excluded.clock_skew_seconds,
			access_token_lifetime_seconds=excluded.access_token_lifetime_seconds,
			id_token_lifetime_seconds=excluded.id_token_lifetime_seconds,
			refresh_token_lifetime_seconds=excluded.refresh_token_lifetime_seconds,
			redirect_uri_globs=excluded.redirect_uri_globs,
			post_logout_redirect_uri_globs=excluded.post_logout_redirect_uri_globs,
			require_consent=excluded.require_consent, custom_claims=excluded.custom_claims,
			force_error=excluded.force_error, latency_ms=excluded.latency_ms, jwks=excluded.jwks,
			updated_at=datetime('now')`,
		c.ID, c.Secret, jsonMarshal(c.RedirectURIList), jsonMarshal(c.PostLogoutRedirectURIList),
		int(c.AppType), string(c.AuthMethodValue), jsonMarshal(responseTypes), jsonMarshal(grantTypes),
		int(c.AccessTokenTypeValue), boolInt(c.DevModeFlag), boolInt(c.IDTokenUserinfoClaimsAssert),
		int(c.ClockSkewDuration.Seconds()), int(c.AccessTokenLifetime.Seconds()),
		int(c.IDTokenLifetimeDuration.Seconds()), int(c.RefreshTokenLifetime.Seconds()),
		jsonMarshal(c.RedirectURIGlobList), jsonMarshal(c.PostLogoutRedirectGlobList),
		boolInt(c.RequireConsent), jsonMarshal(c.CustomClaims), c.ForceError, c.LatencyMS,
		orJSONEmpty(c.JWKS),
	)
	return err
}

// DeleteClient removes a client by id.
func (db *DB) DeleteClient(id string) error {
	_, err := db.conn.Exec(`DELETE FROM clients WHERE id = ?`, id)
	return err
}

// --- Users ----------------------------------------------------------------

const userColumns = `id, username, email, email_verified, phone, phone_verified,
	first_name, last_name, preferred_language, is_admin, claims`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var (
		u                            User
		emailVerified, phoneVerified int
		isAdmin                      int
		claims                       string
	)
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &emailVerified, &u.Phone,
		&phoneVerified, &u.FirstName, &u.LastName, &u.PreferredLanguage, &isAdmin, &claims); err != nil {
		return nil, err
	}
	u.EmailVerified = emailVerified != 0
	u.PhoneVerified = phoneVerified != 0
	u.IsAdmin = isAdmin != 0
	u.Claims = jsonObject(claims)
	return &u, nil
}

// GetUser returns a user by id.
func (db *DB) GetUser(id string) (*User, error) {
	row := db.conn.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUserByUsername returns a user by username.
func (db *DB) GetUserByUsername(username string) (*User, error) {
	row := db.conn.QueryRow(`SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// ListUsers returns all users ordered by username.
func (db *DB) ListUsers() ([]*User, error) {
	rows, err := db.conn.Query(`SELECT ` + userColumns + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SaveUser inserts or replaces a user.
func (db *DB) SaveUser(u *User) error {
	_, err := db.conn.Exec(`
		INSERT INTO users (`+userColumns+`, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
		ON CONFLICT(id) DO UPDATE SET
			username=excluded.username, email=excluded.email,
			email_verified=excluded.email_verified, phone=excluded.phone,
			phone_verified=excluded.phone_verified, first_name=excluded.first_name,
			last_name=excluded.last_name, preferred_language=excluded.preferred_language,
			is_admin=excluded.is_admin, claims=excluded.claims, updated_at=datetime('now')`,
		u.ID, u.Username, u.Email, boolInt(u.EmailVerified), u.Phone, boolInt(u.PhoneVerified),
		u.FirstName, u.LastName, u.PreferredLanguage, boolInt(u.IsAdmin), jsonMarshal(u.Claims),
	)
	return err
}

// DeleteUser removes a user by id.
func (db *DB) DeleteUser(id string) error {
	_, err := db.conn.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// CountConfig returns the number of clients and users (used to decide seeding).
func (db *DB) CountConfig() (clients int, users int, err error) {
	if err = db.conn.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&clients); err != nil {
		return
	}
	err = db.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
	return
}

// --- Settings -------------------------------------------------------------

// GetSetting returns a setting value, or def when absent.
func (db *DB) GetSetting(key, def string) string {
	var v string
	if err := db.conn.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

// SetSetting upserts a setting value.
func (db *DB) SetSetting(key, value string) error {
	_, err := db.conn.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func orJSONEmpty(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
