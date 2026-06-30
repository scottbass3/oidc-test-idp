-- Persistent configuration: clients, users, signing keys, global settings.

CREATE TABLE IF NOT EXISTS clients (
    id                                 TEXT PRIMARY KEY,
    secret                             TEXT NOT NULL DEFAULT '',
    redirect_uris                      TEXT NOT NULL DEFAULT '[]',   -- JSON array
    post_logout_redirect_uris          TEXT NOT NULL DEFAULT '[]',   -- JSON array
    application_type                   INTEGER NOT NULL DEFAULT 0,   -- op.ApplicationType
    auth_method                        TEXT NOT NULL DEFAULT 'client_secret_basic',
    response_types                     TEXT NOT NULL DEFAULT '["code"]',
    grant_types                        TEXT NOT NULL DEFAULT '["authorization_code"]',
    access_token_type                  INTEGER NOT NULL DEFAULT 0,   -- 0 Bearer(opaque), 1 JWT
    dev_mode                           INTEGER NOT NULL DEFAULT 1,
    id_token_userinfo_claims_assertion INTEGER NOT NULL DEFAULT 0,
    clock_skew_seconds                 INTEGER NOT NULL DEFAULT 0,
    access_token_lifetime_seconds      INTEGER NOT NULL DEFAULT 300,
    id_token_lifetime_seconds          INTEGER NOT NULL DEFAULT 3600,
    refresh_token_lifetime_seconds     INTEGER NOT NULL DEFAULT 18000,
    redirect_uri_globs                 TEXT NOT NULL DEFAULT '[]',
    post_logout_redirect_uri_globs     TEXT NOT NULL DEFAULT '[]',
    -- Mock behavior overrides (per client).
    require_consent                    INTEGER NOT NULL DEFAULT 0,
    custom_claims                      TEXT NOT NULL DEFAULT '{}',   -- JSON object merged into tokens
    force_error                        TEXT NOT NULL DEFAULT '',     -- forced OAuth error code on token/authorize
    latency_ms                         INTEGER NOT NULL DEFAULT 0,
    created_at                         TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL,
    email              TEXT NOT NULL DEFAULT '',
    email_verified     INTEGER NOT NULL DEFAULT 1,
    phone              TEXT NOT NULL DEFAULT '',
    phone_verified     INTEGER NOT NULL DEFAULT 0,
    first_name         TEXT NOT NULL DEFAULT '',
    last_name          TEXT NOT NULL DEFAULT '',
    preferred_language TEXT NOT NULL DEFAULT 'en',
    is_admin           INTEGER NOT NULL DEFAULT 0,
    claims             TEXT NOT NULL DEFAULT '{}',   -- arbitrary JSON claims
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);

CREATE TABLE IF NOT EXISTS signing_keys (
    id          TEXT PRIMARY KEY,
    algorithm   TEXT NOT NULL,
    private_pem TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Ephemeral OIDC protocol state. Persisted so flows survive container restarts.

CREATE TABLE IF NOT EXISTS auth_requests (
    id            TEXT PRIMARY KEY,
    data          TEXT NOT NULL,                 -- JSON-encoded auth request
    done          INTEGER NOT NULL DEFAULT 0,
    user_id       TEXT NOT NULL DEFAULT '',
    auth_time     TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code            TEXT PRIMARY KEY,
    auth_request_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id               TEXT PRIMARY KEY,
    application_id   TEXT NOT NULL,
    subject          TEXT NOT NULL,
    refresh_token_id TEXT NOT NULL DEFAULT '',
    audience         TEXT NOT NULL DEFAULT '[]',
    scopes           TEXT NOT NULL DEFAULT '[]',
    expiration       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id             TEXT PRIMARY KEY,
    token          TEXT NOT NULL,
    auth_time      TEXT NOT NULL,
    amr            TEXT NOT NULL DEFAULT '[]',
    audience       TEXT NOT NULL DEFAULT '[]',
    user_id        TEXT NOT NULL,
    application_id TEXT NOT NULL,
    expiration     TEXT NOT NULL,
    scopes         TEXT NOT NULL DEFAULT '[]',
    access_token   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code TEXT PRIMARY KEY,
    user_code   TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '[]',
    expires     TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    done        INTEGER NOT NULL DEFAULT 0,
    denied      INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_user_code ON device_codes (user_code);
