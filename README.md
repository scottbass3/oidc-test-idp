# oidc-test-idp

A single-container OAuth2 / OIDC **test** identity provider in Go. Drop it into local
development or CI to mock a real IdP (Keycloak, Auth0, Entra ID, …) without any external
dependency. Authentication is passwordless: pick an account from a list and click **Sign in**.

- **One container, no dependencies** — a static, cgo-free binary plus an embedded SQLite
  database. Configuration persists inside the container (mount a volume to keep it).
- **OIDC and plain OAuth2** — supports Authorization Code + PKCE, Refresh Token, Client
  Credentials, Device Code, Implicit/Hybrid, the legacy Resource Owner Password Credentials
  grant (`grant_type=password`, passwordless) and the introspection / revocation / end-session
  endpoints. Client authentication via `client_secret_basic`, `client_secret_post`, `none`
  (PKCE) and `private_key_jwt` (register the client's public JWKS).
- **Mock real-IdP behavior** — per-client token format (opaque vs JWT), token lifetimes,
  arbitrary custom claims, forced OAuth errors (spec-correct: redirect on authorize, JSON on
  token) and simulated latency. Live **discovery-document overrides** to match a target IdP.
- **Configurable signing** — RS256 or ES256 signing keys; rotate live from the admin UI
  (previous keys stay in JWKS so already-issued tokens keep validating). Pin a **per-client**
  token signing algorithm when one client must match a specific target IdP.
- **Per-user `acr` / `amr`** — assert authentication-context and methods-references claims in
  id_tokens to mock step-up / MFA. Standard `address` claim supported via the `address` scope.
- **Custom `sub`** — pin a user's subject (e.g. `auth0|abc123`) independently of the row id to
  match a target IdP's exact subject value.
- **Live admin UI** — manage users, clients, signing keys (view + rotate), discovery overrides,
  and a recent-requests log from a browser; changes take effect immediately.
- **Seedable** — pre-populate users and clients from a YAML/JSON file on first boot.

## Quick start

```bash
docker compose up --build
```

Then:

- Discovery: <http://localhost:9000/.well-known/openid-configuration>
- Admin UI: <http://localhost:9000/admin> (default credentials `admin` / `admin`)

Or run locally:

```bash
go run ./cmd/idp     # listens on :9000, DB at /data/idp.db
```

The default seed creates two users (`alice`, `bob`) and four clients (`web-app`, `spa-app`,
`service-app`, `device-app`).

## Configuration (environment variables)

| Variable             | Default                   | Description                                     |
| -------------------- | ------------------------- | ----------------------------------------------- |
| `IDP_ISSUER`         | `http://localhost:9000`   | Public issuer URL advertised in discovery.      |
| `IDP_ADDR`           | `:9000`                   | HTTP listen address.                            |
| `IDP_DB_PATH`        | `/data/idp.db`            | SQLite database path inside the container.      |
| `IDP_SEED_PATH`      | _(none)_                  | Seed file applied on first boot (empty DB).     |
| `IDP_ADMIN_USER`     | `admin`                   | Admin UI Basic-auth username.                   |
| `IDP_ADMIN_PASSWORD` | `admin`                   | Admin UI Basic-auth password.                   |
| `IDP_ALLOW_INSECURE` | `true`                    | Allow an `http://` issuer (needed for testing). |

## Endpoints

Standard OIDC paths are served under the issuer root:
`/.well-known/openid-configuration`, `/keys` (JWKS), `/authorize`, `/oauth/token`,
`/userinfo`, `/oauth/introspect`, `/revoke`, `/end_session`, `/device_authorization`.

End-user UI: `/login` (account selection), `/consent`, `/device` (device verification).

## Mocking a target IdP

1. Open the admin UI, create a client matching your application's `client_id` / redirect URIs.
2. Choose the access-token format (opaque or JWT) and lifetimes to match the target.
3. Add custom claims per user (arbitrary JSON) and per client to reproduce the target's token
   shape. For claims that differ by app or scope, add **conditional claims** to a user — a JSON
   array of rules, each matching on `client_id` and/or `scopes` and contributing extra claims
   (e.g. `[{"client_id":"web-app","claims":{"tenant":"acme"}},{"scopes":["profile"],"claims":{"department":"engineering"}}]`).
4. To simulate failures, set a **forced error** (e.g. `invalid_grant`) and/or **latency** on the
   client. On the authorize endpoint the error is returned as a spec-compliant redirect
   (`?error=...&state=...`); on the token endpoint as a JSON error.
5. Under **Settings → Discovery overrides**, paste a JSON object to shallow-merge into
   `/.well-known/openid-configuration` (e.g. restrict `id_token_signing_alg_values_supported`
   or add vendor-specific fields). Under **Keys**, rotate the signing key — previous keys stay
   in JWKS so already-issued tokens keep validating.

## Seeding

Copy [`seed.example.yaml`](seed.example.yaml), edit it, and either set `IDP_SEED_PATH` or mount
it (see `docker-compose.yml`). The seed is applied only when the database is empty.

## Development

```bash
go build ./...
go test ./...
```

`internal/server/server_test.go` drives the Authorization Code + PKCE, refresh and client
credentials flows end-to-end against an in-process instance.

## Architecture

| Package             | Responsibility                                                        |
| ------------------- | --------------------------------------------------------------------- |
| `internal/storage`  | SQLite persistence + implementation of the zitadel/oidc `op.Storage`. |
| `internal/oidc`     | Wires the `op.OpenIDProvider`; adds the ROPC (`password`) grant.      |
| `internal/auth`     | Passwordless account-selection, consent and device verification UI.   |
| `internal/admin`    | Server-rendered admin UI (users, clients, settings).                  |
| `internal/behavior` | Per-client mock behavior + live discovery-override middleware.        |
| `internal/reqlog`   | In-memory ring buffer of recent protocol requests (admin Logs page). |
| `internal/seed`     | First-boot seeding from a file or built-in defaults.                  |
| `internal/server`   | Router assembly tying everything together.                            |

Built on [`github.com/zitadel/oidc`](https://github.com/zitadel/oidc) with a pure-Go SQLite
driver ([`modernc.org/sqlite`](https://modernc.org/sqlite)), so the binary needs no cgo.
