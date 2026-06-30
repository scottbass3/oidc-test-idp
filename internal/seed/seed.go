// Package seed populates the database on first boot, either from a YAML/JSON
// seed file or from a built-in default set of users and clients.
package seed

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// File is the on-disk seed schema (YAML or JSON).
type File struct {
	Users   []UserSeed   `yaml:"users" json:"users"`
	Clients []ClientSeed `yaml:"clients" json:"clients"`
}

// UserSeed describes a seeded login account.
type UserSeed struct {
	ID                string                         `yaml:"id" json:"id"`
	Username          string                         `yaml:"username" json:"username"`
	Email             string                         `yaml:"email" json:"email"`
	EmailVerified     *bool                          `yaml:"email_verified" json:"email_verified"`
	Phone             string                         `yaml:"phone" json:"phone"`
	FirstName         string                         `yaml:"first_name" json:"first_name"`
	LastName          string                         `yaml:"last_name" json:"last_name"`
	PreferredLanguage string                         `yaml:"preferred_language" json:"preferred_language"`
	Claims            map[string]any                 `yaml:"claims" json:"claims"`
	ConditionalClaims []storage.ConditionalClaimRule `yaml:"conditional_claims" json:"conditional_claims"`
	ACR               string                         `yaml:"acr" json:"acr"`
	AMR               []string                       `yaml:"amr" json:"amr"`
}

// ClientSeed describes a seeded OAuth/OIDC client.
type ClientSeed struct {
	ID                string         `yaml:"id" json:"id"`
	Secret            string         `yaml:"secret" json:"secret"`
	RedirectURIs      []string       `yaml:"redirect_uris" json:"redirect_uris"`
	PostLogout        []string       `yaml:"post_logout_redirect_uris" json:"post_logout_redirect_uris"`
	AuthMethod        string         `yaml:"auth_method" json:"auth_method"`
	ResponseTypes     []string       `yaml:"response_types" json:"response_types"`
	GrantTypes        []string       `yaml:"grant_types" json:"grant_types"`
	AccessTokenType   string         `yaml:"access_token_type" json:"access_token_type"` // "jwt" or "opaque"
	DevMode           *bool          `yaml:"dev_mode" json:"dev_mode"`
	RequireConsent    bool           `yaml:"require_consent" json:"require_consent"`
	CustomClaims      map[string]any `yaml:"custom_claims" json:"custom_claims"`
	AccessTokenTTLSec int            `yaml:"access_token_ttl_seconds" json:"access_token_ttl_seconds"`
	JWKS              string         `yaml:"jwks" json:"jwks"` // public JWKS JSON for private_key_jwt
	IDTokenSignAlg    string         `yaml:"id_token_sign_alg" json:"id_token_sign_alg"`
}

// ApplyIfEmpty seeds the database when it has no clients and no users. If path is
// set the seed is read from that file; otherwise the built-in default is used.
func ApplyIfEmpty(db *storage.DB, path string) error {
	clients, users, err := db.CountConfig()
	if err != nil {
		return err
	}
	if clients > 0 || users > 0 {
		return nil
	}

	seed := defaultSeed()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read seed file: %w", err)
		}
		seed = &File{}
		if err := yaml.Unmarshal(b, seed); err != nil {
			return fmt.Errorf("parse seed file: %w", err)
		}
	}
	return apply(db, seed)
}

func apply(db *storage.DB, seed *File) error {
	for _, u := range seed.Users {
		id := u.ID
		if id == "" {
			id = uuid.NewString()
		}
		emailVerified := true
		if u.EmailVerified != nil {
			emailVerified = *u.EmailVerified
		}
		if err := db.SaveUser(&storage.User{
			ID:                id,
			Username:          u.Username,
			Email:             u.Email,
			EmailVerified:     emailVerified,
			Phone:             u.Phone,
			FirstName:         u.FirstName,
			LastName:          u.LastName,
			PreferredLanguage: orDefault(u.PreferredLanguage, "en"),
			Claims:            u.Claims,
			ConditionalClaims: u.ConditionalClaims,
			ACR:               u.ACR,
			AMR:               u.AMR,
		}); err != nil {
			return err
		}
	}
	for _, c := range seed.Clients {
		if err := db.SaveClient(clientFromSeed(c)); err != nil {
			return err
		}
	}
	return nil
}

func clientFromSeed(c ClientSeed) *storage.Client {
	devMode := true
	if c.DevMode != nil {
		devMode = *c.DevMode
	}
	atType := op.AccessTokenTypeBearer
	if c.AccessTokenType == "jwt" {
		atType = op.AccessTokenTypeJWT
	}
	atTTL := 300
	if c.AccessTokenTTLSec > 0 {
		atTTL = c.AccessTokenTTLSec
	}
	responseTypes := []oidc.ResponseType{oidc.ResponseTypeCode}
	if len(c.ResponseTypes) > 0 {
		responseTypes = nil
		for _, rt := range c.ResponseTypes {
			responseTypes = append(responseTypes, oidc.ResponseType(rt))
		}
	}
	grantTypes := []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
	if len(c.GrantTypes) > 0 {
		grantTypes = nil
		for _, gt := range c.GrantTypes {
			grantTypes = append(grantTypes, oidc.GrantType(gt))
		}
	}
	authMethod := oidc.AuthMethodBasic
	if c.AuthMethod != "" {
		authMethod = oidc.AuthMethod(c.AuthMethod)
	} else if c.Secret == "" {
		authMethod = oidc.AuthMethodNone
	}
	return &storage.Client{
		ID:                        c.ID,
		Secret:                    c.Secret,
		RedirectURIList:           c.RedirectURIs,
		PostLogoutRedirectURIList: c.PostLogout,
		RedirectURIGlobList:       c.RedirectURIs,
		AuthMethodValue:           authMethod,
		ResponseTypeList:          responseTypes,
		GrantTypeList:             grantTypes,
		AccessTokenTypeValue:      atType,
		DevModeFlag:               devMode,
		RequireConsent:            c.RequireConsent,
		CustomClaims:              c.CustomClaims,
		AccessTokenLifetime:       time.Duration(atTTL) * time.Second,
		RefreshTokenLifetime:      5 * time.Hour,
		IDTokenLifetimeDuration:   time.Hour,
		JWKS:                      c.JWKS,
		IDTokenSignAlg:            c.IDTokenSignAlg,
	}
}

func defaultSeed() *File {
	t := true
	return &File{
		Users: []UserSeed{
			{ID: "user-alice", Username: "alice", Email: "alice@example.com",
				EmailVerified: &t, FirstName: "Alice", LastName: "Anderson",
				Claims: map[string]any{"role": "admin", "groups": []string{"admins", "users"}},
				ConditionalClaims: []storage.ConditionalClaimRule{
					{ClientID: "web-app", Claims: map[string]any{"tenant": "acme"}},
					{Scopes: []string{"profile"}, Claims: map[string]any{"department": "engineering"}},
				},
				ACR: "urn:mace:incommon:iap:silver", AMR: []string{"pwd", "mfa"}},
			{ID: "user-bob", Username: "bob", Email: "bob@example.com",
				EmailVerified: &t, FirstName: "Bob", LastName: "Brown",
				Claims: map[string]any{"role": "user", "groups": []string{"users"}}},
		},
		Clients: []ClientSeed{
			{
				ID: "web-app", Secret: "web-secret",
				RedirectURIs: []string{
					"http://localhost:8080/callback", "http://localhost:8080/auth/callback",
					"http://localhost:8088/callback", "http://localhost:8088/auth/callback",
				},
				AuthMethod:      string(oidc.AuthMethodBasic),
				ResponseTypes:   []string{"code"},
				GrantTypes:      []string{"authorization_code", "refresh_token"},
				AccessTokenType: "jwt",
			},
			{
				ID:              "spa-app",
				RedirectURIs:    []string{"http://localhost:3000/callback"},
				AuthMethod:      string(oidc.AuthMethodNone),
				ResponseTypes:   []string{"code"},
				GrantTypes:      []string{"authorization_code", "refresh_token"},
				AccessTokenType: "jwt",
			},
			{
				ID:              "service-app",
				Secret:          "service-secret",
				AuthMethod:      string(oidc.AuthMethodBasic),
				GrantTypes:      []string{"client_credentials"},
				AccessTokenType: "jwt",
			},
			{
				ID:         "device-app",
				Secret:     "device-secret",
				AuthMethod: string(oidc.AuthMethodBasic),
				GrantTypes: []string{string(oidc.GrantTypeDeviceCode)},
			},
			{
				ID:              "ropc-app",
				Secret:          "ropc-secret",
				AuthMethod:      string(oidc.AuthMethodBasic),
				GrantTypes:      []string{"password", "refresh_token"},
				AccessTokenType: "jwt",
			},
		},
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
