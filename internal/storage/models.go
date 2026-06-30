package storage

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Client is the persistent model of an OAuth/OIDC client. It implements op.Client.
// Field names avoid colliding with the op.Client method names.
type Client struct {
	ID                          string
	Secret                      string
	RedirectURIList             []string
	PostLogoutRedirectURIList   []string
	AppType                     op.ApplicationType
	AuthMethodValue             oidc.AuthMethod
	ResponseTypeList            []oidc.ResponseType
	GrantTypeList               []oidc.GrantType
	AccessTokenTypeValue        op.AccessTokenType
	DevModeFlag                 bool
	IDTokenUserinfoClaimsAssert bool
	ClockSkewDuration           time.Duration
	AccessTokenLifetime         time.Duration
	IDTokenLifetimeDuration     time.Duration
	RefreshTokenLifetime        time.Duration
	RedirectURIGlobList         []string
	PostLogoutRedirectGlobList  []string

	// Mock behavior knobs.
	RequireConsent bool
	CustomClaims   map[string]any
	ForceError     string
	LatencyMS      int

	// JWKS is the client's public key set (raw JSON) for private_key_jwt auth.
	JWKS string

	// IDTokenSignAlg optionally pins this client's token signing algorithm
	// (e.g. "RS256", "ES256"); empty uses the IdP default key.
	IDTokenSignAlg string
}

// op.Client implementation -------------------------------------------------

func (c *Client) GetID() string                        { return c.ID }
func (c *Client) RedirectURIs() []string               { return c.RedirectURIList }
func (c *Client) PostLogoutRedirectURIs() []string     { return c.PostLogoutRedirectURIList }
func (c *Client) ApplicationType() op.ApplicationType  { return c.AppType }
func (c *Client) AuthMethod() oidc.AuthMethod          { return c.AuthMethodValue }
func (c *Client) ResponseTypes() []oidc.ResponseType   { return c.ResponseTypeList }
func (c *Client) GrantTypes() []oidc.GrantType         { return c.GrantTypeList }
func (c *Client) AccessTokenType() op.AccessTokenType  { return c.AccessTokenTypeValue }
func (c *Client) IDTokenLifetime() time.Duration       { return c.IDTokenLifetimeDuration }
func (c *Client) DevMode() bool                        { return c.DevModeFlag }
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return c.IDTokenUserinfoClaimsAssert }
func (c *Client) ClockSkew() time.Duration             { return c.ClockSkewDuration }

func (c *Client) LoginURL(id string) string {
	return "/login?authRequestID=" + id
}

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed allows any scope; a mock IdP is permissive by design.
func (c *Client) IsScopeAllowed(scope string) bool { return true }

// hasRedirectGlobs wraps a Client to expose wildcard redirect matching, enabled
// only in dev mode (matching the zitadel example behavior).
type hasRedirectGlobs struct {
	*Client
}

func (c hasRedirectGlobs) RedirectURIGlobs() []string {
	return c.RedirectURIGlobList
}

func (c hasRedirectGlobs) PostLogoutRedirectURIGlobs() []string {
	return c.PostLogoutRedirectGlobList
}

// asOPClient returns the client wrapped with glob support when dev mode is on.
func asOPClient(c *Client) op.Client {
	if c.DevModeFlag {
		return hasRedirectGlobs{c}
	}
	return c
}

// User is the persistent model of a login account.
type User struct {
	ID string
	// Subject overrides the sub claim. Empty means use ID.
	Subject           string
	Username          string
	Email             string
	EmailVerified     bool
	Phone             string
	PhoneVerified     bool
	FirstName         string
	LastName          string
	PreferredLanguage string
	IsAdmin           bool
	Claims            map[string]any
	ConditionalClaims []ConditionalClaimRule
	// ACR/AMR asserted into id_tokens for this user (mock step-up / MFA).
	ACR string
	AMR []string
}

// SubjectOrID returns the custom subject if set, otherwise the row id.
func (u *User) SubjectOrID() string {
	if u.Subject != "" {
		return u.Subject
	}
	return u.ID
}

// ConditionalClaimRule contributes extra claims when the requesting client and/or
// the requested scopes match. An empty ClientID matches any client; an empty
// Scopes list matches any request; otherwise every listed scope must be present.
type ConditionalClaimRule struct {
	ClientID string         `json:"client_id,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	Claims   map[string]any `json:"claims"`
}

// EvaluateConditionalClaims returns the merged claims from all rules matching the
// given client and scopes. Later matching rules override earlier ones.
func (u *User) EvaluateConditionalClaims(clientID string, scopes []string) map[string]any {
	if len(u.ConditionalClaims) == 0 {
		return nil
	}
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}
	var out map[string]any
	for _, rule := range u.ConditionalClaims {
		if rule.ClientID != "" && rule.ClientID != clientID {
			continue
		}
		if !hasAllScopes(scopeSet, rule.Scopes) {
			continue
		}
		if out == nil {
			out = map[string]any{}
		}
		for k, v := range rule.Claims {
			out[k] = v
		}
	}
	return out
}

func hasAllScopes(have map[string]struct{}, want []string) bool {
	for _, s := range want {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}
