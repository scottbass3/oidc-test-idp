package storage

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// AuthRequest is the internal representation of an OIDC authorization request.
// It implements op.AuthRequest. The JSON-serializable fields are persisted; the
// derived done/authTime state lives in dedicated columns.
type AuthRequest struct {
	ID            string             `json:"id"`
	CreationDate  time.Time          `json:"creation_date"`
	ApplicationID string             `json:"application_id"`
	CallbackURI   string             `json:"callback_uri"`
	TransferState string             `json:"transfer_state"`
	Prompt        []string           `json:"prompt"`
	UILocales     []language.Tag     `json:"ui_locales"`
	LoginHint     string             `json:"login_hint"`
	MaxAuthAge    *time.Duration     `json:"max_auth_age"`
	UserID        string             `json:"user_id"`
	Scopes        []string           `json:"scopes"`
	ResponseType  oidc.ResponseType  `json:"response_type"`
	ResponseMode  oidc.ResponseMode  `json:"response_mode"`
	Nonce         string             `json:"nonce"`
	CodeChallenge *OIDCCodeChallenge `json:"code_challenge"`
	ACRValue      string             `json:"acr"`
	AMRValues     []string           `json:"amr"`

	done     bool
	authTime time.Time
}

func (a *AuthRequest) GetID() string  { return a.ID }
func (a *AuthRequest) GetACR() string { return a.ACRValue }
func (a *AuthRequest) GetAMR() []string {
	if len(a.AMRValues) > 0 {
		return a.AMRValues
	}
	if a.done {
		return []string{"pwd"}
	}
	return nil
}
func (a *AuthRequest) GetAudience() []string  { return []string{a.ApplicationID} }
func (a *AuthRequest) GetAuthTime() time.Time { return a.authTime }
func (a *AuthRequest) GetClientID() string    { return a.ApplicationID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return codeChallengeToOIDC(a.CodeChallenge)
}
func (a *AuthRequest) GetNonce() string                   { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string             { return a.CallbackURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                { return a.Scopes }
func (a *AuthRequest) GetState() string                   { return a.TransferState }
func (a *AuthRequest) GetSubject() string                 { return a.UserID }
func (a *AuthRequest) Done() bool                         { return a.done }

// OIDCCodeChallenge is the PKCE challenge persisted with an auth request.
type OIDCCodeChallenge struct {
	Challenge string `json:"challenge"`
	Method    string `json:"method"`
}

func codeChallengeToOIDC(c *OIDCCodeChallenge) *oidc.CodeChallenge {
	if c == nil {
		return nil
	}
	method := oidc.CodeChallengeMethodPlain
	if c.Method == "S256" {
		method = oidc.CodeChallengeMethodS256
	}
	return &oidc.CodeChallenge{Challenge: c.Challenge, Method: method}
}

func promptToInternal(p oidc.SpaceDelimitedArray) []string {
	prompts := make([]string, 0, len(p))
	for _, v := range p {
		switch v {
		case oidc.PromptNone, oidc.PromptLogin, oidc.PromptConsent, oidc.PromptSelectAccount:
			prompts = append(prompts, v)
		}
	}
	return prompts
}

func maxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	d := time.Duration(*maxAge) * time.Second
	return &d
}

func authRequestToInternal(req *oidc.AuthRequest, userID string) *AuthRequest {
	var cc *OIDCCodeChallenge
	if req.CodeChallenge != "" {
		cc = &OIDCCodeChallenge{Challenge: req.CodeChallenge, Method: string(req.CodeChallengeMethod)}
	}
	return &AuthRequest{
		CreationDate:  time.Now(),
		ApplicationID: req.ClientID,
		CallbackURI:   req.RedirectURI,
		TransferState: req.State,
		Prompt:        promptToInternal(req.Prompt),
		UILocales:     req.UILocales,
		LoginHint:     req.LoginHint,
		MaxAuthAge:    maxAgeToInternal(req.MaxAge),
		UserID:        userID,
		Scopes:        req.Scopes,
		ResponseType:  req.ResponseType,
		ResponseMode:  req.ResponseMode,
		Nonce:         req.Nonce,
		CodeChallenge: cc,
	}
}

// NewAuthenticatedRequest builds an already-authenticated AuthRequest for grants
// that bypass the browser login (e.g. Resource Owner Password Credentials).
func NewAuthenticatedRequest(clientID string, user *User, scopes []string) *AuthRequest {
	now := time.Now()
	return &AuthRequest{
		ID:            uuid.NewString(),
		CreationDate:  now,
		ApplicationID: clientID,
		UserID:        user.SubjectOrID(),
		Scopes:        scopes,
		ResponseType:  oidc.ResponseTypeCode,
		ACRValue:      user.ACR,
		AMRValues:     user.AMR,
		done:          true,
		authTime:      now,
	}
}

// RefreshToken is the internal model of an issued refresh token.
type RefreshToken struct {
	ID            string
	Token         string
	AuthTime      time.Time
	AMR           []string
	Audience      []string
	UserID        string
	ApplicationID string
	Expiration    time.Time
	Scopes        []string
	AccessToken   string
}

// RefreshTokenRequest wraps RefreshToken to implement op.RefreshTokenRequest.
type RefreshTokenRequest struct {
	*RefreshToken
}

func (r *RefreshTokenRequest) GetAMR() []string                 { return r.AMR }
func (r *RefreshTokenRequest) GetAudience() []string            { return r.Audience }
func (r *RefreshTokenRequest) GetAuthTime() time.Time           { return r.AuthTime }
func (r *RefreshTokenRequest) GetClientID() string              { return r.ApplicationID }
func (r *RefreshTokenRequest) GetScopes() []string              { return r.Scopes }
func (r *RefreshTokenRequest) GetSubject() string               { return r.UserID }
func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string) { r.Scopes = scopes }

var _ op.AuthRequest = (*AuthRequest)(nil)
var _ op.RefreshTokenRequest = (*RefreshTokenRequest)(nil)
