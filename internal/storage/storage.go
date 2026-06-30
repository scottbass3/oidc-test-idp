package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Storage implements op.Storage (plus the optional ClientCredentials, Device and
// CanSetUserinfoFromRequest interfaces) on top of the SQLite DB.
type Storage struct {
	db        *DB
	keyMu     sync.RWMutex
	key       *signingKey                             // current (newest) signing key
	keysByAlg map[jose.SignatureAlgorithm]*signingKey // cache of one active key per alg
}

// signingAlgCtxKey carries a per-request preferred signing algorithm.
type signingAlgCtxKey struct{}

// WithSigningAlg returns a context requesting that tokens be signed with alg.
func WithSigningAlg(ctx context.Context, alg jose.SignatureAlgorithm) context.Context {
	return context.WithValue(ctx, signingAlgCtxKey{}, alg)
}

func signingAlgFromContext(ctx context.Context) jose.SignatureAlgorithm {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(signingAlgCtxKey{}).(jose.SignatureAlgorithm); ok {
		return v
	}
	return ""
}

// Compile-time interface checks.
var (
	_ op.Storage                    = (*Storage)(nil)
	_ op.ClientCredentialsStorage   = (*Storage)(nil)
	_ op.DeviceAuthorizationStorage = (*Storage)(nil)
	_ op.CanSetUserinfoFromRequest  = (*Storage)(nil)
)

// NewStorage builds the op.Storage on top of db, loading/creating the signing key.
func NewStorage(db *DB) (*Storage, error) {
	key, err := db.loadOrCreateSigningKey()
	if err != nil {
		return nil, err
	}
	return &Storage{
		db:        db,
		key:       key,
		keysByAlg: map[jose.SignatureAlgorithm]*signingKey{key.algorithm: key},
	}, nil
}

// DB exposes the underlying database for the admin/seed layers.
func (s *Storage) DB() *DB { return s.db }

// --- Auth requests --------------------------------------------------------

func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		return nil, oidc.ErrLoginRequired()
	}
	req := authRequestToInternal(authReq, userID)
	req.ID = uuid.NewString()
	if err := s.saveAuthRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *Storage) saveAuthRequest(req *AuthRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_, err = s.db.conn.Exec(`
		INSERT INTO auth_requests (id, data, done, user_id, auth_time)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET data=excluded.data, done=excluded.done,
			user_id=excluded.user_id, auth_time=excluded.auth_time`,
		req.ID, string(data), boolInt(req.done), req.UserID, timeStr(req.authTime))
	return err
}

func (s *Storage) loadAuthRequest(id string) (*AuthRequest, error) {
	var data, userID, authTime string
	var done int
	err := s.db.conn.QueryRow(
		`SELECT data, done, user_id, auth_time FROM auth_requests WHERE id = ?`, id,
	).Scan(&data, &done, &userID, &authTime)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("request not found")
	}
	if err != nil {
		return nil, err
	}
	var req AuthRequest
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return nil, err
	}
	req.done = done != 0
	req.UserID = userID
	req.authTime = parseTime(authTime)
	return &req, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.loadAuthRequest(id)
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	var id string
	err := s.db.conn.QueryRow(`SELECT auth_request_id FROM auth_codes WHERE code = ?`, code).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("code invalid or expired")
	}
	return s.loadAuthRequest(id)
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	_, err := s.db.conn.Exec(`INSERT INTO auth_codes (code, auth_request_id) VALUES (?, ?)`, code, id)
	return err
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	if _, err := s.db.conn.Exec(`DELETE FROM auth_codes WHERE auth_request_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.conn.Exec(`DELETE FROM auth_requests WHERE id = ?`, id)
	return err
}

// SetAuthRequestUser records the chosen user on an auth request without marking
// it done. Used when a consent step must run before completion.
func (s *Storage) SetAuthRequestUser(id, userID string) error {
	req, err := s.loadAuthRequest(id)
	if err != nil {
		return err
	}
	req.UserID = userID
	return s.saveAuthRequest(req)
}

// CompleteAuthRequest marks an auth request as authenticated by a user. Called by
// the account-selection login UI.
func (s *Storage) CompleteAuthRequest(id, userID string) error {
	req, err := s.loadAuthRequest(id)
	if err != nil {
		return err
	}
	req.UserID = userID
	req.done = true
	req.authTime = time.Now()
	// Stamp the selected user's ACR/AMR so they land in the id_token.
	if u, uerr := s.db.GetUser(userID); uerr == nil {
		req.ACRValue = u.ACR
		req.AMRValues = u.AMR
	}
	return s.saveAuthRequest(req)
}

// --- Tokens ---------------------------------------------------------------

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	applicationID := ""
	switch req := request.(type) {
	case *AuthRequest:
		applicationID = req.ApplicationID
	case op.TokenExchangeRequest:
		applicationID = req.GetClientID()
	case *oidc.JWTTokenRequest:
		// Client Credentials / JWT Profile: audience holds the client id.
		if aud := req.GetAudience(); len(aud) > 0 {
			applicationID = aud[0]
		}
	}
	token, err := s.accessToken(applicationID, "", request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, token.Expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	applicationID, authTime, amr := getInfoFromRequest(request)

	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken, err := s.createRefreshToken(accessToken, amr, authTime)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return accessToken.ID, refreshToken, accessToken.Expiration, nil
	}

	newRefreshToken := uuid.NewString()
	accessToken, err := s.accessToken(applicationID, newRefreshToken, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := s.renewRefreshToken(currentRefreshToken, newRefreshToken, accessToken.ID); err != nil {
		return "", "", time.Time{}, err
	}
	return accessToken.ID, newRefreshToken, accessToken.Expiration, nil
}

func (s *Storage) accessToken(applicationID, refreshTokenID, subject string, audience, scopes []string) (*tokenRow, error) {
	t := &tokenRow{
		ID:             uuid.NewString(),
		ApplicationID:  applicationID,
		RefreshTokenID: refreshTokenID,
		Subject:        subject,
		Audience:       audience,
		Scopes:         scopes,
		Expiration:     time.Now().Add(s.accessTokenLifetime(applicationID)),
	}
	_, err := s.db.conn.Exec(`
		INSERT INTO tokens (id, application_id, subject, refresh_token_id, audience, scopes, expiration)
		VALUES (?,?,?,?,?,?,?)`,
		t.ID, t.ApplicationID, t.Subject, t.RefreshTokenID,
		jsonMarshal(t.Audience), jsonMarshal(t.Scopes), timeStr(t.Expiration))
	return t, err
}

func (s *Storage) accessTokenLifetime(clientID string) time.Duration {
	c, err := s.db.GetClient(clientID)
	if err == nil && c.AccessTokenLifetime > 0 {
		return c.AccessTokenLifetime
	}
	return 5 * time.Minute
}

func (s *Storage) createRefreshToken(accessToken *tokenRow, amr []string, authTime time.Time) (string, error) {
	lifetime := 5 * time.Hour
	if c, err := s.db.GetClient(accessToken.ApplicationID); err == nil && c.RefreshTokenLifetime > 0 {
		lifetime = c.RefreshTokenLifetime
	}
	_, err := s.db.conn.Exec(`
		INSERT INTO refresh_tokens (id, token, auth_time, amr, audience, user_id, application_id, expiration, scopes, access_token)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		accessToken.RefreshTokenID, accessToken.RefreshTokenID, timeStr(authTime),
		jsonMarshal(amr), jsonMarshal(accessToken.Audience), accessToken.Subject,
		accessToken.ApplicationID, timeStr(time.Now().Add(lifetime)),
		jsonMarshal(accessToken.Scopes), accessToken.ID)
	if err != nil {
		return "", err
	}
	return accessToken.RefreshTokenID, nil
}

func (s *Storage) renewRefreshToken(currentRefreshToken, newRefreshToken, newAccessToken string) error {
	rt, err := s.loadRefreshToken(currentRefreshToken)
	if err != nil {
		return fmt.Errorf("invalid refresh token")
	}
	if rt.Expiration.Before(time.Now()) {
		return fmt.Errorf("expired refresh token")
	}
	// Rotation: delete old refresh token and its access token, insert renewed.
	if _, err := s.db.conn.Exec(`DELETE FROM refresh_tokens WHERE id = ?`, currentRefreshToken); err != nil {
		return err
	}
	if _, err := s.db.conn.Exec(`DELETE FROM tokens WHERE id = ?`, rt.AccessToken); err != nil {
		return err
	}
	_, err = s.db.conn.Exec(`
		INSERT INTO refresh_tokens (id, token, auth_time, amr, audience, user_id, application_id, expiration, scopes, access_token)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		newRefreshToken, newRefreshToken, timeStr(rt.AuthTime), jsonMarshal(rt.AMR),
		jsonMarshal(rt.Audience), rt.UserID, rt.ApplicationID,
		timeStr(time.Now().Add(5*time.Hour)), jsonMarshal(rt.Scopes), newAccessToken)
	return err
}

func (s *Storage) loadRefreshToken(token string) (*RefreshToken, error) {
	var rt RefreshToken
	var authTime, exp, amr, aud, scopes string
	err := s.db.conn.QueryRow(`
		SELECT id, token, auth_time, amr, audience, user_id, application_id, expiration, scopes, access_token
		FROM refresh_tokens WHERE id = ?`, token).Scan(
		&rt.ID, &rt.Token, &authTime, &amr, &aud, &rt.UserID, &rt.ApplicationID, &exp, &scopes, &rt.AccessToken)
	if err != nil {
		return nil, err
	}
	rt.AuthTime = parseTime(authTime)
	rt.Expiration = parseTime(exp)
	rt.AMR = jsonStrings(amr)
	rt.Audience = jsonStrings(aud)
	rt.Scopes = jsonStrings(scopes)
	return &rt, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	rt, err := s.loadRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh_token")
	}
	return &RefreshTokenRequest{rt}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	if _, err := s.db.conn.Exec(
		`DELETE FROM refresh_tokens WHERE user_id = ? AND application_id = ?`, userID, clientID); err != nil {
		return err
	}
	_, err := s.db.conn.Exec(
		`DELETE FROM tokens WHERE subject = ? AND application_id = ?`, userID, clientID)
	return err
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	rt, err := s.loadRefreshToken(token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.UserID, rt.ID, nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// access token id?
	var appID string
	err := s.db.conn.QueryRow(`SELECT application_id FROM tokens WHERE id = ?`, tokenIDOrToken).Scan(&appID)
	if err == nil {
		if appID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		_, _ = s.db.conn.Exec(`DELETE FROM tokens WHERE id = ?`, tokenIDOrToken)
		return nil
	}
	// refresh token?
	rt, rerr := s.loadRefreshToken(tokenIDOrToken)
	if rerr != nil {
		return nil // unknown token: treat as already revoked
	}
	if rt.ApplicationID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	_, _ = s.db.conn.Exec(`DELETE FROM refresh_tokens WHERE id = ?`, rt.ID)
	_, _ = s.db.conn.Exec(`DELETE FROM tokens WHERE id = ?`, rt.AccessToken)
	return nil
}

// --- Keys -----------------------------------------------------------------

func (s *Storage) currentKey() *signingKey {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	return s.key
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	if alg := signingAlgFromContext(ctx); alg != "" && IsSupportedAlg(alg) {
		if k, err := s.ensureKeyForAlg(alg); err == nil {
			return k, nil
		}
	}
	return s.currentKey(), nil
}

// ensureKeyForAlg returns an active signing key of the requested algorithm,
// loading or generating (and persisting) one if needed. Results are cached.
func (s *Storage) ensureKeyForAlg(alg jose.SignatureAlgorithm) (*signingKey, error) {
	s.keyMu.RLock()
	if k, ok := s.keysByAlg[alg]; ok {
		s.keyMu.RUnlock()
		return k, nil
	}
	s.keyMu.RUnlock()

	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if k, ok := s.keysByAlg[alg]; ok { // re-check under write lock
		return k, nil
	}
	if k, err := s.db.loadActiveKeyByAlg(alg); err == nil {
		s.keysByAlg[alg] = k
		return k, nil
	}
	k, err := s.db.generateSigningKey(alg)
	if err != nil {
		return nil, err
	}
	s.keysByAlg[alg] = k
	return k, nil
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	keys, err := s.db.loadAllSigningKeys()
	if err != nil || len(keys) == 0 {
		return []jose.SignatureAlgorithm{s.currentKey().algorithm}, nil
	}
	seen := map[jose.SignatureAlgorithm]bool{}
	var algs []jose.SignatureAlgorithm
	for _, k := range keys {
		if !seen[k.algorithm] {
			seen[k.algorithm] = true
			algs = append(algs, k.algorithm)
		}
	}
	return algs, nil
}

// KeySet publishes all active public keys so tokens signed by a rotated-out key
// still validate during the overlap window.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	keys, err := s.db.loadAllSigningKeys()
	if err != nil || len(keys) == 0 {
		// Fall back to the current key.
		return []op.Key{&publicKey{s.currentKey()}}, nil
	}
	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, &publicKey{k})
	}
	return out, nil
}

// RotateSigningKey generates a new signing key of the given algorithm, persists
// it and makes it current. Returns the new key id.
func (s *Storage) RotateSigningKey(alg jose.SignatureAlgorithm) (string, error) {
	key, err := s.db.generateSigningKey(alg)
	if err != nil {
		return "", err
	}
	s.keyMu.Lock()
	s.key = key
	s.keysByAlg[key.algorithm] = key
	s.keyMu.Unlock()
	return key.id, nil
}

// --- Clients --------------------------------------------------------------

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.db.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}
	return asOPClient(c), nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.db.GetClient(clientID)
	if err != nil {
		return fmt.Errorf("client not found")
	}
	if c.Secret != clientSecret {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

// --- Userinfo / claims ----------------------------------------------------

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, token.GetSubject(), token.GetClientID(), scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	t, err := s.loadToken(tokenID)
	if err != nil {
		return fmt.Errorf("token is invalid or has expired")
	}
	if t.Expiration.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	return s.setUserinfo(ctx, userinfo, t.Subject, t.ApplicationID, t.Scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	t, err := s.loadToken(tokenID)
	if err != nil {
		return fmt.Errorf("token is invalid")
	}
	introspection.Expiration = oidc.FromTime(t.Expiration)
	if t.Expiration.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	for _, aud := range t.Audience {
		if aud == clientID {
			userInfo := new(oidc.UserInfo)
			if err := s.setUserinfo(ctx, userInfo, subject, clientID, t.Scopes); err != nil {
				return err
			}
			introspection.SetUserInfo(userInfo)
			introspection.Scope = t.Scopes
			introspection.ClientID = t.ApplicationID
			return nil
		}
	}
	return fmt.Errorf("token is not valid for this client")
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	claims := map[string]any{}
	// Merge per-user static + conditional claims, then per-client custom claims,
	// into JWT access tokens.
	if u, err := s.db.GetUser(userID); err == nil {
		for k, v := range u.Claims {
			claims[k] = v
		}
		for k, v := range u.EvaluateConditionalClaims(clientID, scopes) {
			claims[k] = v
		}
	}
	if c, err := s.db.GetClient(clientID); err == nil {
		for k, v := range c.CustomClaims {
			claims[k] = v
		}
	}
	if len(claims) == 0 {
		return nil, nil
	}
	return claims, nil
}

func (s *Storage) setUserinfo(ctx context.Context, userInfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	u, err := s.db.GetUser(userID)
	if err != nil {
		// No user row — e.g. a client_credentials token whose subject is the
		// client itself. Still produce a valid (minimal) response: set the
		// subject and apply any per-client custom claims.
		userInfo.Subject = userID
		if c, cerr := s.db.GetClient(clientID); cerr == nil {
			for k, v := range c.CustomClaims {
				userInfo.AppendClaims(k, v)
			}
		}
		return nil
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userInfo.Subject = u.ID
		case oidc.ScopeEmail:
			userInfo.Email = u.Email
			userInfo.EmailVerified = oidc.Bool(u.EmailVerified)
		case oidc.ScopeProfile:
			userInfo.PreferredUsername = u.Username
			userInfo.Name = joinName(u.FirstName, u.LastName)
			userInfo.FamilyName = u.LastName
			userInfo.GivenName = u.FirstName
			userInfo.Locale = oidc.NewLocale(localeTag(u.PreferredLanguage))
		case oidc.ScopePhone:
			userInfo.PhoneNumber = u.Phone
			userInfo.PhoneNumberVerified = oidc.Bool(u.PhoneVerified)
		case oidc.ScopeAddress:
			if addr, ok := u.Claims["address"].(map[string]any); ok {
				userInfo.Address = toAddress(addr)
			}
		}
	}
	// Always assert arbitrary custom claims: per-user static, then per-user
	// conditional (by client/scope), then per-client custom (most specific).
	// "address" is reserved for the address scope above and not emitted raw.
	for k, v := range u.Claims {
		if k == "address" {
			continue
		}
		userInfo.AppendClaims(k, v)
	}
	for k, v := range u.EvaluateConditionalClaims(clientID, scopes) {
		userInfo.AppendClaims(k, v)
	}
	if c, err := s.db.GetClient(clientID); err == nil {
		for k, v := range c.CustomClaims {
			userInfo.AppendClaims(k, v)
		}
	}
	return nil
}

// GetKeyByIDAndClientID returns the client's registered public key for the given
// key id, used to validate private_key_jwt assertions and JWT-profile grants.
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	c, err := s.db.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}
	if c.JWKS == "" || c.JWKS == "{}" {
		return nil, fmt.Errorf("client %s has no registered JWKS", clientID)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(c.JWKS), &set); err != nil {
		return nil, fmt.Errorf("invalid client JWKS: %w", err)
	}
	keys := set.Key(keyID)
	if len(keys) == 0 {
		return nil, fmt.Errorf("key %q not found for client %s", keyID, clientID)
	}
	return &keys[0], nil
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	allowed := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == oidc.ScopeOpenID {
			allowed = append(allowed, scope)
		}
	}
	return allowed, nil
}

func (s *Storage) Health(ctx context.Context) error { return s.db.conn.PingContext(ctx) }

// --- Client credentials ---------------------------------------------------

func (s *Storage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	c, err := s.db.GetClient(clientID)
	if err != nil {
		return nil, errors.New("wrong service user or password")
	}
	if c.Secret != clientSecret {
		return nil, errors.New("wrong service user or password")
	}
	return asOPClient(c), nil
}

func (s *Storage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	if _, err := s.db.GetClient(clientID); err != nil {
		return nil, errors.New("wrong service user or password")
	}
	return &oidc.JWTTokenRequest{
		Subject:  clientID,
		Audience: []string{clientID},
		Scopes:   scopes,
	}, nil
}

// --- Device authorization -------------------------------------------------

func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	if _, err := s.db.GetClient(clientID); err != nil {
		return errors.New("client not found")
	}
	var exists int
	_ = s.db.conn.QueryRow(`SELECT COUNT(*) FROM device_codes WHERE user_code = ?`, userCode).Scan(&exists)
	if exists > 0 {
		return op.ErrDuplicateUserCode
	}
	_, err := s.db.conn.Exec(`
		INSERT INTO device_codes (device_code, user_code, client_id, scopes, expires)
		VALUES (?,?,?,?,?)`, deviceCode, userCode, clientID, jsonMarshal(scopes), timeStr(expires))
	return err
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	st, gotClient, err := s.loadDeviceState(`device_code`, deviceCode)
	if err != nil || gotClient != clientID {
		return nil, errors.New("device code not found for client")
	}
	return st, nil
}

// GetDeviceAuthorizationByUserCode is used by the device verification UI.
func (s *Storage) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	st, _, err := s.loadDeviceState(`user_code`, userCode)
	if err != nil {
		return nil, errors.New("user code not found")
	}
	return st, nil
}

func (s *Storage) loadDeviceState(column, value string) (*op.DeviceAuthorizationState, string, error) {
	var clientID, scopes, expires, subject string
	var done, denied int
	err := s.db.conn.QueryRow(
		`SELECT client_id, scopes, expires, subject, done, denied FROM device_codes WHERE `+column+` = ?`, value,
	).Scan(&clientID, &scopes, &expires, &subject, &done, &denied)
	if err != nil {
		return nil, "", err
	}
	return &op.DeviceAuthorizationState{
		ClientID: clientID,
		Scopes:   jsonStrings(scopes),
		Expires:  parseTime(expires),
		Subject:  subject,
		Done:     done != 0,
		Denied:   denied != 0,
	}, clientID, nil
}

// CompleteDeviceAuthorization is called by the device verification UI on approval.
func (s *Storage) CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error {
	_, err := s.db.conn.Exec(
		`UPDATE device_codes SET subject = ?, done = 1 WHERE user_code = ?`, subject, userCode)
	return err
}

// DenyDeviceAuthorization is called by the device verification UI on denial.
func (s *Storage) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	_, err := s.db.conn.Exec(`UPDATE device_codes SET denied = 1 WHERE user_code = ?`, userCode)
	return err
}

// --- helpers --------------------------------------------------------------

type tokenRow struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Scopes         []string
	Expiration     time.Time
}

func (s *Storage) loadToken(id string) (*tokenRow, error) {
	var t tokenRow
	var aud, scopes, exp string
	err := s.db.conn.QueryRow(`
		SELECT id, application_id, subject, refresh_token_id, audience, scopes, expiration
		FROM tokens WHERE id = ?`, id).Scan(
		&t.ID, &t.ApplicationID, &t.Subject, &t.RefreshTokenID, &aud, &scopes, &exp)
	if err != nil {
		return nil, err
	}
	t.Audience = jsonStrings(aud)
	t.Scopes = jsonStrings(scopes)
	t.Expiration = parseTime(exp)
	return &t, nil
}

func getInfoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	switch r := req.(type) {
	case *AuthRequest:
		return r.ApplicationID, r.authTime, r.GetAMR()
	case *RefreshTokenRequest:
		return r.ApplicationID, r.AuthTime, r.AMR
	}
	return "", time.Time{}, nil
}

func timeStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// toAddress maps a free-form address claim object to the OIDC address structure.
func toAddress(m map[string]any) *oidc.UserInfoAddress {
	str := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	return &oidc.UserInfoAddress{
		Formatted:     str("formatted"),
		StreetAddress: str("street_address"),
		Locality:      str("locality"),
		Region:        str("region"),
		PostalCode:    str("postal_code"),
		Country:       str("country"),
	}
}

func localeTag(s string) language.Tag {
	if s == "" {
		return language.English
	}
	t, err := language.Parse(s)
	if err != nil {
		return language.English
	}
	return t
}

func joinName(first, last string) string {
	switch {
	case first == "" && last == "":
		return ""
	case first == "":
		return last
	case last == "":
		return first
	default:
		return first + " " + last
	}
}
