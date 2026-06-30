package server_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/scottbass3/oidc-test-idp/internal/seed"
	"github.com/scottbass3/oidc-test-idp/internal/server"
	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// startIDP boots a fully wired IdP on a random loopback port and returns its base URL.
func startIDP(t *testing.T) string {
	issuer, _ := startIDPWithStore(t)
	return issuer
}

// startIDPWithStore is like startIDP but also exposes the storage for tests that
// need to mutate config directly.
func startIDPWithStore(t *testing.T) (string, *storage.Storage) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()

	db, err := storage.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := seed.ApplyIfEmpty(db, ""); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.New(store, slog.New(slog.NewTextHandler(io.Discard, nil)), server.Options{
		Issuer:        issuer,
		AdminUser:     "admin",
		AdminPassword: "admin",
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Wait until discovery answers.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(issuer + "/.well-known/openid-configuration"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return issuer, store
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idp did not become ready")
	return "", nil
}

func TestAuthCodePKCEFlow(t *testing.T) {
	issuer := startIDP(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	verifier := "0123456789012345678901234567890123456789abc"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := issuer + "/authorize?" + url.Values{
		"client_id":             {"spa-app"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// 1. authorize -> redirect to /login
	loginLoc := mustRedirect(t, client, "GET", authURL, nil)
	if !strings.Contains(loginLoc, "/login?authRequestID=") {
		t.Fatalf("expected login redirect, got %q", loginLoc)
	}
	reqID := mustQuery(t, loginLoc, "authRequestID")

	// 2. select account alice -> redirect to op callback
	cbLoc := mustRedirect(t, client, "POST", issuer+"/login", url.Values{
		"authRequestID": {reqID}, "userID": {"user-alice"},
	})
	// 3. follow op callback -> redirect to app with code
	appLoc := mustRedirect(t, client, "GET", abs(issuer, cbLoc), nil)
	code := mustQuery(t, appLoc, "code")
	if code == "" {
		t.Fatalf("no code in %q", appLoc)
	}

	// 4. token exchange
	tok := postForm(t, issuer+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"spa-app"},
		"code_verifier": {verifier},
	})
	for _, k := range []string{"access_token", "id_token", "refresh_token"} {
		if _, ok := tok[k]; !ok {
			t.Fatalf("token response missing %q: %v", k, tok)
		}
	}

	// 5. userinfo with custom claims
	at, _ := tok["access_token"].(string)
	req, _ := http.NewRequest("GET", issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ui map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ui)
	if ui["role"] != "admin" {
		t.Fatalf("expected custom claim role=admin in userinfo, got %v", ui)
	}

	// 6. refresh grant
	rt, _ := tok["refresh_token"].(string)
	refreshed := postForm(t, issuer+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"spa-app"},
	})
	if _, ok := refreshed["access_token"]; !ok {
		t.Fatalf("refresh did not return access_token: %v", refreshed)
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	issuer := startIDP(t)
	tok := postFormAuth(t, issuer+"/oauth/token", "service-app", "service-secret", url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	})
	if _, ok := tok["access_token"]; !ok {
		t.Fatalf("client_credentials did not return access_token: %v", tok)
	}
}

func TestDeviceCodeFlow(t *testing.T) {
	issuer := startIDP(t)

	// 1. device authorization request (confidential device-app).
	da := postFormAuth(t, issuer+"/device_authorization", "device-app", "device-secret", url.Values{
		"scope": {"openid profile"},
	})
	deviceCode, _ := da["device_code"].(string)
	userCode, _ := da["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("missing device_code/user_code: %v", da)
	}

	// 2. user approves via the passwordless device UI.
	resp, err := http.PostForm(issuer+"/device/approve", url.Values{
		"user_code": {userCode}, "userID": {"user-bob"}, "action": {"allow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 3. device polls the token endpoint and gets tokens.
	tok := postFormAuth(t, issuer+"/oauth/token", "device-app", "device-secret", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
	if _, ok := tok["access_token"]; !ok {
		t.Fatalf("device flow returned no access_token: %v", tok)
	}
}

func TestIntrospectionAndRevocation(t *testing.T) {
	issuer := startIDP(t)

	tok := postFormAuth(t, issuer+"/oauth/token", "service-app", "service-secret", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"openid"},
	})
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatal("no access_token")
	}

	// Active before revocation.
	intro := postFormAuth(t, issuer+"/oauth/introspect", "service-app", "service-secret", url.Values{"token": {at}})
	if active, _ := intro["active"].(bool); !active {
		t.Fatalf("expected token active, got %v", intro)
	}
	if intro["client_id"] != "service-app" {
		t.Fatalf("expected client_id service-app, got %v", intro["client_id"])
	}

	// Revoke.
	req, _ := http.NewRequest("POST", issuer+"/revoke", strings.NewReader(url.Values{"token": {at}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("service-app", "service-secret")
	rresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status %d", rresp.StatusCode)
	}

	// Inactive after revocation.
	intro2 := postFormAuth(t, issuer+"/oauth/introspect", "service-app", "service-secret", url.Values{"token": {at}})
	if active, _ := intro2["active"].(bool); active {
		t.Fatalf("expected token inactive after revoke, got %v", intro2)
	}
}

func TestPrivateKeyJWTClientAuth(t *testing.T) {
	issuer, store := startIDPWithStore(t)

	// Generate the client's signing key and register its public JWKS.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "client-key-1"
	pubJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig",
	}}}
	jwksJSON, _ := json.Marshal(pubJWKS)

	// private_key_jwt is authenticated at the code token-exchange (not on
	// client_credentials, which only supports id+secret in zitadel).
	const redirect = "http://localhost:3000/cb"
	if err := store.DB().SaveClient(&storage.Client{
		ID:                   "pkjwt-app",
		AuthMethodValue:      oidc.AuthMethodPrivateKeyJWT,
		GrantTypeList:        []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		ResponseTypeList:     []oidc.ResponseType{oidc.ResponseTypeCode},
		AccessTokenTypeValue: op.AccessTokenTypeJWT,
		RedirectURIList:      []string{redirect},
		AccessTokenLifetime:  300 * time.Second,
		DevModeFlag:          true,
		JWKS:                 string(jwksJSON),
	}); err != nil {
		t.Fatal(err)
	}

	// Run the authorization-code flow to obtain a code.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := issuer + "/authorize?" + url.Values{
		"client_id": {"pkjwt-app"}, "redirect_uri": {redirect},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"s"},
	}.Encode()
	loginLoc := mustRedirect(t, client, "GET", authURL, nil)
	reqID := mustQuery(t, loginLoc, "authRequestID")
	cbLoc := mustRedirect(t, client, "POST", issuer+"/login", url.Values{"authRequestID": {reqID}, "userID": {"user-alice"}})
	appLoc := mustRedirect(t, client, "GET", abs(issuer, cbLoc), nil)
	code := mustQuery(t, appLoc, "code")
	if code == "" {
		t.Fatalf("no code obtained: %q", appLoc)
	}

	// Build a signed client assertion (aud = issuer, iss = sub = client_id).
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	assertion, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   "pkjwt-app",
		Subject:  "pkjwt-app",
		Audience: jwt.Audience{issuer},
		Expiry:   jwt.NewNumericDate(now.Add(time.Minute)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       "assertion-1",
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	tok := postForm(t, issuer+"/oauth/token", url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {redirect},
		"client_id":             {"pkjwt-app"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	})
	if _, ok := tok["access_token"]; !ok {
		t.Fatalf("private_key_jwt auth returned no access_token: %v", tok)
	}
}

func TestConditionalClaims(t *testing.T) {
	issuer := startIDP(t)

	// alice (seeded) has conditional rules:
	//   client web-app    -> tenant: acme
	//   scope  profile     -> department: engineering
	userinfo := func(clientID, secret, scope string) map[string]any {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		redirect := "http://localhost:8088/auth/callback"
		if clientID == "spa-app" {
			redirect = "http://localhost:3000/callback"
		}
		v := "0123456789012345678901234567890123456789abc"
		sum := sha256.Sum256([]byte(v))
		authURL := issuer + "/authorize?" + url.Values{
			"client_id": {clientID}, "redirect_uri": {redirect},
			"response_type": {"code"}, "scope": {scope}, "state": {"s"},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		}.Encode()
		loginLoc := mustRedirect(t, c, "GET", authURL, nil)
		reqID := mustQuery(t, loginLoc, "authRequestID")
		cbLoc := mustRedirect(t, c, "POST", issuer+"/login", url.Values{"authRequestID": {reqID}, "userID": {"user-alice"}})
		appLoc := mustRedirect(t, c, "GET", abs(issuer, cbLoc), nil)
		code := mustQuery(t, appLoc, "code")
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {v},
		}
		var tok map[string]any
		if secret != "" {
			tok = postFormAuth(t, issuer+"/oauth/token", clientID, secret, form)
		} else {
			tok = postForm(t, issuer+"/oauth/token", form)
		}
		at, _ := tok["access_token"].(string)
		req, _ := http.NewRequest("GET", issuer+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+at)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var ui map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&ui)
		return ui
	}

	// web-app + profile: both rules fire.
	ui := userinfo("web-app", "web-secret", "openid profile")
	if ui["tenant"] != "acme" {
		t.Fatalf("web-app should get tenant=acme, got %v", ui["tenant"])
	}
	if ui["department"] != "engineering" {
		t.Fatalf("profile scope should add department, got %v", ui["department"])
	}

	// spa-app without profile scope: neither rule fires.
	ui2 := userinfo("spa-app", "", "openid")
	if _, ok := ui2["tenant"]; ok {
		t.Fatalf("spa-app must not get tenant claim, got %v", ui2["tenant"])
	}
	if _, ok := ui2["department"]; ok {
		t.Fatalf("no profile scope must not add department, got %v", ui2["department"])
	}
}

func TestACRAMRAndAddressClaims(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	// Give alice an address claim alongside her seeded acr/amr.
	u, err := store.DB().GetUser("user-alice")
	if err != nil {
		t.Fatal(err)
	}
	u.Claims["address"] = map[string]any{"locality": "Lyon", "country": "FR"}
	if err := store.DB().SaveUser(u); err != nil {
		t.Fatal(err)
	}

	tok := codeFlow(t, issuer, "spa-app", "", "http://localhost:3000/callback", "openid profile address")
	idClaims := decodeJWTPart(t, tok["id_token"].(string), 1)
	if idClaims["acr"] != "urn:mace:incommon:iap:silver" {
		t.Fatalf("expected seeded acr, got %v", idClaims["acr"])
	}
	amr, _ := idClaims["amr"].([]any)
	if len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Fatalf("expected amr [pwd mfa], got %v", idClaims["amr"])
	}

	at := tok["access_token"].(string)
	ui := userinfoGet(t, issuer, at)
	addr, ok := ui["address"].(map[string]any)
	if !ok || addr["locality"] != "Lyon" {
		t.Fatalf("expected address claim with locality Lyon, got %v", ui["address"])
	}
}

func TestPerClientSigningAlg(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	if err := store.DB().SaveClient(&storage.Client{
		ID:                      "es256-app",
		AuthMethodValue:         oidc.AuthMethodNone,
		ResponseTypeList:        []oidc.ResponseType{oidc.ResponseTypeCode},
		GrantTypeList:           []oidc.GrantType{oidc.GrantTypeCode},
		AccessTokenTypeValue:    op.AccessTokenTypeJWT,
		RedirectURIList:         []string{"http://localhost:3000/cb"},
		IDTokenLifetimeDuration: time.Hour,
		DevModeFlag:             true,
		IDTokenSignAlg:          "ES256",
	}); err != nil {
		t.Fatal(err)
	}
	tok := codeFlow(t, issuer, "es256-app", "", "http://localhost:3000/cb", "openid")
	hdr := decodeJWTPart(t, tok["id_token"].(string), 0)
	if hdr["alg"] != "ES256" {
		t.Fatalf("expected id_token alg ES256, got %v", hdr["alg"])
	}
	// The ES256 key must also be published in JWKS for verification.
	if c := jwksHasAlg(t, issuer, "ES256"); !c {
		t.Fatal("ES256 key not present in JWKS")
	}
}

func TestUserinfoWWWAuthenticate(t *testing.T) {
	issuer := startIDP(t)
	req, _ := http.NewRequest("GET", issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if h := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(h, "Bearer") {
		t.Fatalf("expected Bearer WWW-Authenticate header, got %q", h)
	}
}

func TestCustomSubject(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	u, err := store.DB().GetUser("user-alice")
	if err != nil {
		t.Fatal(err)
	}
	u.Subject = "auth0|abc123"
	if err := store.DB().SaveUser(u); err != nil {
		t.Fatal(err)
	}

	tok := codeFlow(t, issuer, "spa-app", "", "http://localhost:3000/callback", "openid profile")
	idClaims := decodeJWTPart(t, tok["id_token"].(string), 1)
	if idClaims["sub"] != "auth0|abc123" {
		t.Fatalf("id_token sub should be custom subject, got %v", idClaims["sub"])
	}

	// userinfo (looked up by the custom subject) still resolves the user + claims.
	ui := userinfoGet(t, issuer, tok["access_token"].(string))
	if ui["sub"] != "auth0|abc123" {
		t.Fatalf("userinfo sub should be custom subject, got %v", ui["sub"])
	}
	if ui["role"] != "admin" {
		t.Fatalf("custom-subject user must still resolve claims, got %v", ui)
	}
}

func TestROPCFlow(t *testing.T) {
	issuer := startIDP(t)

	// Happy path: password grant returns full token set.
	tok := postFormAuth(t, issuer+"/oauth/token", "ropc-app", "ropc-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"ignored-by-test-idp"},
		"scope":      {"openid profile offline_access"},
	})
	for _, k := range []string{"access_token", "id_token", "refresh_token"} {
		if _, ok := tok[k]; !ok {
			t.Fatalf("ROPC response missing %q: %v", k, tok)
		}
	}

	// The ROPC-issued refresh token works.
	rt, _ := tok["refresh_token"].(string)
	refreshed := postFormAuth(t, issuer+"/oauth/token", "ropc-app", "ropc-secret", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
	})
	if _, ok := refreshed["access_token"]; !ok {
		t.Fatalf("refresh after ROPC failed: %v", refreshed)
	}

	// Negative: unknown user.
	if status := postStatus(t, issuer+"/oauth/token", "ropc-app", "ropc-secret", url.Values{
		"grant_type": {"password"}, "username": {"ghost"}, "password": {"x"}, "scope": {"openid"},
	}); status != http.StatusBadRequest {
		t.Fatalf("unknown user: expected 400, got %d", status)
	}

	// Negative: client without the password grant.
	if status := postStatus(t, issuer+"/oauth/token", "service-app", "service-secret", url.Values{
		"grant_type": {"password"}, "username": {"alice"}, "password": {"x"}, "scope": {"openid"},
	}); status != http.StatusBadRequest {
		t.Fatalf("client without password grant: expected 400, got %d", status)
	}
}

func TestImplicitAndHybridFlow(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	const redirect = "http://localhost:3000/cb"
	if err := store.DB().SaveClient(&storage.Client{
		ID:              "implicit-app",
		AuthMethodValue: oidc.AuthMethodNone,
		ResponseTypeList: []oidc.ResponseType{
			oidc.ResponseTypeIDToken,     // "id_token token" (implicit)
			oidc.ResponseTypeIDTokenOnly, // "id_token"
		},
		GrantTypeList:           []oidc.GrantType{oidc.GrantTypeImplicit},
		AccessTokenTypeValue:    op.AccessTokenTypeJWT,
		RedirectURIList:         []string{redirect},
		IDTokenLifetimeDuration: time.Hour,
		DevModeFlag:             true,
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		responseType string
		wantAccess   bool // implicit ("id_token token") also returns an access_token
	}{
		{"implicit", "id_token token", true},
		{"hybrid_idtoken_only", "id_token", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			authURL := issuer + "/authorize?" + url.Values{
				"client_id": {"implicit-app"}, "redirect_uri": {redirect},
				"response_type": {tc.responseType}, "scope": {"openid profile"},
				"state": {"st"}, "nonce": {"n0"},
			}.Encode()
			loginLoc := mustRedirect(t, client, "GET", authURL, nil)
			reqID := mustQuery(t, loginLoc, "authRequestID")
			cbLoc := mustRedirect(t, client, "POST", issuer+"/login", url.Values{
				"authRequestID": {reqID}, "userID": {"user-alice"},
			})
			// Follow the OP callback to the final redirect (tokens in fragment).
			finalLoc := mustRedirect(t, client, "GET", abs(issuer, cbLoc), nil)
			// Implicit/hybrid return tokens in the URL fragment.
			u, err := url.Parse(finalLoc)
			if err != nil {
				t.Fatal(err)
			}
			frag, err := url.ParseQuery(u.Fragment)
			if err != nil {
				t.Fatal(err)
			}
			if frag.Get("id_token") == "" {
				t.Fatalf("%s: no id_token in fragment of %q", tc.name, finalLoc)
			}
			if frag.Get("state") != "st" {
				t.Fatalf("%s: state not echoed", tc.name)
			}
			if tc.wantAccess && frag.Get("access_token") == "" {
				t.Fatalf("%s: expected access_token in fragment", tc.name)
			}
		})
	}
}

func TestES256KeyRotation(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	if _, err := store.RotateSigningKey(jose.ES256); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(issuer + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	foundEC := false
	for _, k := range set.Keys {
		if k.Algorithm == string(jose.ES256) {
			foundEC = true
		}
	}
	if !foundEC {
		t.Fatalf("expected an ES256 key in JWKS after rotation, got %d keys", len(set.Keys))
	}
}

func TestDiscoveryOverride(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	if err := store.DB().SetSetting("discovery_override",
		`{"id_token_signing_alg_values_supported":["RS256","ES256"],"x_vendor":"mock-acme"}`); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc["x_vendor"] != "mock-acme" {
		t.Fatalf("override field missing: %v", doc["x_vendor"])
	}
	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 2 {
		t.Fatalf("expected overridden algs, got %v", doc["id_token_signing_alg_values_supported"])
	}
	if doc["issuer"] != issuer {
		t.Fatalf("issuer must be preserved, got %v", doc["issuer"])
	}
}

func TestKeyRotation(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	before := jwksCount(t, issuer)
	if _, err := store.RotateSigningKey(jose.RS256); err != nil {
		t.Fatal(err)
	}
	after := jwksCount(t, issuer)
	if after != before+1 {
		t.Fatalf("expected JWKS to grow after rotation: before=%d after=%d", before, after)
	}
}

func TestForcedErrorOnAuthorizeRedirects(t *testing.T) {
	issuer, store := startIDPWithStore(t)
	c, err := store.DB().GetClient("spa-app")
	if err != nil {
		t.Fatal(err)
	}
	c.ForceError = "access_denied"
	if err := store.DB().SaveClient(c); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := issuer + "/authorize?" + url.Values{
		"client_id":     {"spa-app"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"abc123"},
	}.Encode()
	loc := mustRedirect(t, client, "GET", authURL, nil)
	u, _ := url.Parse(loc)
	if !strings.HasPrefix(loc, "http://localhost:3000/callback") {
		t.Fatalf("expected redirect to redirect_uri, got %q", loc)
	}
	if got := u.Query().Get("error"); got != "access_denied" {
		t.Fatalf("expected error=access_denied, got %q", got)
	}
	if got := u.Query().Get("state"); got != "abc123" {
		t.Fatalf("expected state preserved, got %q", got)
	}
}

func jwksCount(t *testing.T, issuer string) int {
	t.Helper()
	resp, err := http.Get(issuer + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&jwks)
	return len(jwks.Keys)
}

// --- helpers --------------------------------------------------------------

func mustRedirect(t *testing.T, c *http.Client, method, u string, form url.Values) string {
	t.Helper()
	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest(method, u, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, u, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("%s %s: expected redirect, got status %d", method, u, resp.StatusCode)
	}
	return loc
}

func postForm(t *testing.T, u string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode token response: %v (%s)", err, body)
	}
	return out
}

func postFormAuth(t *testing.T, u, user, pass string, form url.Values) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return out
}

// codeFlow runs a full Authorization Code + PKCE flow as user-alice and returns
// the token response. Pass secret="" for public clients.
func codeFlow(t *testing.T, issuer, clientID, secret, redirect, scope string) map[string]any {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	v := "0123456789012345678901234567890123456789abc"
	sum := sha256.Sum256([]byte(v))
	authURL := issuer + "/authorize?" + url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {scope}, "state": {"s"}, "nonce": {"n"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode()
	loginLoc := mustRedirect(t, c, "GET", authURL, nil)
	reqID := mustQuery(t, loginLoc, "authRequestID")
	cbLoc := mustRedirect(t, c, "POST", issuer+"/login", url.Values{"authRequestID": {reqID}, "userID": {"user-alice"}})
	appLoc := mustRedirect(t, c, "GET", abs(issuer, cbLoc), nil)
	code := mustQuery(t, appLoc, "code")
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {v},
	}
	if secret != "" {
		return postFormAuth(t, issuer+"/oauth/token", clientID, secret, form)
	}
	return postForm(t, issuer+"/oauth/token", form)
}

func userinfoGet(t *testing.T, issuer, accessToken string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ui map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ui)
	return ui
}

// decodeJWTPart decodes part 0 (header) or 1 (payload) of a JWT into a map.
func decodeJWTPart(t *testing.T, token string, part int) map[string]any {
	t.Helper()
	segs := strings.Split(token, ".")
	if len(segs) < 2 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[part])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func jwksHasAlg(t *testing.T, issuer, alg string) bool {
	t.Helper()
	resp, err := http.Get(issuer + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	_ = json.NewDecoder(resp.Body).Decode(&set)
	for _, k := range set.Keys {
		if k.Algorithm == alg {
			return true
		}
	}
	return false
}

func postStatus(t *testing.T, u, user, pass string, form url.Values) int {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func mustQuery(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func abs(issuer, loc string) string {
	if strings.HasPrefix(loc, "http") {
		return loc
	}
	return issuer + loc
}
