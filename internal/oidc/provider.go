// Package oidc wires the zitadel/oidc OpenID Provider onto the SQLite storage.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"time"

	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// NewProvider builds the OpenIDProvider for the given issuer, enabling the full
// set of supported flows (PKCE, refresh, device, client credentials, token
// exchange, private_key_jwt form auth).
func NewProvider(issuer string, store *storage.Storage, logger *slog.Logger, allowInsecure bool) (op.OpenIDProvider, error) {
	key, keyID, err := cryptoKey(store)
	if err != nil {
		return nil, err
	}

	config := &op.Config{
		CryptoKey:                key,
		CryptoKeyId:              keyID,
		DefaultLogoutRedirectURI: "/logged-out",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}

	opts := []op.Option{op.WithLogger(logger.WithGroup("op"))}
	if allowInsecure {
		opts = append(opts, op.WithAllowInsecure())
	}
	return op.NewOpenIDProvider(issuer, config, store, opts...)
}

// cryptoKey returns the 32-byte token-encryption key, generating and persisting
// one (base64) on first boot so tokens survive restarts.
func cryptoKey(store *storage.Storage) ([32]byte, string, error) {
	const settingKey = "crypto_key"
	const keyID = "key1"
	if b64 := store.DB().GetSetting(settingKey, ""); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err == nil && len(raw) == 32 {
			return sha256.Sum256(raw), keyID, nil
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return [32]byte{}, "", err
	}
	if err := store.DB().SetSetting(settingKey, base64.StdEncoding.EncodeToString(raw)); err != nil {
		return [32]byte{}, "", err
	}
	return sha256.Sum256(raw), keyID, nil
}
