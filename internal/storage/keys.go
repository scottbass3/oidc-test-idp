package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// SupportedSignatureAlgorithms are the algorithms a developer can choose for the
// signing key, so the mock IdP can match a target IdP's id_token alg.
var SupportedSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// IsSupportedAlg reports whether alg can be used for the signing key.
func IsSupportedAlg(alg jose.SignatureAlgorithm) bool {
	for _, a := range SupportedSignatureAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// KeyInfo is a display model for the admin keys page.
type KeyInfo struct {
	ID        string
	Algorithm string
	Active    bool
	CreatedAt string
}

// signingKey implements op.SigningKey. The private key is any crypto.Signer
// (RSA or ECDSA), so multiple signature algorithms are supported.
type signingKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       crypto.Signer
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return s.algorithm }
func (s *signingKey) Key() any                                    { return s.key }
func (s *signingKey) ID() string                                  { return s.id }

// publicKey implements op.Key.
type publicKey struct {
	*signingKey
}

func (p *publicKey) ID() string                         { return p.id }
func (p *publicKey) Algorithm() jose.SignatureAlgorithm { return p.algorithm }
func (p *publicKey) Use() string                        { return "sig" }
func (p *publicKey) Key() any                           { return p.signingKey.key.Public() }

// loadOrCreateSigningKey returns the active signing key, generating an RS256 one
// on first boot.
func (db *DB) loadOrCreateSigningKey() (*signingKey, error) {
	var id, alg, pemStr string
	err := db.conn.QueryRow(
		`SELECT id, algorithm, private_pem FROM signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&id, &alg, &pemStr)
	if err == nil {
		key, perr := parsePrivatePEM(pemStr)
		if perr != nil {
			return nil, perr
		}
		return &signingKey{id: id, algorithm: jose.SignatureAlgorithm(alg), key: key}, nil
	}
	return db.generateSigningKey(jose.RS256)
}

// loadAllSigningKeys returns every active key, newest first, for JWKS publication
// so tokens signed by a rotated-out key still validate during overlap.
func (db *DB) loadAllSigningKeys() ([]*signingKey, error) {
	rows, err := db.conn.Query(
		`SELECT id, algorithm, private_pem FROM signing_keys WHERE active = 1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*signingKey
	for rows.Next() {
		var id, alg, pemStr string
		if err := rows.Scan(&id, &alg, &pemStr); err != nil {
			return nil, err
		}
		key, perr := parsePrivatePEM(pemStr)
		if perr != nil {
			return nil, perr
		}
		out = append(out, &signingKey{id: id, algorithm: jose.SignatureAlgorithm(alg), key: key})
	}
	return out, rows.Err()
}

// loadActiveKeyByAlg returns the newest active signing key with the given
// algorithm, or an error if none exists.
func (db *DB) loadActiveKeyByAlg(alg jose.SignatureAlgorithm) (*signingKey, error) {
	var id, pemStr string
	err := db.conn.QueryRow(
		`SELECT id, private_pem FROM signing_keys WHERE active = 1 AND algorithm = ? ORDER BY created_at DESC LIMIT 1`,
		string(alg),
	).Scan(&id, &pemStr)
	if err != nil {
		return nil, err
	}
	key, perr := parsePrivatePEM(pemStr)
	if perr != nil {
		return nil, perr
	}
	return &signingKey{id: id, algorithm: alg, key: key}, nil
}

// generateSigningKey creates, persists and returns a fresh signing key of the
// requested algorithm (RS256 or ES256).
func (db *DB) generateSigningKey(alg jose.SignatureAlgorithm) (*signingKey, error) {
	if !IsSupportedAlg(alg) {
		return nil, fmt.Errorf("unsupported signature algorithm %q", alg)
	}
	var signer crypto.Signer
	var err error
	switch alg {
	case jose.ES256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	pemStr, err := encodePrivatePEM(signer)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	if _, err := db.conn.Exec(
		`INSERT INTO signing_keys (id, algorithm, private_pem, active) VALUES (?, ?, ?, 1)`,
		id, string(alg), pemStr,
	); err != nil {
		return nil, fmt.Errorf("store signing key: %w", err)
	}
	return &signingKey{id: id, algorithm: alg, key: signer}, nil
}

// ListKeys returns key metadata (no private material) for the admin UI.
func (db *DB) ListKeys() ([]KeyInfo, error) {
	rows, err := db.conn.Query(
		`SELECT id, algorithm, active, created_at FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyInfo
	for rows.Next() {
		var k KeyInfo
		var active int
		var created string
		if err := rows.Scan(&k.ID, &k.Algorithm, &active, &created); err != nil {
			return nil, err
		}
		k.Active = active != 0
		if t, perr := time.Parse(time.RFC3339, created); perr == nil {
			k.CreatedAt = t.Format("2006-01-02 15:04:05")
		} else {
			k.CreatedAt = created
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// encodePrivatePEM serializes any supported private key as PKCS#8 PEM.
func encodePrivatePEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// parsePrivatePEM parses a private key PEM, accepting PKCS#8 ("PRIVATE KEY"),
// legacy PKCS#1 RSA ("RSA PRIVATE KEY") and SEC1 EC ("EC PRIVATE KEY") blocks.
func parsePrivatePEM(s string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM for signing key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("parsed key is not a signer")
		}
		return signer, nil
	}
}
