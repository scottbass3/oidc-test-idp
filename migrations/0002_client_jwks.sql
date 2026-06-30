-- Public JWKS for clients using private_key_jwt authentication. The client signs
-- its token-request assertions with a private key; the OP validates them with the
-- matching public key found here by `kid`.
ALTER TABLE clients ADD COLUMN jwks TEXT NOT NULL DEFAULT '{}';
