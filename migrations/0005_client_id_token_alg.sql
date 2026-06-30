-- Optional per-client id_token (and JWT access token) signing algorithm. Empty
-- means use the IdP's current default signing key. Lets a client's tokens be
-- signed with a specific alg (RS256/ES256) to match a target IdP.
ALTER TABLE clients ADD COLUMN id_token_sign_alg TEXT NOT NULL DEFAULT '';
