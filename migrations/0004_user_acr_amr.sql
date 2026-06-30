-- Per-user authentication context: acr (authentication context class reference)
-- and amr (authentication methods references), asserted into id_tokens so a
-- developer can mock step-up / MFA behavior of a target IdP.
ALTER TABLE users ADD COLUMN acr TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN amr TEXT NOT NULL DEFAULT '[]';
