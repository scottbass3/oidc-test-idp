-- Optional custom subject (sub claim) per user, decoupled from the row id. Empty
-- means use the row id as the subject. Lets a developer mock a target IdP's exact
-- sub value (e.g. an opaque GUID or "auth0|abc123").
ALTER TABLE users ADD COLUMN subject TEXT NOT NULL DEFAULT '';
