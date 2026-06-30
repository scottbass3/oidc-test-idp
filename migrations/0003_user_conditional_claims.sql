-- Conditional claim rules per user: a JSON array of rules, each matching on the
-- requesting client_id and/or requested scopes, contributing extra claims. Lets a
-- user expose different claims depending on which app/scopes are asking.
ALTER TABLE users ADD COLUMN conditional_claims TEXT NOT NULL DEFAULT '[]';
