-- Phase 1: identity, sessions, devices. Later phases add vaults, secrets,
-- envelopes, orgs and audit (docs/design/cloud-mvp.md).

CREATE TABLE users (
  id           TEXT PRIMARY KEY,
  github_id    INTEGER NOT NULL UNIQUE,
  github_login TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

-- A session is one sign-in; it is the refresh-token family. Revoking it
-- voids every access and refresh token issued under it.
CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id),
  device_id  TEXT REFERENCES devices(id),
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

-- Tokens are stored only as SHA-256 hashes.
CREATE TABLE access_tokens (
  hash       TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE refresh_tokens (
  hash       TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);

CREATE TABLE devices (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id),
  name       TEXT NOT NULL,
  public_key TEXT NOT NULL,          -- base64 X25519 public key (32 bytes)
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  UNIQUE (user_id, public_key)
);

CREATE INDEX idx_access_tokens_session ON access_tokens(session_id);
CREATE INDEX idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX idx_devices_user ON devices(user_id);
