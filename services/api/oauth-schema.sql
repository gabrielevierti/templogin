CREATE TABLE IF NOT EXISTS oauth_pending (
  state_hash TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
  browser_binding_hash TEXT NOT NULL,
  verifier TEXT NOT NULL,
  nonce TEXT,
  scopes JSONB NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_pending_expiry ON oauth_pending(expires_at);
CREATE TABLE IF NOT EXISTS oauth_connections (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  subject TEXT,
  scopes JSONB NOT NULL,
  token_envelope JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'linked' CHECK(status IN ('linked','reauthorization_required')),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  UNIQUE(user_id,provider_id)
);
CREATE INDEX IF NOT EXISTS oauth_connections_user ON oauth_connections(user_id);
