
-- CoinForest Authentication Foundation
-- Builds on the existing CoinForest schema.
-- Does not replace or modify existing KYC/investment tables.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Ensure the expected roles exist.
INSERT INTO roles (id, name)
VALUES
  ('35d67501-d0ca-4110-9f16-a4dc085af32f', 'admin'),
  ('9dbe97ec-7b11-4789-b31b-bff00bc2483e', 'user')
ON CONFLICT (id) DO NOTHING;

-- Password credentials are kept separate from the customer profile.
CREATE TABLE IF NOT EXISTS auth_credentials (
  user_id UUID PRIMARY KEY
    REFERENCES profiles(id)
    ON DELETE CASCADE,

  password_hash TEXT NOT NULL,

  password_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  failed_login_attempts INTEGER NOT NULL DEFAULT 0,

  locked_until TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS auth_credentials_locked_until_idx
  ON auth_credentials (locked_until);

-- Sessions used by the CoinForest application.
CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id UUID NOT NULL
    REFERENCES profiles(id)
    ON DELETE CASCADE,

  session_token_hash TEXT UNIQUE NOT NULL,

  ip_address INET,

  user_agent TEXT,

  device_name TEXT,

  status TEXT NOT NULL DEFAULT 'active',

  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  expires_at TIMESTAMPTZ NOT NULL,

  revoked_at TIMESTAMPTZ,

  revoked_by UUID
    REFERENCES profiles(id)
    ON DELETE SET NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_sessions_user_id_idx
  ON user_sessions (user_id);

CREATE INDEX IF NOT EXISTS user_sessions_token_hash_idx
  ON user_sessions (session_token_hash);

CREATE INDEX IF NOT EXISTS user_sessions_status_idx
  ON user_sessions (status);

CREATE INDEX IF NOT EXISTS user_sessions_expires_at_idx
  ON user_sessions (expires_at);
