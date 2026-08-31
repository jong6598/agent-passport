PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS passports (
  did TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('self-registered-unverified', 'verified', 'blocked')),
  profile_json TEXT NOT NULL,
  registration_json TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_ip ON challenges(ip_hash, created_at);

CREATE TABLE IF NOT EXISTS ip_limits (
  day TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  challenge_count INTEGER NOT NULL DEFAULT 0 CHECK(challenge_count >= 0),
  registration_count INTEGER NOT NULL DEFAULT 0 CHECK(registration_count >= 0),
  PRIMARY KEY(day, ip_hash)
);

CREATE TABLE IF NOT EXISTS global_limits (
  day TEXT PRIMARY KEY,
  registration_count INTEGER NOT NULL DEFAULT 0 CHECK(registration_count >= 0)
);
