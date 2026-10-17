-- Private, expiring single-use inspection nonces, including missing assignments.
-- Deliberately independent of assigned_bots: inspection never bootstraps a bot.
CREATE TABLE assigned_bot_inspections (
    community_id UUID NOT NULL REFERENCES communities(id),
    authority_pubkey BYTEA NOT NULL CHECK (length(authority_pubkey) = 32),
    nonce UUID NOT NULL CHECK (nonce <> '00000000-0000-0000-0000-000000000000'::uuid),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, authority_pubkey, nonce)
);

CREATE INDEX assigned_bot_inspections_expiry ON assigned_bot_inspections (community_id, authority_pubkey, expires_at);
