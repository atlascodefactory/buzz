-- ── Assigned bot lifecycle (migration 0056) ──────────────────────────────────
-- Separate administrative attestations; never mint NIP-OA ownership. Unknown
-- assignments may receive revocation tombstones before any profile exists.
CREATE TABLE assigned_bots (
    community_id UUID NOT NULL REFERENCES communities(id),
    bot_pubkey BYTEA NOT NULL CHECK (length(bot_pubkey) = 32),
    assignment_id UUID NOT NULL CHECK (assignment_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    authority_pubkey BYTEA NOT NULL CHECK (length(authority_pubkey) = 32),
    owner_pubkey BYTEA NOT NULL CHECK (length(owner_pubkey) = 32),
    generation BIGINT NOT NULL CHECK (generation > 0),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, bot_pubkey),
    UNIQUE (community_id, assignment_id),
    CHECK (bot_pubkey <> owner_pubkey AND bot_pubkey <> authority_pubkey AND owner_pubkey <> authority_pubkey)
);
