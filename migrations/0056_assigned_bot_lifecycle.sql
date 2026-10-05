-- Separate authority-attested assignments, NOT users.agent_owner_pubkey/NIP-OA.
-- Revocation can arrive before first admission, so key columns deliberately do
-- not reference users. Tombstones must survive profile deletion/key retirement.
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

-- Durable, assignment-scoped nonce receipts are not replaceable events and are
-- never erased by a profile update or ordinary event-retention cleanup.
CREATE TABLE assigned_bot_commands (
    community_id UUID NOT NULL,
    bot_pubkey BYTEA NOT NULL,
    nonce UUID NOT NULL CHECK (nonce <> '00000000-0000-0000-0000-000000000000'::uuid),
    event_id BYTEA NOT NULL CHECK (length(event_id) = 32),
    PRIMARY KEY (community_id, bot_pubkey, nonce),
    UNIQUE (community_id, event_id),
    FOREIGN KEY (community_id, bot_pubkey) REFERENCES assigned_bots (community_id, bot_pubkey)
);

SELECT attach_community_write_fence('assigned_bots');
SELECT attach_community_write_fence('assigned_bot_commands');

-- An assignment limits its own bot; it never grants authority to another key.
-- STABLE uses the current statement snapshot. Callers must recheck at effect/
-- delivery boundaries; this function alone is not an in-flight commit fence.
CREATE FUNCTION assigned_bot_access_allowed(target UUID, actor BYTEA, channel UUID DEFAULT NULL)
RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path = public AS $$
    SELECT NOT EXISTS (
        SELECT 1 FROM assigned_bots a
        WHERE a.community_id = target AND a.bot_pubkey = actor
          AND NOT (
              a.revoked_at IS NULL
              AND EXISTS (
                  SELECT 1 FROM users u WHERE u.community_id = target
                    AND u.pubkey = a.bot_pubkey AND u.deactivated_at IS NULL
                    AND (u.agent_owner_pubkey IS NULL OR u.agent_owner_pubkey = a.owner_pubkey)
              )
              AND EXISTS (
                  SELECT 1 FROM users u WHERE u.community_id = target
                    AND u.pubkey = a.owner_pubkey AND u.deactivated_at IS NULL
              )
              AND EXISTS (
                  SELECT 1 FROM relay_members r WHERE r.community_id = target
                    AND r.pubkey = encode(a.owner_pubkey, 'hex')
              )
              AND NOT EXISTS (
                  SELECT 1 FROM community_bans b WHERE b.community_id = target
                    AND b.pubkey IN (a.bot_pubkey, a.owner_pubkey)
                    AND b.banned AND (b.ban_expires_at IS NULL OR b.ban_expires_at > statement_timestamp())
              )
              AND (channel IS NULL OR EXISTS (
                  SELECT 1 FROM channels c
                  JOIN channel_members bot ON bot.community_id = c.community_id AND bot.channel_id = c.id
                  JOIN channel_members owner ON owner.community_id = c.community_id AND owner.channel_id = c.id
                  WHERE c.community_id = target AND c.id = channel AND c.deleted_at IS NULL
                    AND bot.pubkey = a.bot_pubkey AND bot.removed_at IS NULL
                    AND owner.pubkey = a.owner_pubkey AND owner.removed_at IS NULL
              ))
          )
    )
$$;

-- Fence durable event insertion in its own transaction, including producers
-- which do not enter the Relay's early statement-time authorization gate.
-- Row locks serialize existing assignment/identity/membership withdrawals with
-- commit. This is not a fence for a newly inserted ban, Git or delivery.
CREATE FUNCTION enforce_assigned_bot_event_write() RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SET search_path = public AS $$
DECLARE
    owner_key BYTEA;
BEGIN
    SELECT a.owner_pubkey INTO owner_key FROM assigned_bots a
    WHERE a.community_id = NEW.community_id AND a.bot_pubkey = NEW.pubkey
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.channel_id IS NOT NULL THEN
        -- The deferred TTL refresh and TTL transitions use this same key
        -- before updating the channel row. No SHARE-to-UPDATE row upgrade.
        PERFORM pg_advisory_xact_lock_shared(hashtextextended(
            'buzz_channel_ttl:' || NEW.community_id::text || ':' || NEW.channel_id::text, 0));
        PERFORM 1 FROM channels c
        WHERE c.community_id = NEW.community_id AND c.id = NEW.channel_id
        FOR NO KEY UPDATE;
    END IF;
    PERFORM 1 FROM users u
    WHERE u.community_id = NEW.community_id AND u.pubkey IN (NEW.pubkey, owner_key)
    ORDER BY u.pubkey FOR SHARE;
    PERFORM 1 FROM relay_members r
    WHERE r.community_id = NEW.community_id AND r.pubkey = encode(owner_key, 'hex')
    FOR SHARE;
    IF NEW.channel_id IS NOT NULL THEN
        PERFORM 1 FROM channel_members m
        WHERE m.community_id = NEW.community_id AND m.channel_id = NEW.channel_id
          AND m.pubkey IN (NEW.pubkey, owner_key)
        ORDER BY m.pubkey FOR SHARE;
    END IF;

    -- VOLATILE runs this query with a fresh snapshot after any lock wait.
    IF NOT assigned_bot_access_allowed(NEW.community_id, NEW.pubkey, NEW.channel_id) THEN
        RAISE EXCEPTION 'assigned bot event write withdrawn'
            USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'assigned_bot_event_write';
    END IF;
    RETURN NEW;
END
$$;
-- Run after the existing community write fence so lock ordering is unchanged.
CREATE TRIGGER zz_assigned_bot_event_write BEFORE INSERT ON events
FOR EACH ROW EXECUTE FUNCTION enforce_assigned_bot_event_write();
