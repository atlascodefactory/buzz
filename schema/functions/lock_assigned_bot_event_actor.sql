-- Fence durable event insertion in its own transaction, including producers
-- which do not enter the Relay's early statement-time authorization gate.
-- Predicate locks cover assignment/ban absence; row locks hold existing
-- assignment/identity/membership state. This is not a Git or delivery fence.
CREATE FUNCTION lock_assigned_bot_event_actor(target UUID, actor BYTEA, channel UUID)
RETURNS VOID
LANGUAGE plpgsql VOLATILE SET search_path = public AS $$
DECLARE
    owner_key BYTEA;
    ban_key BYTEA;
BEGIN
    -- Match the command helper and creation trigger before testing absence.
    PERFORM pg_advisory_xact_lock_shared(hashtextextended(
        'buzz_assigned_bot:' || target::text || ':' || encode(actor, 'hex'), 0));
    SELECT a.owner_pubkey INTO owner_key FROM assigned_bots a
    WHERE a.community_id = target AND a.bot_pubkey = actor
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    FOR ban_key IN SELECT DISTINCT principals.pubkey
        FROM unnest(ARRAY[actor, owner_key]) AS principals(pubkey)
        ORDER BY principals.pubkey
    LOOP
        PERFORM pg_advisory_xact_lock_shared(hashtextextended(
            'buzz_assigned_bot_ban:' || target::text || ':' || encode(ban_key, 'hex'), 0));
    END LOOP;

    IF channel IS NOT NULL THEN
        -- The deferred TTL refresh and TTL transitions use this same key
        -- before updating the channel row. No SHARE-to-UPDATE row upgrade.
        PERFORM pg_advisory_xact_lock_shared(hashtextextended(
            'buzz_channel_ttl:' || target::text || ':' || channel::text, 0));
        PERFORM 1 FROM channels c
        WHERE c.community_id = target AND c.id = channel
        FOR NO KEY UPDATE;
    END IF;
    PERFORM 1 FROM users u
    WHERE u.community_id = target AND u.pubkey IN (actor, owner_key)
    ORDER BY u.pubkey FOR SHARE;
    PERFORM 1 FROM relay_members r
    WHERE r.community_id = target AND r.pubkey = encode(owner_key, 'hex')
    FOR SHARE;
    IF channel IS NOT NULL THEN
        PERFORM 1 FROM channel_members m
        WHERE m.community_id = target AND m.channel_id = channel
          AND m.pubkey IN (actor, owner_key)
        ORDER BY m.pubkey FOR SHARE;
    END IF;

    -- VOLATILE runs this query with a fresh snapshot after any lock wait.
    IF NOT assigned_bot_access_allowed(target, actor, channel) THEN
        RAISE EXCEPTION 'assigned bot event write withdrawn'
            USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'assigned_bot_event_write';
    END IF;
END
$$;
