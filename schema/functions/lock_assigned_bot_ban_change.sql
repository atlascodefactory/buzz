-- A missing ban row cannot be row-locked. Mutations instead serialize with the
-- event's predicate lock; the event never locks a community_bans tuple.
CREATE FUNCTION lock_assigned_bot_ban_change() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
    ban_key TEXT;
BEGIN
    FOR ban_key IN
        SELECT DISTINCT keys.key FROM unnest(ARRAY[
            CASE WHEN TG_OP <> 'INSERT' THEN
                'buzz_assigned_bot_ban:' || OLD.community_id::text || ':' || encode(OLD.pubkey, 'hex') END,
            CASE WHEN TG_OP <> 'DELETE' THEN
                'buzz_assigned_bot_ban:' || NEW.community_id::text || ':' || encode(NEW.pubkey, 'hex') END
        ]) AS keys(key) WHERE keys.key IS NOT NULL ORDER BY keys.key
    LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(ban_key, 0));
    END LOOP;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;
