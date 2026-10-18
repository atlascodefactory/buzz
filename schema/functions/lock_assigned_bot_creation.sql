-- Cover first assignment INSERTs even when they bypass the Rust command helper.
-- Do not add an UPDATE trigger that would invert tuple/advisory lock ordering.
CREATE FUNCTION lock_assigned_bot_creation() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'buzz_assigned_bot:' || NEW.community_id::text || ':' || encode(NEW.bot_pubkey, 'hex'), 0));
    RETURN NEW;
END
$$;
