CREATE FUNCTION enforce_assigned_bot_event_write() RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SET search_path = public AS $$
BEGIN
    PERFORM lock_assigned_bot_event_actor(NEW.community_id, NEW.pubkey, NEW.channel_id);
    RETURN NEW;
END
$$;
