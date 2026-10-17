SELECT attach_community_write_fence('community_bans');

CREATE TRIGGER zz_assigned_bot_ban_change BEFORE INSERT OR UPDATE OR DELETE ON community_bans
FOR EACH ROW EXECUTE FUNCTION lock_assigned_bot_ban_change();
