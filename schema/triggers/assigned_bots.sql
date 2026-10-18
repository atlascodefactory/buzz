CREATE TRIGGER zz_assigned_bot_creation BEFORE INSERT ON assigned_bots
FOR EACH ROW EXECUTE FUNCTION lock_assigned_bot_creation();


SELECT attach_community_write_fence('assigned_bots');
