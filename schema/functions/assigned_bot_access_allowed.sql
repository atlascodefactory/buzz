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
