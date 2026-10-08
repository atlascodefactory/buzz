//! Private, single-use observations for the pinned assignment authority.

use super::*;

/// Observe an exact assignment on the writer without registering or admitting it.
///
/// The caller must verify the authority signature and acquire the community
/// write fence first. A nonce is consumed atomically with the observation; it is
/// not a public event or an admission receipt. All returned state comes from one
/// statement snapshot. This is evidence for reconciliation, not an access grant
/// or a promise that membership cannot change after the observation.
pub async fn inspect_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    command: &AssignedBotCommand,
) -> Result<serde_json::Value> {
    let AssignedBotOperation::Inspect { cursor, receipt } = command.operation() else {
        return Err(DbError::InvalidData(
            "expected assignment inspection".into(),
        ));
    };
    let community = command.community();
    let bot = command.bot().to_bytes();
    let owner = command.owner().to_bytes();
    let authority = command.authority().to_bytes();
    // Same lifecycle key as admission/revocation, including a missing assignment.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))")
        .bind(format!(
            "buzz_assigned_bot:{community}:{}",
            hex::encode(bot)
        ))
        .execute(&mut **tx)
        .await?;
    require_current_lifetime(tx, command).await?;
    // Expired signed commands can never be replayed. Bound cleanup work and keep
    // it scoped to this authority/community; no background process is needed.
    sqlx::query(
        "DELETE FROM assigned_bot_inspections WHERE (community_id, authority_pubkey, nonce) IN \
         (SELECT community_id, authority_pubkey, nonce FROM assigned_bot_inspections \
          WHERE community_id = $1 AND authority_pubkey = $2 AND expires_at <= clock_timestamp() \
          ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)",
    )
    .bind(community.as_uuid())
    .bind(authority.as_slice())
    .execute(&mut **tx)
    .await?;
    let expires_at = i64::try_from(command.expires_at())
        .ok()
        .and_then(|s| DateTime::from_timestamp(s, 0))
        .ok_or_else(|| DbError::InvalidData("invalid inspection expiration".into()))?;
    let inserted = sqlx::query(
        "INSERT INTO assigned_bot_inspections (community_id, authority_pubkey, nonce, expires_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(community.as_uuid())
    .bind(authority.as_slice())
    .bind(command.nonce())
    .bind(expires_at)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(DbError::AccessDenied("inspection nonce was reused".into()));
    }
    require_current_lifetime(tx, command).await?;
    let observation: serde_json::Value = sqlx::query_scalar(r#"
        WITH assignment AS MATERIALIZED (
            SELECT * FROM assigned_bots WHERE community_id = $1 AND bot_pubkey = $2
        ), state AS MATERIALIZED (
            SELECT
                NOT EXISTS (SELECT 1 FROM assignment WHERE assignment_id <> $5
                    OR authority_pubkey <> $4 OR owner_pubkey <> $3 OR generation <> $6) AS matches,
                EXISTS (SELECT 1 FROM users u JOIN relay_members r
                    ON r.community_id = u.community_id AND r.pubkey = encode(u.pubkey, 'hex')
                    WHERE u.community_id = $1 AND u.pubkey = $3 AND u.deactivated_at IS NULL
                    AND NOT EXISTS (SELECT 1 FROM community_bans b WHERE b.community_id = $1
                        AND b.pubkey = $3 AND b.banned
                        AND (b.ban_expires_at IS NULL OR b.ban_expires_at > statement_timestamp()))) AS owner_active,
                EXISTS (SELECT 1 FROM assignment) AS present,
                EXISTS (SELECT 1 FROM assignment WHERE revoked_at IS NOT NULL) AS revoked
        ), page AS MATERIALIZED (
            -- Atlas bounds names to 200 UTF-16 units; 100 SQL characters also
            -- fit when every character is a supplementary-plane emoji.
            SELECT c.id, left(c.name, 100) AS name, c.channel_type::text AS channel_type,
                c.visibility::text AS visibility, m.role::text AS owner_role,
                bot.role::text AS bot_role, c.ttl_deadline
            FROM channels c
            JOIN channel_members m ON m.community_id = c.community_id AND m.channel_id = c.id
            LEFT JOIN channel_members bot ON bot.community_id = c.community_id AND bot.channel_id = c.id
                AND bot.pubkey = $2 AND bot.removed_at IS NULL
            WHERE c.community_id = $1 AND m.pubkey = $3 AND m.removed_at IS NULL
                AND m.role::text IN ('owner', 'admin', 'member')
                AND c.deleted_at IS NULL AND c.archived_at IS NULL
                AND (c.ttl_deadline IS NULL OR c.ttl_deadline > statement_timestamp())
                AND c.channel_type::text IN ('stream', 'forum')
                AND ($7::uuid IS NULL OR c.id > $7)
                AND (SELECT matches AND owner_active FROM state)
            ORDER BY c.id LIMIT 101
        ), visible AS MATERIALIZED (SELECT * FROM page ORDER BY id LIMIT 100)
        SELECT jsonb_build_object(
            'version', 1, 'communityId', $1::uuid, 'ownerPublicKey', encode($3, 'hex'),
            'botPublicKey', encode($2, 'hex'), 'assignmentId', $5::uuid, 'generation', $6::bigint,
            'coordinateMatch', state.matches, 'ownerActive', state.owner_active,
            'assignmentState', CASE WHEN NOT state.present THEN 'missing'
                WHEN state.revoked THEN 'revoked' ELSE 'active' END,
            'receiptCommitted', state.matches AND EXISTS (
                SELECT 1 FROM assigned_bot_commands r WHERE r.community_id = $1
                    AND r.bot_pubkey = $2 AND r.event_id = $8),
            'accessReady', state.matches AND state.present AND state.owner_active
                AND assigned_bot_access_allowed($1, $2, NULL),
            'observedAt', statement_timestamp(),
            'channels', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                'channelId', id, 'name', name, 'channelType', channel_type,
                'visibility', CASE WHEN visibility = 'open' THEN 'open' ELSE 'closed' END,
                'ownerRole', owner_role, 'botRole', bot_role, 'expiresAt', ttl_deadline,
                'botAccessReady', state.present AND state.matches AND state.owner_active
                    AND COALESCE(bot_role = 'bot', false) AND assigned_bot_access_allowed($1, $2, id)
            ) ORDER BY id) FROM visible), '[]'::jsonb),
            'nextCursor', CASE WHEN (SELECT count(*) FROM page) > 100
                THEN (SELECT id FROM visible ORDER BY id DESC LIMIT 1) ELSE NULL END
        ) FROM state
    "#).bind(community.as_uuid()).bind(bot.as_slice()).bind(owner.as_slice())
        .bind(authority.as_slice()).bind(command.assignment_id()).bind(command.generation())
        .bind(cursor).bind(receipt.map(|id| id.to_bytes().to_vec()))
        .fetch_one(&mut **tx).await?;
    if observation
        .get("coordinateMatch")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(DbError::AccessDenied(
            "assignment coordinates or generation changed".into(),
        ));
    }
    require_current_lifetime(tx, command).await?;
    Ok(observation)
}
