//! Metadata-only operator-agent discovery and transactional name edits.

use buzz_core::CommunityId;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{Db, DbError, Result};

const MAX_HYGIENE_CHANNELS: i64 = 4096;

/// Capture canonical metadata and reserve the same discovery coordinate used by
/// ordinary publishers. The caller retains this lock through its atomic commit.
pub async fn rename_metadata_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    community: CommunityId,
    channel: Uuid,
    relay_pubkey: &[u8],
) -> Result<(super::ChannelRecord, Vec<super::MemberRecord>, u64)> {
    let lock = crate::replaceable::event_replacement_lock_key(
        community,
        39000,
        relay_pubkey,
        Some(channel.as_bytes()),
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock)
        .execute(&mut **tx)
        .await?;
    let row = sqlx::query(
        "SELECT id, name, channel_type::text AS channel_type, visibility::text AS visibility, \
         description, canvas, created_by, created_at, updated_at, archived_at, deleted_at, \
         nip29_group_id, topic_required, max_members, topic, topic_set_by, topic_set_at, \
         purpose, purpose_set_by, purpose_set_at, ttl_seconds, ttl_deadline \
         FROM channels WHERE community_id=$1 AND id=$2 AND deleted_at IS NULL",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .fetch_one(&mut **tx)
    .await?;
    let record = super::row_to_channel_record(row)?;
    let rows = sqlx::query(
        "SELECT channel_id, pubkey, role::text AS role, joined_at, invited_by, removed_at \
         FROM channel_members WHERE community_id=$1 AND channel_id=$2 AND removed_at IS NULL \
         ORDER BY joined_at, pubkey LIMIT 4097",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() > 4096 {
        return Err(DbError::InvalidData(
            "rename metadata roster exceeds 4096 members".into(),
        ));
    }
    let members = rows
        .into_iter()
        .map(crate::channel_members::row_to_member_record)
        .collect::<Result<Vec<_>>>()?;
    let head: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT created_at FROM events WHERE community_id=$1 AND channel_id=$2 AND kind=39000 \
         AND pubkey=$3 AND deleted_at IS NULL ORDER BY created_at DESC, id ASC LIMIT 1",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(relay_pubkey)
    .fetch_optional(&mut **tx)
    .await?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let timestamp = head
        .map(|ts| (ts.timestamp().max(0) as u64).saturating_add(1))
        .unwrap_or(now)
        .max(now);
    Ok((record, members, timestamp))
}

impl Db {
    /// Bounded non-DM channel IDs for a separately authorized metadata reader.
    /// Reads the writer: channel deletion/type changes must not lag authorization.
    pub async fn channel_hygiene_ids(&self, community: CommunityId) -> Result<Vec<Uuid>> {
        let mut connection = crate::observability::acquire_writer(
            &self.pool,
            crate::observability::WriterOperation::Authorization,
        )
        .await?;
        let ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM channels WHERE community_id = $1 AND deleted_at IS NULL \
             AND channel_type IN ('stream', 'forum') ORDER BY id LIMIT $2",
        )
        .bind(community.as_uuid())
        .bind(MAX_HYGIENE_CHANNELS + 1)
        .fetch_all(&mut *connection)
        .await?;
        if ids.len() as i64 > MAX_HYGIENE_CHANNELS {
            return Err(DbError::InvalidData(
                "channel hygiene inventory exceeds 4096 channels".into(),
            ));
        }
        Ok(ids)
    }
}

/// Rename under a channel row lock, composing with the signed request and audit
/// append in the caller's transaction. Optional expected-name protects plans and
/// compensating undo from overwriting a name that has changed since preview.
pub async fn rename_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    community: CommunityId,
    channel: Uuid,
    name: &str,
    expected_name: Option<&str>,
    reject_collision: bool,
) -> Result<String> {
    let name = buzz_core::channel::canonical_channel_name(name);
    if name.trim().is_empty() {
        return Err(DbError::InvalidData("channel name is required".into()));
    }
    // Serialize hygiene plans within a community, without blocking other tenants.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("buzz_channel_rename:{community}"))
        .execute(&mut **tx)
        .await?;
    let previous: String = sqlx::query_scalar(
        "SELECT name FROM channels WHERE community_id = $1 AND id = $2 \
         AND deleted_at IS NULL AND archived_at IS NULL FOR UPDATE",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| DbError::NotFound("active channel not found".into()))?;
    if expected_name.is_some_and(|expected| expected != previous) {
        return Err(DbError::InvalidData(
            "conflict: channel name changed since preview".into(),
        ));
    }
    if reject_collision && previous != name {
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM channels WHERE community_id = $1 AND id <> $2 \
             AND deleted_at IS NULL AND channel_type IN ('stream', 'forum') AND lower(name) = lower($3))",
        ).bind(community.as_uuid()).bind(channel).bind(name)
            .fetch_one(&mut **tx).await?;
        if conflict {
            return Err(DbError::InvalidData(
                "conflict: channel name already exists".into(),
            ));
        }
    }
    sqlx::query(
        "UPDATE channels SET name = $3, updated_at = now() WHERE community_id = $1 AND id = $2",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(name)
    .execute(&mut **tx)
    .await?;
    Ok(previous)
}
