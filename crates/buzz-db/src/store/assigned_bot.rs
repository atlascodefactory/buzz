//! Durable authority-attested bot lifecycle, independent of NIP-OA ownership.
//!
//! These functions are not an ingress authorization shortcut. The Relay must
//! construct the command with its server-resolved community and pinned authority,
//! acquire the community serving-write fence, and commit only after success.

use buzz_core::assigned_bot::{AssignedBotCommand, AssignedBotOperation};
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{DbError, Result};

#[path = "assigned_bot_inspection.rs"]
mod inspection;
pub use inspection::inspect_in_transaction;

/// Apply a verified command and retain its nonce atomically with its effects.
///
/// Lock order is bot lifecycle, then channel membership/TTL/row (for admission).
/// A revocation tombstone wins even when it arrives before the first admission.
/// A generation cannot be resurrected. Owner, issuer and assignment are immutable
/// across generations; owner-key recovery must use a new bot. A higher admission generation is
/// allowed only after the old one is revoked. Exact replay never re-adds a bot.
/// No NIP-OA owner field or repository capability is written by this function.
pub async fn apply_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    command: &AssignedBotCommand,
) -> Result<bool> {
    if matches!(command.operation(), AssignedBotOperation::Inspect { .. }) {
        return Err(DbError::InvalidData(
            "inspection cannot mutate an assignment".into(),
        ));
    }
    let community = *command.community().as_uuid();
    let bot = command.bot().to_bytes();
    let owner = command.owner().to_bytes();
    let authority = command.authority().to_bytes();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "buzz_assigned_bot:{community}:{}",
            hex::encode(bot)
        ))
        .execute(&mut **tx)
        .await?;
    require_current_lifetime(tx, command).await?;
    sqlx::query(
        "INSERT INTO assigned_bots (community_id, bot_pubkey, assignment_id, authority_pubkey, owner_pubkey, generation) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (community_id, bot_pubkey) DO NOTHING",
    ).bind(community).bind(bot.as_slice()).bind(command.assignment_id())
        .bind(authority.as_slice()).bind(owner.as_slice()).bind(command.generation())
        .execute(&mut **tx).await?;
    let current = sqlx::query(
        "SELECT assignment_id, authority_pubkey, owner_pubkey, generation, revoked_at \
         FROM assigned_bots WHERE community_id = $1 AND bot_pubkey = $2 FOR UPDATE",
    )
    .bind(community)
    .bind(bot.as_slice())
    .fetch_one(&mut **tx)
    .await?;
    let generation: i64 = current.try_get("generation")?;
    let revoked: Option<DateTime<Utc>> = current.try_get("revoked_at")?;
    if current.try_get::<uuid::Uuid, _>("assignment_id")? != command.assignment_id()
        || current.try_get::<Vec<u8>, _>("authority_pubkey")? != authority
        || generation > command.generation()
        || current.try_get::<Vec<u8>, _>("owner_pubkey")? != owner
    {
        return Err(DbError::AccessDenied(
            "assignment coordinates or generation changed".into(),
        ));
    }
    if matches!(command.operation(), AssignedBotOperation::Admit { .. })
        && ((generation == command.generation() && revoked.is_some())
            || (generation < command.generation() && revoked.is_none()))
    {
        return Err(DbError::AccessDenied(
            "assignment revoked or predecessor still active".into(),
        ));
    }
    let receipt = sqlx::query_scalar::<_, Vec<u8>>(
        "INSERT INTO assigned_bot_commands (community_id, bot_pubkey, nonce, event_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (community_id, bot_pubkey, nonce) DO NOTHING RETURNING event_id",
    ).bind(community).bind(bot.as_slice()).bind(command.nonce())
        .bind(command.event_id().to_bytes().as_slice()).fetch_optional(&mut **tx).await?;
    if receipt.is_none() {
        let previous: Vec<u8> = sqlx::query_scalar(
            "SELECT event_id FROM assigned_bot_commands WHERE community_id = $1 AND bot_pubkey = $2 AND nonce = $3",
        ).bind(community).bind(bot.as_slice()).bind(command.nonce()).fetch_one(&mut **tx).await?;
        if previous != command.event_id().to_bytes() {
            return Err(DbError::AccessDenied("assignment nonce was reused".into()));
        }
        return Ok(false);
    }
    require_current_lifetime(tx, command).await?;
    match command.operation() {
        AssignedBotOperation::Inspect { .. } => {
            return Err(DbError::InvalidData(
                "inspection cannot mutate an assignment".into(),
            ));
        }
        AssignedBotOperation::Admit { .. } => {
            if !crate::channel_members::admit_assigned_bot_in_transaction(tx, command).await? {
                return Err(DbError::AccessDenied(
                    "command already exists without its receipt".into(),
                ));
            }
            if generation < command.generation() {
                sqlx::query(
                    "UPDATE assigned_bots SET generation = $3, revoked_at = NULL \
                     WHERE community_id = $1 AND bot_pubkey = $2",
                )
                .bind(community)
                .bind(bot.as_slice())
                .bind(command.generation())
                .execute(&mut **tx)
                .await?;
            }
        }
        AssignedBotOperation::Revoke => {
            let (_, inserted) = crate::event::insert_event_in_transaction(
                tx,
                command.community(),
                command.event(),
                None,
            )
            .await?;
            if !inserted {
                return Err(DbError::AccessDenied(
                    "command already exists without its receipt".into(),
                ));
            }
            sqlx::query(
                "UPDATE assigned_bots SET generation = $3, revoked_at = COALESCE(revoked_at, clock_timestamp()) \
                 WHERE community_id = $1 AND bot_pubkey = $2",
            ).bind(community).bind(bot.as_slice()).bind(command.generation())
                .execute(&mut **tx).await?;
        }
    }
    Ok(true)
}

async fn require_current_lifetime(
    tx: &mut Transaction<'_, Postgres>,
    command: &AssignedBotCommand,
) -> Result<()> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let now = u64::try_from(now.timestamp())
        .map_err(|_| DbError::InvalidData("invalid database clock".into()))?;
    if !command.valid_at(now) {
        return Err(DbError::AccessDenied(
            "assignment command expired or premature".into(),
        ));
    }
    Ok(())
}

/// Read current writer-side withdrawal state; absence is not an assignment.
/// Consumers must still apply their ordinary membership/capability checks.
pub async fn is_revoked(pool: &PgPool, community: CommunityId, bot: &[u8]) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM assigned_bots WHERE community_id = $1 AND bot_pubkey = $2 AND revoked_at IS NOT NULL)",
    ).bind(community.as_uuid()).bind(bot).fetch_one(pool).await?)
}

/// Current writer-side assignment gate. `None` keeps legacy principals unchanged.
/// A channel checks BOTH current owner and bot memberships, even in open rooms.
/// This is a statement-time authorization decision, not an in-flight effect lock.
pub async fn access_status(
    pool: &PgPool,
    community: CommunityId,
    actor: &[u8],
    channel: Option<uuid::Uuid>,
) -> Result<Option<bool>> {
    let mut connection = crate::observability::acquire_writer(
        pool,
        crate::observability::WriterOperation::Authorization,
    )
    .await?;
    Ok(sqlx::query_scalar(
        "SELECT assigned_bot_access_allowed($1, $2, $3) FROM assigned_bots \
         WHERE community_id = $1 AND bot_pubkey = $2",
    )
    .bind(community.as_uuid())
    .bind(actor)
    .bind(channel)
    .fetch_optional(&mut *connection)
    .await?)
}

/// Batch delivery gate: one writer read for all distinct recipient principals.
/// Legacy keys pass unchanged; assigned bots must pass current lifecycle/channel
/// checks. A store error propagates so the delivery seam can fail closed.
pub async fn filter_recipients(
    pool: &PgPool,
    community: CommunityId,
    actors: &[Vec<u8>],
    channel: Option<uuid::Uuid>,
    require_membership: bool,
) -> Result<Vec<Vec<u8>>> {
    if actors.is_empty() {
        return Ok(Vec::new());
    }
    let mut connection = crate::observability::acquire_writer(
        pool,
        crate::observability::WriterOperation::Authorization,
    )
    .await?;
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT actor FROM unnest($2::bytea[]) AS recipient(actor) \
         WHERE assigned_bot_access_allowed($1, actor, $3) \
         AND (NOT $4 OR EXISTS (SELECT 1 FROM channel_members m \
              JOIN channels c ON c.community_id = m.community_id AND c.id = m.channel_id \
              WHERE m.community_id = $1 AND m.channel_id = $3 \
              AND m.pubkey = actor AND m.removed_at IS NULL AND c.deleted_at IS NULL))",
    )
    .bind(community.as_uuid())
    .bind(actors)
    .bind(channel)
    .bind(require_membership)
    .fetch_all(&mut *connection)
    .await?)
}

impl crate::Db {
    /// Persist a WebSocket gift wrap under its authenticated transport actor.
    ///
    /// The envelope's ephemeral signer is not transport authority. Both actors'
    /// assignment fences, the event and mention rows share a single commit.
    /// The caller must authenticate the actor and verify the signed envelope.
    pub async fn insert_authenticated_gift_wrap(
        &self,
        community: CommunityId,
        event: &nostr::Event,
        actor: &nostr::PublicKey,
    ) -> Result<(buzz_core::StoredEvent, bool)> {
        let mut tx = self.begin_event_write_transaction().await?;
        let result = self
            .insert_authenticated_gift_wrap_in_transaction(&mut tx, community, event, actor)
            .await?;
        tx.commit().await?;
        Ok(result)
    }

    async fn insert_authenticated_gift_wrap_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        community: CommunityId,
        event: &nostr::Event,
        actor: &nostr::PublicKey,
    ) -> Result<(buzz_core::StoredEvent, bool)> {
        if event.kind != nostr::Kind::GiftWrap {
            return Err(DbError::InvalidData("expected gift-wrap envelope".into()));
        }
        self.deletion_store()
            .guard_transaction(tx, community)
            .await?;
        let mut principals = vec![actor.to_bytes(), event.pubkey.to_bytes()];
        principals.sort_unstable();
        principals.dedup();
        // Take both lifecycle predicates before any assignment/user row locks.
        // Otherwise a reversed actor/envelope pair could invert command locks.
        for principal in &principals {
            sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))")
                .bind(format!(
                    "buzz_assigned_bot:{community}:{}",
                    hex::encode(principal)
                ))
                .execute(&mut **tx)
                .await?;
        }
        for principal in &principals {
            sqlx::query("SELECT lock_assigned_bot_event_actor($1, $2, NULL)")
                .bind(community.as_uuid())
                .bind(principal.as_slice())
                .execute(&mut **tx)
                .await?;
        }
        let result =
            crate::event::insert_event_with_thread_metadata_tx(tx, community, event, None, None)
                .await?;
        if result.1 {
            crate::insert_mentions_in_transaction(tx, community, event, None).await?;
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "assigned_bot_postgres_tests.rs"]
mod postgres_tests;
