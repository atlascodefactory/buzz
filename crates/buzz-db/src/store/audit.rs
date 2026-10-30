//! Narrow audit-chain storage for community-admitted domain transactions.

use crate::{AdmittedTx, Result};
use chrono::{DateTime, Utc};

/// Row supplied by the audit service after canonical hashing.
pub struct AuditAppend<'a> {
    /// Sequence within this community's chain.
    pub seq: i64,
    /// Canonical hash encoding version.
    pub hash_version: i16,
    /// Canonical entry hash.
    pub hash: &'a [u8],
    /// Previous chain head hash.
    pub prev_hash: Option<&'a [u8]>,
    /// Audit action identifier.
    pub action: &'a str,
    /// Optional actor public key.
    pub actor_pubkey: Option<&'a [u8]>,
    /// Optional object identifier.
    pub object_id: Option<&'a str>,
    /// Structured audit details.
    pub detail: &'a serde_json::Value,
    /// Timestamp used when hashing the entry.
    pub created_at: DateTime<Utc>,
}

/// Hold the same per-community chain lock as ordinary audit writers and read its head.
pub async fn lock_head(tx: &mut AdmittedTx) -> Result<Option<(i64, Vec<u8>)>> {
    let community = tx.community();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("buzz_audit:{community}"))
        .execute(tx.conn())
        .await?;
    Ok(sqlx::query_as(
        "SELECT seq, hash FROM audit_log WHERE community_id=$1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(community.as_uuid())
    .fetch_optional(tx.conn())
    .await?)
}

/// Append a pre-hashed audit entry without exposing the admitted connection.
pub async fn append(tx: &mut AdmittedTx, row: AuditAppend<'_>) -> Result<()> {
    let community = tx.community();
    sqlx::query("INSERT INTO audit_log (community_id, seq, hash, prev_hash, action, actor_pubkey, object_id, detail, created_at, hash_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(community.as_uuid()).bind(row.seq).bind(row.hash).bind(row.prev_hash)
        .bind(row.action).bind(row.actor_pubkey).bind(row.object_id).bind(row.detail)
        .bind(row.created_at).bind(row.hash_version).execute(tx.conn()).await?;
    Ok(())
}
