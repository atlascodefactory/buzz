//! Pinned assignment commands after common signature, actor, scope and ban gates.

use std::sync::Arc;

use buzz_core::assigned_bot::{AssignedBotCommand, AssignedBotOperation};
use buzz_core::tenant::TenantContext;
use nostr::{Event, PublicKey, Timestamp};
use uuid::Uuid;

use super::ingest::{IngestError, IngestResult};
use crate::state::AppState;

/// Validate the exact pin and commit lifecycle/receipt/membership as one write.
/// Roster publication happens separately after the caller records its write trace.
pub async fn accept(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: Event,
    actor: PublicKey,
    token_channels: Option<&[Uuid]>,
) -> Result<(IngestResult, Option<Uuid>), IngestError> {
    let community = tenant.community();
    let pin = state
        .config
        .assigned_bot_authority
        .as_ref()
        .and_then(|pin| pin.for_community(community));
    let command = tokio::task::spawn_blocking(move || {
        AssignedBotCommand::verify(
            &event,
            community,
            &actor,
            pin.as_ref(),
            Timestamp::now().as_secs(),
        )
    })
    .await
    .map_err(|_| IngestError::Internal("error: assignment verification failed".into()))?
    .map_err(|error| IngestError::Rejected(format!("restricted: {error}")))?;
    let channel = match command.operation() {
        AssignedBotOperation::Admit { channel_id, .. } => {
            if token_channels.is_some_and(|channels| !channels.contains(&channel_id)) {
                return Err(IngestError::AuthFailed(
                    "restricted: token does not cover assigned channel".into(),
                ));
            }
            Some(channel_id)
        }
        AssignedBotOperation::Revoke => {
            if token_channels.is_some() {
                return Err(IngestError::AuthFailed(
                    "restricted: assignment revocation requires a global token".into(),
                ));
            }
            None
        }
    };
    let mut tx = state
        .db
        .begin_event_write_transaction()
        .await
        .map_err(|_| IngestError::Internal("error: begin assigned bot command".into()))?;
    buzz_deletion::store(&state.db)
        .guard_transaction(&mut tx, community)
        .await
        .map_err(|_| IngestError::Rejected("restricted: community writes are fenced".into()))?;
    let inserted = buzz_db::assigned_bot::apply_in_transaction(&mut tx, &command)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(reason) | buzz_db::DbError::InvalidData(reason) => {
                IngestError::Rejected(format!("restricted: {reason}"))
            }
            buzz_db::DbError::ChannelNotFound(_) => {
                IngestError::Rejected("invalid: assigned channel not found".into())
            }
            _ => IngestError::Internal("error: assigned bot persistence failed".into()),
        })?;
    tx.commit()
        .await
        .map_err(|_| IngestError::Internal("error: commit assigned bot command".into()))?;
    if let Some(channel) = channel {
        state.invalidate_membership(tenant, channel, &command.bot().to_bytes());
    }
    Ok((
        IngestResult {
            event_id: command.event_id().to_hex(),
            accepted: true,
            message: if inserted {
                String::new()
            } else {
                "duplicate:".into()
            },
        },
        channel,
    ))
}

#[cfg(test)]
#[path = "assigned_bot_postgres_tests.rs"]
mod postgres_tests;
