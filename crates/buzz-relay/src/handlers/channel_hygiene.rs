//! Narrow platform-operator delegation: channel names and discovery, never content.

use std::sync::Arc;

use buzz_core::{CommunityId, StoredEvent, TenantContext};
use nostr::{Event, Filter};
use uuid::Uuid;

use crate::{api::admin, state::AppState};

fn tag_is(tag: &nostr::Tag, key: &str) -> bool {
    tag.as_slice().first().is_some_and(|value| value == key)
}

/// Resolve the verified owner on every request; roster revocation is not cached.
/// A moderator, community admin, profile claim, or another community's binding
/// must never become a deployment-operator grant.
pub(crate) async fn operator_owner(
    state: &AppState,
    community: CommunityId,
    agent: &[u8],
) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(owner) = state.db.get_agent_owner(community, agent).await? else {
        return Ok(None);
    };
    let owner: [u8; 32] = owner
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid verified agent owner"))?;
    if owner.as_slice() == agent {
        return Ok(None);
    }
    let principal = admin::lookup_admin_principal(state, owner)
        .await
        .map_err(|e| anyhow::anyhow!("platform authority lookup failed: {}", e.code))?;
    Ok(principal
        .filter(|p| p.role == admin::PlatformRole::Operator)
        .map(|_| owner))
}

/// Only a single name edit inherits authority. Fail closed on unknown tags so
/// future metadata fields cannot accidentally piggyback on this capability.
pub(crate) fn rename_only(event: &Event) -> bool {
    event.kind.as_u16() == 9002
        && event.content.is_empty()
        && event.tags.iter().filter(|t| tag_is(t, "h")).count() == 1
        && event.tags.iter().filter(|t| tag_is(t, "name")).count() == 1
        && event.tags.iter().all(|tag| {
            let parts = tag.as_slice();
            match parts.first().map(String::as_str) {
                Some("h" | "name" | "expected-name") => parts.len() == 2,
                // The unchanged CLI attaches its NIP-OA credential to writes.
                // This is transport provenance, never another metadata field.
                Some("auth") => parts.len() == 4,
                _ => false,
            }
        })
        && event
            .tags
            .iter()
            .filter(|t| tag_is(t, "expected-name"))
            .count()
            <= 1
        && event.tags.iter().filter(|t| tag_is(t, "auth")).count() <= 1
}

/// Widen only an explicitly metadata-only historical query, never a kindless
/// filter, an OR-with-messages filter, search, rosters, or live subscriptions.
pub(crate) fn metadata_only(filter: &Filter) -> bool {
    filter.search.is_none()
        && filter
            .kinds
            .as_ref()
            .is_some_and(|kinds| kinds.len() == 1 && kinds.iter().all(|k| k.as_u16() == 39000))
}

/// Bounded, tenant-local non-DM discovery. Token channel fences still apply.
pub(crate) async fn metadata_channels(
    state: &AppState,
    community: CommunityId,
    actor: &[u8],
    filters: &[Filter],
    token_channels: Option<&[Uuid]>,
) -> anyhow::Result<Vec<Uuid>> {
    if !filters.iter().any(metadata_only)
        || operator_owner(state, community, actor).await?.is_none()
    {
        return Ok(Vec::new());
    }
    let mut ids = state.db.channel_hygiene_ids(community).await?;
    if let Some(allowed) = token_channels {
        ids.retain(|id| allowed.contains(id));
    }
    Ok(ids)
}

/// Union is request/filter local: it must not enter membership caches or the
/// subscription registry, which also authorize messages and member lists.
pub(crate) fn read_channels<'a>(
    filter: &Filter,
    ordinary: &'a [Uuid],
    metadata: &'a [Uuid],
    combined: &'a [Uuid],
) -> &'a [Uuid] {
    if metadata_only(filter) && !metadata.is_empty() {
        combined
    } else {
        ordinary
    }
}

/// Persist a plain rename and its before/after audit entry in one commit.
/// Existing channel-role grants continue through validation; no delete policy
/// or role assignment is changed here.
pub(crate) async fn persist_rename(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: &Event,
) -> anyhow::Result<(StoredEvent, bool)> {
    let channel = super::side_effects::extract_h_tag_channel(event)
        .ok_or_else(|| anyhow::anyhow!("invalid channel"))?;
    let value = |key: &str| {
        event
            .tags
            .iter()
            .find(|t| tag_is(t, key))
            .and_then(|t| t.content())
    };
    let name = value("name").ok_or_else(|| anyhow::anyhow!("missing name"))?;
    let owner = operator_owner(state, tenant.community(), &event.pubkey.to_bytes()).await?;
    let reject_collision = if owner.is_some() {
        !matches!(
            state
                .db
                .get_member_role(tenant.community(), channel, &event.pubkey.to_bytes())
                .await?
                .as_deref(),
            Some("owner" | "admin")
        )
    } else {
        false
    };

    let mut tx = state
        .db
        .begin_event_write_transaction(tenant.community())
        .await?;
    let (stored, inserted) =
        buzz_db::event::insert_event_in_transaction(&mut tx, event, Some(channel)).await?;
    let mut metadata = None;
    if inserted {
        let previous = buzz_db::channel::rename_in_transaction(
            &mut tx,
            channel,
            name,
            value("expected-name"),
            reject_collision,
        )
        .await?;
        buzz_audit::AuditService::log_in_transaction(&mut tx, buzz_audit::NewAuditEntry {
            community_id: tenant.community(),
            action: buzz_audit::AuditAction::ChannelUpdated,
            actor_pubkey: Some(event.pubkey.to_bytes().to_vec()),
            object_id: Some(channel.to_string()),
            detail: serde_json::json!({
                "operation": "rename", "event_id": event.id.to_hex(),
                "old_name": previous, "new_name": buzz_core::channel::canonical_channel_name(name),
                "operator_owner": owner.map(hex::encode),
            }),
        }).await?;
        let (record, members, timestamp) = buzz_db::channel::rename_metadata_snapshot(
            &mut tx,
            channel,
            &state.relay_keypair.public_key().to_bytes(),
        )
        .await?;
        let tags = super::side_effects::group_metadata_tags(&record, &members)?;
        let snapshot = nostr::EventBuilder::new(nostr::Kind::Custom(39000), "")
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(timestamp))
            .sign_with_keys(&state.relay_keypair)?;
        let (saved, replaced) = state
            .db
            .replace_addressable_event_in_transaction(&mut tx, &snapshot, Some(channel))
            .await?;
        anyhow::ensure!(replaced, "rename metadata was not replaced");
        metadata = Some(saved);
    }
    tx.commit().await?;
    if let Some(metadata) = metadata {
        super::event::dispatch_persistent_event(
            tenant,
            state,
            &metadata,
            39000,
            &state.relay_keypair.public_key().to_hex(),
            None,
        )
        .await;
    }
    Ok((stored, inserted))
}

#[cfg(test)]
mod postgres_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn edit(tags: &[&[&str]], content: &str) -> Event {
        EventBuilder::new(Kind::Custom(9002), content)
            .tags(tags.iter().map(|t| Tag::parse(t.iter().copied()).unwrap()))
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    #[test]
    fn inherited_rename_rejects_mixed_and_ambiguous_edits() {
        let base = [&["h", "channel"][..], &["name", "new"][..]];
        assert!(rename_only(&edit(&base, "")));
        assert!(rename_only(&edit(
            &[base[0], base[1], &["expected-name", "old"]],
            ""
        )));
        for tag in [
            "about",
            "visibility",
            "archived",
            "ttl",
            "topic",
            "purpose",
            "t",
            "p",
            "future",
        ] {
            assert!(
                !rename_only(&edit(&[base[0], base[1], &[tag, "value"]], "")),
                "{tag}"
            );
        }
        assert!(!rename_only(&edit(&[base[0], base[1], base[1]], "")));
        assert!(!rename_only(&edit(&[base[0], base[1], base[0]], "")));
        assert!(!rename_only(&edit(&base, "hidden payload")));
    }

    #[test]
    fn discovery_never_widens_mixed_or_kindless_filters() {
        for value in [
            r#"{}"#,
            r#"{"kinds":[9,39000]}"#,
            r#"{"kinds":[39001]}"#,
            r#"{"kinds":[39000],"search":"secret"}"#,
        ] {
            assert!(!metadata_only(
                &serde_json::from_str::<Filter>(value).unwrap()
            ));
        }
        assert!(metadata_only(&Filter::new().kind(Kind::Custom(39000))));
    }
}
