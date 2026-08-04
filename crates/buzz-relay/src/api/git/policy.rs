//! Internal policy endpoint — pre-receive hook callback.
//!
//! The pre-receive hook POSTs here with HMAC-signed payload containing
//! the pusher's pubkey, repo ID, and ref updates. This endpoint:
//!
//! 1. Validates HMAC signature + 30s TTL (fail-closed)
//! 2. Resolves kind:30617 → protection rules
//! 3. Grants owner authority to the repo key or its verified managed-agent owner
//! 4. Otherwise resolves the pusher's channel role via buzz-channel binding
//! 5. Promotes Bot → Member (bots in a channel push as members)
//! 6. Calls `buzz_core::git_perms::evaluate_push()`
//! 7. Returns 200 (allow) or 403 (deny with reasons)
//!
//! # Bot Role Model
//!
//! Bots are intentionally added to channels by members/admins. For git push,
//! they're promoted to Member — protection rules still apply. Bot is a
//! designation (what it is), not a permission tier (what it can do). The
//! promotion is scoped to this module; the core `MemberRole::Bot` hierarchy
//! is unchanged.
//!
//! # Security invariants
//!
//! - Endpoint binds to 127.0.0.1 only (enforced at router level)
//! - HMAC binds callback to the specific push operation
//! - Fail-closed: any error → 403

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use nostr::{Event, JsonUtil, Kind};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{error, warn};

use uuid::Uuid;

use buzz_core::channel::MemberRole;
use buzz_core::git_perms::{
    evaluate_push_with_patch_authorizations, parse_protection_tags, Denial, PatchAuthorization,
    RefUpdate, UpdateKind, GIT_MERGE_AUTHORIZATION_MAX_AGE_SECS,
    GIT_MERGE_AUTHORIZATION_MAX_ENCODED_BYTES, GIT_NO_CHANNEL_BINDING_BODY,
};
use buzz_db::EventQuery;

use crate::state::AppState;

/// Maximum age of a hook callback (seconds). Push is synchronous so 30s is generous.
const MAX_CALLBACK_AGE_SECS: u64 = 30;

/// Request payload from the pre-receive hook.
#[derive(Debug, Clone, Deserialize)]
pub struct HookCallbackRequest {
    /// Repo identifier (d-tag from kind:30617).
    pub repo_id: String,
    /// Hex-encoded repo owner pubkey (from URL path, verified against kind:30617).
    pub repo_owner: String,
    /// Server-resolved community id from the git HTTP request that spawned the hook.
    /// Internal-only: set by relay env and HMAC-bound by the hook callback.
    pub community_id: String,
    /// Hex-encoded pusher pubkey.
    pub pusher_pubkey: String,
    /// Ref updates from git stdin (old_oid, new_oid, ref_name, is_ancestor).
    pub ref_updates: Vec<HookRefUpdate>,
    /// URL-safe base64 owner-signed NIP-34 merged status, or empty for a direct push.
    pub merge_authorization: String,
    /// Unix timestamp when the hook was invoked.
    pub timestamp: u64,
    /// HMAC-SHA256 signature over the canonical payload.
    pub signature: String,
}

/// A single ref update as reported by the pre-receive hook.
#[derive(Debug, Clone, Deserialize)]
pub struct HookRefUpdate {
    /// Old object ID (40 hex chars, zero OID for creates).
    pub old_oid: String,
    /// New object ID (40 hex chars, zero OID for deletes).
    pub new_oid: String,
    /// Full ref name (e.g., "refs/heads/main").
    pub ref_name: String,
    /// Result of `git merge-base --is-ancestor old new`.
    /// For creates/deletes this is false (ignored by classifier).
    pub is_ancestor: bool,
    /// Result of `git merge-base --is-ancestor <signed PR head> new`.
    /// False when the push carries no merge proof or the relation cannot be proven.
    pub merge_source_is_ancestor: bool,
}

/// Response to the hook — either allow or deny.
#[derive(Debug, Serialize)]
pub struct HookCallbackResponse {
    /// Whether the push is allowed.
    pub allowed: bool,
    /// Denial reasons (empty if allowed).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub denials: Vec<DenialResponse>,
}

/// A single denial reason in the hook response.
#[derive(Debug, Serialize)]
pub struct DenialResponse {
    /// The ref that was denied.
    pub ref_name: String,
    /// Human-readable reason for denial.
    pub reason: String,
}

impl From<Denial> for DenialResponse {
    fn from(d: Denial) -> Self {
        Self {
            ref_name: d.ref_name,
            reason: d.reason,
        }
    }
}

/// Compute the canonical HMAC payload.
///
/// Format (length-prefixed, `|`-separated, structurally unambiguous):
/// ```text
/// len(repo_id):repo_id | repo_owner(64) | community_id(36) | pusher(64) |
/// sorted_refs | len(merge_authorization):merge_authorization | timestamp
/// ```
/// where each ref is: `old_oid(40) + new_oid(40) + len(ref_name):ref_name
/// + is_ancestor("1"/"0") + merge_source_is_ancestor("1"/"0")`
///
/// Fixed-length fields (OIDs=40, pubkeys=64) need no length prefix.
/// Variable-length fields (repo_id, ref_name) are length-prefixed to prevent concatenation ambiguity.
fn compute_hmac(secret: &[u8], req: &HookCallbackRequest) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC can take key of any size");

    // Structurally unambiguous format: length-prefixed fields separated by |.
    // This prevents field confusion attacks (e.g., repo_id="a|b" being parsed differently).
    mac.update(req.repo_id.len().to_string().as_bytes());
    mac.update(b":");
    mac.update(req.repo_id.as_bytes());
    mac.update(b"|");
    mac.update(req.repo_owner.as_bytes()); // Fixed 64 chars, no ambiguity.
    mac.update(b"|");
    mac.update(req.community_id.as_bytes()); // Fixed UUID string from server-resolved tenant.
    mac.update(b"|");
    mac.update(req.pusher_pubkey.as_bytes()); // Fixed 64 chars, no ambiguity.
    mac.update(b"|");
    // Deterministic ref update representation: sorted by ref_name.
    // Each ref is length-prefixed to prevent concatenation ambiguity.
    let mut refs_sorted: Vec<&HookRefUpdate> = req.ref_updates.iter().collect();
    refs_sorted.sort_by_key(|r| r.ref_name.clone());
    for r in &refs_sorted {
        mac.update(r.old_oid.as_bytes()); // Fixed 40 chars.
        mac.update(r.new_oid.as_bytes()); // Fixed 40 chars.
        mac.update(r.ref_name.len().to_string().as_bytes());
        mac.update(b":");
        mac.update(r.ref_name.as_bytes());
        mac.update(if r.is_ancestor { b"1" } else { b"0" });
        mac.update(if r.merge_source_is_ancestor {
            b"1"
        } else {
            b"0"
        });
    }
    mac.update(b"|");
    mac.update(req.merge_authorization.len().to_string().as_bytes());
    mac.update(b":");
    mac.update(req.merge_authorization.as_bytes());
    mac.update(b"|");
    mac.update(req.timestamp.to_string().as_bytes());

    mac.finalize().into_bytes().to_vec()
}

/// Verify the HMAC signature on a hook callback.
fn verify_hmac(secret: &[u8], req: &HookCallbackRequest) -> bool {
    let expected = compute_hmac(secret, req);
    let provided = match hex::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    // Constant-time comparison.
    use subtle::ConstantTimeEq;
    expected.ct_eq(&provided).into()
}

fn unique_tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    let mut values = event.tags.iter().filter_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn root_event_id(event: &Event) -> Option<&str> {
    let mut roots = event.tags.iter().filter_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some("e")
            && parts.get(3).map(String::as_str) == Some("root"))
        .then(|| parts.get(1).map(String::as_str))
        .flatten()
    });
    let root = roots.next()?;
    roots.next().is_none().then_some(root)
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MergeAuthorizationClaims {
    authorization: PatchAuthorization,
    pull_request_id: Vec<u8>,
    repo_address: String,
    target_branch: String,
    source_commit: String,
}

fn parse_merge_authorization_claims(
    req: &HookCallbackRequest,
    now: u64,
) -> Result<Option<MergeAuthorizationClaims>, String> {
    if req.merge_authorization.is_empty() {
        return Ok(None);
    }
    if req.merge_authorization.len() > GIT_MERGE_AUTHORIZATION_MAX_ENCODED_BYTES {
        return Err("merge authorization exceeds maximum size".to_string());
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.merge_authorization.as_bytes())
        .map_err(|_| "merge authorization is not valid URL-safe base64".to_string())?;
    let json = String::from_utf8(bytes)
        .map_err(|_| "merge authorization is not valid UTF-8".to_string())?;
    let event = Event::from_json(json)
        .map_err(|_| "merge authorization is not a valid Nostr event".to_string())?;
    if event.kind != Kind::Custom(1631) || event.verify().is_err() {
        return Err("merge authorization must be a valid signed NIP-34 merged status".to_string());
    }
    if event.pubkey.to_hex() != req.repo_owner || req.pusher_pubkey != req.repo_owner {
        return Err(
            "merge authorization must be signed and pushed by the repository owner".to_string(),
        );
    }
    let event_ts = event.created_at.as_secs();
    if now.saturating_sub(event_ts) > GIT_MERGE_AUTHORIZATION_MAX_AGE_SECS
        || event_ts.saturating_sub(now) > 30
    {
        return Err("merge authorization is expired or too far in the future".to_string());
    }

    let repo_address = format!("30617:{}:{}", req.repo_owner, req.repo_id);
    if unique_tag_value(&event, "a") != Some(repo_address.as_str()) {
        return Err("merge authorization repository does not match the push".to_string());
    }
    let target_branch = unique_tag_value(&event, "target-branch")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "merge authorization has no unique target branch".to_string())?
        .to_string();
    let ref_name = format!("refs/heads/{target_branch}");
    let merge_commit = unique_tag_value(&event, "merge-commit")
        .filter(|value| valid_commit(value))
        .ok_or_else(|| "merge authorization has no unique merge commit".to_string())?;
    if unique_tag_value(&event, "r") != Some(merge_commit) {
        return Err("merge authorization commit tags disagree".to_string());
    }
    let source_commit = unique_tag_value(&event, "source-commit")
        .filter(|value| valid_commit(value))
        .ok_or_else(|| "merge authorization has no unique source commit".to_string())?
        .to_ascii_lowercase();
    let pull_request_id = root_event_id(&event)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "merge authorization has no unique pull-request root".to_string())?;
    let pull_request_id = hex::decode(pull_request_id)
        .map_err(|_| "merge authorization pull-request id is invalid".to_string())?;

    Ok(Some(MergeAuthorizationClaims {
        authorization: PatchAuthorization {
            ref_name,
            new_oid: merge_commit.to_ascii_lowercase(),
        },
        pull_request_id,
        repo_address,
        target_branch,
        source_commit,
    }))
}

async fn resolve_merge_authorization(
    state: &AppState,
    community: buzz_core::CommunityId,
    req: &HookCallbackRequest,
    now: u64,
) -> Result<Vec<PatchAuthorization>, String> {
    let Some(claims) = parse_merge_authorization_claims(req, now)? else {
        return Ok(Vec::new());
    };
    let query = EventQuery {
        kinds: Some(vec![1618]),
        ids: Some(vec![claims.pull_request_id]),
        global_only: true,
        limit: Some(1),
        ..EventQuery::for_community(community)
    };
    let pull_request = state
        .db
        .query_events(&query)
        .await
        .map_err(|error| format!("pull-request lookup failed: {error}"))?
        .pop()
        .ok_or_else(|| "merge authorization pull request was not found".to_string())?;
    if unique_tag_value(&pull_request.event, "a") != Some(claims.repo_address.as_str())
        || unique_tag_value(&pull_request.event, "target-branch")
            != Some(claims.target_branch.as_str())
        || unique_tag_value(&pull_request.event, "c").is_none_or(|commit| {
            !valid_commit(commit) || !commit.eq_ignore_ascii_case(&claims.source_commit)
        })
    {
        return Err(
            "merge authorization pull request does not match the repository, target, and source commit"
                .to_string(),
        );
    }
    if !req.ref_updates.iter().any(|update| {
        update.ref_name == claims.authorization.ref_name
            && update
                .new_oid
                .eq_ignore_ascii_case(&claims.authorization.new_oid)
            && update.merge_source_is_ancestor
    }) {
        return Err(
            "merge authorization result does not contain the pull-request commit".to_string(),
        );
    }

    Ok(vec![claims.authorization])
}

/// `POST /internal/git/policy` — pre-receive hook callback.
///
/// Fail-closed: ANY error returns 403. The hook script treats non-200 as deny.
pub async fn hook_policy_check(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HookCallbackRequest>,
) -> Response {
    // 1. Validate input fields (cheap structural checks before expensive HMAC).
    // This prevents wasting CPU on malformed payloads.
    if req.repo_id.is_empty() || req.repo_id.len() > 64 {
        return (StatusCode::FORBIDDEN, "invalid repo_id").into_response();
    }
    if req.repo_owner.len() != 64
        || !req
            .repo_owner
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return (StatusCode::FORBIDDEN, "invalid repo_owner").into_response();
    }
    if req.pusher_pubkey.len() != 64
        || !req
            .pusher_pubkey
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return (StatusCode::FORBIDDEN, "invalid pusher_pubkey").into_response();
    }
    let community_uuid = match Uuid::parse_str(&req.community_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::FORBIDDEN, "invalid community_id").into_response(),
    };
    let community = buzz_core::CommunityId::from_uuid(community_uuid);
    if req.ref_updates.is_empty() || req.ref_updates.len() > 500 {
        return (StatusCode::FORBIDDEN, "invalid ref_updates count").into_response();
    }
    if req.merge_authorization.len() > GIT_MERGE_AUTHORIZATION_MAX_ENCODED_BYTES
        || !req
            .merge_authorization
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return (StatusCode::FORBIDDEN, "invalid merge_authorization").into_response();
    }
    for r in &req.ref_updates {
        if r.old_oid.len() != 40 || !r.old_oid.chars().all(|c| c.is_ascii_hexdigit()) {
            return (StatusCode::FORBIDDEN, "invalid old_oid").into_response();
        }
        if r.new_oid.len() != 40 || !r.new_oid.chars().all(|c| c.is_ascii_hexdigit()) {
            return (StatusCode::FORBIDDEN, "invalid new_oid").into_response();
        }
        if r.ref_name.is_empty()
            || r.ref_name.len() > 256
            || !r.ref_name.starts_with("refs/")
            || r.ref_name.contains("..")
            || r.ref_name.bytes().any(|b| b <= 0x20 || b == 0x7f)
        {
            return (StatusCode::FORBIDDEN, "invalid ref_name").into_response();
        }
    }

    // 2. Verify HMAC signature (now that we know the payload is structurally valid).
    let secret = state.config.git_hook_hmac_secret.as_bytes();
    if !verify_hmac(secret, &req) {
        warn!(repo = %req.repo_id, "hook callback: HMAC verification failed");
        return (StatusCode::FORBIDDEN, "signature verification failed").into_response();
    }

    // 3. Validate timestamp (30s TTL, max 5s future tolerance).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > MAX_CALLBACK_AGE_SECS {
        warn!(repo = %req.repo_id, age = now.saturating_sub(req.timestamp), "hook callback: expired");
        return (StatusCode::FORBIDDEN, "callback expired").into_response();
    }
    if req.timestamp.saturating_sub(now) > 5 {
        warn!(repo = %req.repo_id, "hook callback: timestamp too far in future");
        return (StatusCode::FORBIDDEN, "callback timestamp invalid").into_response();
    }

    // 4. Validate and resolve kind:30617 for this repo.
    // Query by (community_id, kind=30617, pubkey=owner, d_tag=repo_id) to
    // prevent spoofing and keep the localhost hook callback on the same
    // server-resolved tenant as the git HTTP request that spawned it.
    let owner_bytes = match hex::decode(&req.repo_owner) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (StatusCode::FORBIDDEN, "invalid repo owner").into_response();
        }
    };
    let query = EventQuery {
        kinds: Some(vec![30617]),
        pubkey: Some(owner_bytes.clone()),
        d_tag: Some(req.repo_id.clone()),
        global_only: true,
        limit: Some(1),
        ..EventQuery::for_community(community)
    };
    let repo_event = match state.db.query_events(&query).await {
        Ok(mut events) => {
            if let Some(event) = events.pop() {
                event
            } else {
                warn!(repo = %req.repo_id, "hook callback: kind:30617 not found");
                return (StatusCode::FORBIDDEN, "repository not found").into_response();
            }
        }
        Err(e) => {
            error!(repo = %req.repo_id, error = %e, "hook callback: DB error");
            return (StatusCode::FORBIDDEN, "internal error").into_response();
        }
    };

    // 5. Parse protection rules from kind:30617 tags.
    let tags: Vec<Vec<String>> = repo_event
        .event
        .tags
        .iter()
        .map(|t| t.as_slice().to_vec())
        .collect();

    let rules = match parse_protection_tags(&tags) {
        Ok(parsed) => {
            // Log unknown rules as warnings (helps catch typos).
            for unknown in &parsed.unknown_rules {
                warn!(repo = %req.repo_id, rule = %unknown, "unknown buzz-protect rule (skipped)");
            }
            parsed.rules
        }
        Err(e) => {
            warn!(repo = %req.repo_id, error = %e, "hook callback: malformed protection tags");
            // Fail-closed: malformed rules = deny.
            return (StatusCode::FORBIDDEN, "malformed protection rules").into_response();
        }
    };

    // 6. Resolve channel binding via the shared resolver (same first-tag,
    // fail-closed semantics as the read gate) and check archived state
    // (applies to ALL pushers including owner).
    //
    // `Broken` denies HERE, before owner resolution: a malformed or
    // ambiguous first binding fails closed for *everyone*, exactly like the
    // read gate. Letting it fall through as "unbound" would hand the owner
    // short-circuit below a push path through a binding the read gate
    // refuses to honor — the tri-state exists precisely so Broken and
    // NotBound cannot collapse. Only genuinely-NotBound repos proceed, and
    // only they may earn the remediation-token denial.
    let channel_id = match crate::api::git::binding::resolve_repo_binding(&repo_event.event) {
        crate::api::git::binding::RepoBinding::Bound(id) => Some(id),
        crate::api::git::binding::RepoBinding::NotBound => None,
        crate::api::git::binding::RepoBinding::Broken => {
            warn!(repo = %req.repo_id, "hook callback: broken buzz-channel binding");
            // Deliberately NOT the no_channel_binding token body: the
            // remediation contract is NotBound-only. A broken binding is
            // ambiguity, and ambiguity gets a generic denial (matching the
            // read gate's posture for the same announcement).
            return (StatusCode::FORBIDDEN, "invalid channel binding").into_response();
        }
    };

    if let Some(ch_id) = channel_id {
        match state.db.get_channel(community, ch_id).await {
            Ok(ch) if ch.archived_at.is_some() => {
                return (StatusCode::FORBIDDEN, "channel is archived (read-only)").into_response();
            }
            Err(e) => {
                error!(error = %e, "hook callback: channel lookup failed");
                return (StatusCode::FORBIDDEN, "internal error").into_response();
            }
            _ => {} // Channel exists and is not archived.
        }
    }

    // 7. Resolve pusher's role. A cryptographically verified managed-agent
    // owner has the same repository authority as the agent key itself.
    let repo_owner_hex = hex::encode(repo_event.event.pubkey.to_bytes());
    let pusher_bytes = match hex::decode(&req.pusher_pubkey) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return (StatusCode::FORBIDDEN, "invalid pusher pubkey").into_response(),
    };
    let is_repo_owner = req.pusher_pubkey == repo_owner_hex;
    let is_managed_agent_owner = if is_repo_owner {
        false
    } else {
        match state
            .db
            .is_agent_owner(community, &owner_bytes, &pusher_bytes)
            .await
        {
            Ok(is_owner) => is_owner,
            Err(error) => {
                error!(
                    repo = %req.repo_id,
                    error = %error,
                    "hook callback: managed-agent owner lookup failed"
                );
                return (StatusCode::FORBIDDEN, "internal error").into_response();
            }
        }
    };
    let role = if is_repo_owner || is_managed_agent_owner {
        MemberRole::Owner
    } else {
        match channel_id {
            None => {
                warn!(repo = %req.repo_id, "hook callback: no buzz-channel binding");
                // Declared cross-component contract — see the const docs in
                // buzz-core::git_perms for who consumes the token and why
                // the body also repeats the legacy phrase.
                return (StatusCode::FORBIDDEN, GIT_NO_CHANNEL_BINDING_BODY).into_response();
            }
            Some(ch_id) => {
                match state
                    .db
                    .get_member_role(community, ch_id, &pusher_bytes)
                    .await
                {
                    Ok(Some(role_str)) => match role_str.parse::<MemberRole>() {
                        Ok(role) => role,
                        Err(_) => {
                            error!(role = %role_str, "hook callback: unknown role");
                            return (StatusCode::FORBIDDEN, "internal error").into_response();
                        }
                    },
                    Ok(None) => {
                        return (StatusCode::FORBIDDEN, "not a channel member").into_response();
                    }
                    Err(e) => {
                        error!(error = %e, "hook callback: role lookup failed");
                        return (StatusCode::FORBIDDEN, "internal error").into_response();
                    }
                }
            }
        }
    };

    // 8. Effective git role: bots intentionally added to a channel push as members.
    // Protection rules (push:admin, no-force-push, require-patch, etc.) still apply.
    // Bot is a designation (what it is), not a permission tier (what it can do).
    let git_role = match role {
        MemberRole::Bot => MemberRole::Member,
        other => other,
    };

    // 9. Classify ref updates and evaluate policy.
    let updates: Vec<RefUpdate> = req
        .ref_updates
        .iter()
        .map(|r| RefUpdate {
            ref_name: r.ref_name.clone(),
            kind: UpdateKind::classify(&r.old_oid, &r.new_oid, r.is_ancestor),
            old_oid: r.old_oid.clone(),
            new_oid: r.new_oid.clone(),
        })
        .collect();

    let patch_authorizations = match resolve_merge_authorization(&state, community, &req, now).await
    {
        Ok(authorizations) => authorizations,
        Err(reason) => {
            warn!(repo = %req.repo_id, reason = %reason, "hook callback: invalid merge authorization");
            return (StatusCode::FORBIDDEN, reason).into_response();
        }
    };

    match evaluate_push_with_patch_authorizations(&updates, git_role, &rules, &patch_authorizations)
    {
        Ok(()) => Json(HookCallbackResponse {
            allowed: true,
            denials: vec![],
        })
        .into_response(),
        Err(denials) => {
            let response = HookCallbackResponse {
                allowed: false,
                denials: denials.into_iter().map(DenialResponse::from).collect(),
            };
            (StatusCode::FORBIDDEN, Json(response)).into_response()
        }
    }
}

/// Generate the HMAC signature for a hook callback payload.
///
/// Called by the relay when setting up the pre-receive hook environment.
pub fn generate_hook_hmac(
    secret: &[u8],
    repo_id: &str,
    repo_owner: &str,
    community_id: &str,
    pusher_pubkey: &str,
    ref_updates: &[HookRefUpdate],
    timestamp: u64,
) -> String {
    let req = HookCallbackRequest {
        repo_id: repo_id.to_string(),
        repo_owner: repo_owner.to_string(),
        community_id: community_id.to_string(),
        pusher_pubkey: pusher_pubkey.to_string(),
        ref_updates: ref_updates.to_vec(),
        merge_authorization: String::new(),
        timestamp,
        signature: String::new(), // Not used in computation.
    };
    let mac_bytes = compute_hmac(secret, &req);
    hex::encode(mac_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use nostr::{EventBuilder, Keys, Tag, Timestamp};

    fn make_request() -> HookCallbackRequest {
        HookCallbackRequest {
            repo_id: "test-repo".to_string(),
            repo_owner: "a".repeat(64),
            community_id: uuid::Uuid::from_u128(1).to_string(),
            pusher_pubkey: "b".repeat(64),
            ref_updates: vec![HookRefUpdate {
                old_oid: "1".repeat(40),
                new_oid: "2".repeat(40),
                ref_name: "refs/heads/main".to_string(),
                is_ancestor: true,
                merge_source_is_ancestor: false,
            }],
            merge_authorization: String::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: String::new(),
        }
    }

    fn sign_request(req: &mut HookCallbackRequest, secret: &[u8]) {
        let mac = compute_hmac(secret, req);
        req.signature = hex::encode(mac);
    }

    fn encoded_merge_authorization(
        keys: &Keys,
        repo_address: &str,
        pull_request_id: &str,
        target_branch: &str,
        source_commit: &str,
        merge_commit: &str,
        created_at: u64,
    ) -> String {
        let tags = [
            vec!["e", pull_request_id, "", "root"],
            vec!["a", repo_address],
            vec!["source-commit", source_commit],
            vec!["merge-commit", merge_commit],
            vec!["r", merge_commit],
            vec!["target-branch", target_branch],
        ]
        .into_iter()
        .map(|tag| Tag::parse(tag).expect("valid test tag"))
        .collect::<Vec<_>>();
        let event = EventBuilder::new(Kind::Custom(1631), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .expect("sign merge authorization");
        URL_SAFE_NO_PAD.encode(event.as_json().as_bytes())
    }

    fn valid_merge_authorization_request(now: u64) -> (HookCallbackRequest, Keys) {
        let keys = Keys::generate();
        let owner = keys.public_key().to_hex();
        let mut req = make_request();
        req.repo_id = "governed-repo".to_string();
        req.repo_owner = owner.clone();
        req.pusher_pubkey = owner.clone();
        req.ref_updates[0].new_oid = "c".repeat(40);
        req.ref_updates[0].merge_source_is_ancestor = true;
        req.merge_authorization = encoded_merge_authorization(
            &keys,
            &format!("30617:{owner}:governed-repo"),
            &"d".repeat(64),
            "main",
            &req.ref_updates[0].new_oid,
            &req.ref_updates[0].new_oid,
            now,
        );
        (req, keys)
    }

    #[test]
    fn merge_authorization_claims_are_exact_and_signed() {
        let now = 1_700_000_000;
        let (req, _) = valid_merge_authorization_request(now);
        let claims = parse_merge_authorization_claims(&req, now)
            .expect("valid authorization")
            .expect("authorization present");

        assert_eq!(claims.authorization.ref_name, "refs/heads/main");
        assert_eq!(claims.authorization.new_oid, "c".repeat(40));
        assert_eq!(claims.pull_request_id, vec![0xdd; 32]);
        assert_eq!(
            claims.repo_address,
            format!("30617:{}:governed-repo", req.repo_owner)
        );
        assert_eq!(claims.target_branch, "main");
        assert_eq!(claims.source_commit, "c".repeat(40));
    }

    #[test]
    fn merge_authorization_claims_reject_wrong_signer_pusher_repo_and_time() {
        let now = 1_700_000_000;
        let (valid, _) = valid_merge_authorization_request(now);

        let mut wrong_signer = valid.clone();
        let attacker = Keys::generate();
        wrong_signer.merge_authorization = encoded_merge_authorization(
            &attacker,
            &format!("30617:{}:governed-repo", valid.repo_owner),
            &"d".repeat(64),
            "main",
            &"c".repeat(40),
            &"c".repeat(40),
            now,
        );
        assert!(parse_merge_authorization_claims(&wrong_signer, now).is_err());

        let mut wrong_pusher = valid.clone();
        wrong_pusher.pusher_pubkey = "e".repeat(64);
        assert!(parse_merge_authorization_claims(&wrong_pusher, now).is_err());

        let mut wrong_repo = valid.clone();
        wrong_repo.repo_id = "other-repo".to_string();
        assert!(parse_merge_authorization_claims(&wrong_repo, now).is_err());

        let mut expired = valid.clone();
        let owner_keys = Keys::new(
            nostr::SecretKey::from_hex(
                // Re-signing requires the original key, so generate a fresh
                // internally consistent request at the stale timestamp.
                &"1".repeat(64),
            )
            .expect("test secret"),
        );
        let owner = owner_keys.public_key().to_hex();
        expired.repo_owner = owner.clone();
        expired.pusher_pubkey = owner.clone();
        expired.merge_authorization = encoded_merge_authorization(
            &owner_keys,
            &format!("30617:{owner}:governed-repo"),
            &"d".repeat(64),
            "main",
            &"c".repeat(40),
            &"c".repeat(40),
            now - GIT_MERGE_AUTHORIZATION_MAX_AGE_SECS - 1,
        );
        assert!(parse_merge_authorization_claims(&expired, now).is_err());

        let mut future = expired;
        future.merge_authorization = encoded_merge_authorization(
            &owner_keys,
            &format!("30617:{owner}:governed-repo"),
            &"d".repeat(64),
            "main",
            &"c".repeat(40),
            &"c".repeat(40),
            now + 31,
        );
        assert!(parse_merge_authorization_claims(&future, now).is_err());
    }

    #[test]
    fn merge_authorization_claims_reject_malformed_or_ambiguous_tags() {
        let now = 1_700_000_000;
        let (mut req, keys) = valid_merge_authorization_request(now);
        let repo_address = format!("30617:{}:governed-repo", req.repo_owner);
        let commit = "c".repeat(40);
        let root = "d".repeat(64);

        let cases = vec![
            vec![
                vec!["e", root.as_str(), "", "root"],
                vec!["a", repo_address.as_str()],
                vec!["source-commit", commit.as_str()],
                vec!["merge-commit", commit.as_str()],
                vec!["r", "e000000000000000000000000000000000000000"],
                vec!["target-branch", "main"],
            ],
            vec![
                vec!["e", root.as_str(), "", "root"],
                vec!["a", repo_address.as_str()],
                vec!["source-commit", commit.as_str()],
                vec!["merge-commit", commit.as_str()],
                vec!["r", commit.as_str()],
                vec!["target-branch", "main"],
                vec!["target-branch", "release"],
            ],
            vec![
                vec!["e", root.as_str(), "", "root"],
                vec!["e", root.as_str(), "", "root"],
                vec!["a", repo_address.as_str()],
                vec!["source-commit", commit.as_str()],
                vec!["merge-commit", commit.as_str()],
                vec!["r", commit.as_str()],
                vec!["target-branch", "main"],
            ],
            vec![
                vec!["e", root.as_str(), "", "root"],
                vec!["a", repo_address.as_str()],
                vec!["source-commit", commit.as_str()],
                vec!["source-commit", "e000000000000000000000000000000000000000"],
                vec!["merge-commit", commit.as_str()],
                vec!["r", commit.as_str()],
                vec!["target-branch", "main"],
            ],
        ];

        for raw_tags in cases {
            let tags = raw_tags
                .into_iter()
                .map(|tag| Tag::parse(tag).expect("valid test tag"))
                .collect::<Vec<_>>();
            let event = EventBuilder::new(Kind::Custom(1631), "")
                .tags(tags)
                .custom_created_at(Timestamp::from(now))
                .sign_with_keys(&keys)
                .expect("sign malformed claim");
            req.merge_authorization = URL_SAFE_NO_PAD.encode(event.as_json().as_bytes());
            assert!(parse_merge_authorization_claims(&req, now).is_err());
        }
    }

    #[test]
    fn hmac_valid_signature_accepted() {
        let secret = b"test-secret-key";
        let mut req = make_request();
        sign_request(&mut req, secret);
        assert!(verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_wrong_secret_rejected() {
        let mut req = make_request();
        sign_request(&mut req, b"correct-secret");
        assert!(!verify_hmac(b"wrong-secret", &req));
    }

    /// Deploy-skew guard for the unbound-repo deny body. The token
    /// (`no_channel_binding`, underscores) and the legacy phrase
    /// (`no channel binding`, spaces) do NOT contain each other, so the body
    /// must carry both: the token for structured consumers (Desktop's merge
    /// classifier and dialog matcher), the phrase for desktops already in
    /// the field that prose-match it. Relay ships continuously and Desktop
    /// on release cadence — dropping the phrase strands every old desktop
    /// on a new relay. Asserted against the shared consts, not re-typed
    /// literals, so the const and this test cannot drift apart separately.
    #[test]
    fn no_channel_binding_body_satisfies_old_and_new_matchers() {
        assert!(
            GIT_NO_CHANNEL_BINDING_BODY.starts_with(&format!(
                "{}: ",
                buzz_core::git_perms::GIT_NO_CHANNEL_BINDING_TOKEN
            )),
            "new structured consumers match the token prefix"
        );
        assert!(
            GIT_NO_CHANNEL_BINDING_BODY.contains("no channel binding"),
            "shipped desktops prose-match this exact phrase (spaces, not underscores)"
        );
    }

    #[test]
    fn hmac_tampered_repo_id_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.repo_id = "evil-repo".to_string();
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_pusher_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.pusher_pubkey = "c".repeat(64);
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_ref_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.ref_updates[0].ref_name = "refs/heads/evil".to_string();
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_is_ancestor_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.ref_updates[0].is_ancestor = false; // Flip FF → NFF
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_merge_source_is_ancestor_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.ref_updates[0].merge_source_is_ancestor = true;
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_owner_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.repo_owner = "c".repeat(64);
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_timestamp_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.timestamp += 1;
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_invalid_hex_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        req.signature = "not-valid-hex!!!".to_string();
        assert!(!verify_hmac(secret, &req));
    }

    /// Tampering the server-resolved community changes the HMAC input, so a
    /// hook callback cannot be replayed across communities even though the
    /// localhost policy endpoint itself has no inbound Host header.
    #[test]
    fn hmac_tampered_community_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        sign_request(&mut req, secret);
        req.community_id = uuid::Uuid::from_u128(2).to_string();
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_tampered_merge_authorization_rejected() {
        let secret = b"test-secret";
        let mut req = make_request();
        req.merge_authorization = "abc_DEF-123".to_string();
        sign_request(&mut req, secret);
        req.merge_authorization.push('x');
        assert!(!verify_hmac(secret, &req));
    }

    #[test]
    fn hmac_deterministic_across_ref_order() {
        let secret = b"test-secret";
        let mut req1 = make_request();
        req1.ref_updates.push(HookRefUpdate {
            old_oid: "3".repeat(40),
            new_oid: "4".repeat(40),
            ref_name: "refs/heads/develop".to_string(),
            is_ancestor: false,
            merge_source_is_ancestor: false,
        });
        let mut req2 = req1.clone();
        // Reverse the ref order — HMAC should be the same (sorted internally).
        req2.ref_updates.reverse();
        let mac1 = compute_hmac(secret, &req1);
        let mac2 = compute_hmac(secret, &req2);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn generate_hook_hmac_matches_verify() {
        let secret = b"test-secret";
        let mut req = make_request();
        let sig = generate_hook_hmac(
            secret,
            &req.repo_id,
            &req.repo_owner,
            &req.community_id,
            &req.pusher_pubkey,
            &req.ref_updates,
            req.timestamp,
        );
        req.signature = sig;
        assert!(verify_hmac(secret, &req));
    }

    /// Cross-boundary HMAC integration test.
    ///
    /// Runs the bash HMAC computation logic (extracted from the pre-receive hook)
    /// and compares its output against Rust's `generate_hook_hmac`. This is the
    /// most critical test — it verifies the bash/Rust format agreement that the
    /// entire security model depends on.
    #[test]
    fn bash_hmac_matches_rust_hmac() {
        let secret = "cross-boundary-test-secret-key-1234";
        let repo_id = "my-project";
        let repo_owner = "ab".repeat(32); // 64 hex chars
        let pusher = "cd".repeat(32); // 64 hex chars
        let community_id = uuid::Uuid::from_u128(1).to_string();
        let merge_authorization = "abc_DEF-123";
        let timestamp: u64 = 1700000000;

        // Two refs, intentionally out of sorted order to test sorting.
        let ref_updates = vec![
            HookRefUpdate {
                old_oid: "b".repeat(40),
                new_oid: "c".repeat(40),
                ref_name: "refs/heads/main".to_string(),
                is_ancestor: true,
                merge_source_is_ancestor: true,
            },
            HookRefUpdate {
                old_oid: "a".repeat(40),
                new_oid: "d".repeat(40),
                ref_name: "refs/heads/feature".to_string(),
                is_ancestor: false,
                merge_source_is_ancestor: false,
            },
        ];

        // Compute Rust-side HMAC.
        let rust_req = HookCallbackRequest {
            repo_id: repo_id.to_string(),
            repo_owner: repo_owner.clone(),
            community_id: community_id.clone(),
            pusher_pubkey: pusher.clone(),
            ref_updates: ref_updates.clone(),
            merge_authorization: merge_authorization.to_string(),
            timestamp,
            signature: String::new(),
        };
        let rust_sig = hex::encode(compute_hmac(secret.as_bytes(), &rust_req));

        // Bash script that replicates the hook's HMAC computation.
        // This is the exact logic from hook.rs PRE_RECEIVE_HOOK, extracted into
        // a standalone script with hardcoded values.
        let bash_script = format!(
            r#"
export LC_ALL=C
BUZZ_REPO_ID="{repo_id}"
BUZZ_REPO_OWNER="{repo_owner}"
BUZZ_COMMUNITY_ID="{community_id}"
BUZZ_PUSHER_PUBKEY="{pusher}"
BUZZ_HOOK_SECRET="{secret}"
BUZZ_MERGE_AUTHORIZATION="{merge_authorization}"
TIMESTAMP="{timestamp}"

# Simulate the HMAC_FILE with two refs (unsorted, like the hook writes them)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
HMAC_FILE="$WORK_DIR/hmac"

# Write refs in the order they'd arrive (main first, feature second)
echo "refs/heads/main {old1} {new1} 1 1" >> "$HMAC_FILE"
echo "refs/heads/feature {old2} {new2} 0 0" >> "$HMAC_FILE"

# Build HMAC input — exact logic from hook script
REPO_ID_LEN=${{#BUZZ_REPO_ID}}
HMAC_INPUT="${{REPO_ID_LEN}}:${{BUZZ_REPO_ID}}|${{BUZZ_REPO_OWNER}}|${{BUZZ_COMMUNITY_ID}}|${{BUZZ_PUSHER_PUBKEY}}|"
sort "$HMAC_FILE" | while IFS=' ' read -r ref_name old_oid new_oid is_anc merge_source_is_anc; do
    REF_LEN=${{#ref_name}}
    printf '%s%s%s:%s%s%s' "$old_oid" "$new_oid" "$REF_LEN" "$ref_name" "$is_anc" "$merge_source_is_anc"
done > "$HMAC_FILE.concat"
MERGE_AUTH_LEN=${{#BUZZ_MERGE_AUTHORIZATION}}
HMAC_INPUT="${{HMAC_INPUT}}$(cat "$HMAC_FILE.concat")|${{MERGE_AUTH_LEN}}:${{BUZZ_MERGE_AUTHORIZATION}}|${{TIMESTAMP}}"

# Compute HMAC-SHA256
printf '%s' "$HMAC_INPUT" | openssl dgst -sha256 -hmac "$BUZZ_HOOK_SECRET" -hex 2>/dev/null | sed 's/.*= //'
"#,
            repo_id = repo_id,
            repo_owner = repo_owner,
            community_id = community_id,
            pusher = pusher,
            secret = secret,
            merge_authorization = merge_authorization,
            timestamp = timestamp,
            old1 = "b".repeat(40),
            new1 = "c".repeat(40),
            old2 = "a".repeat(40),
            new2 = "d".repeat(40),
        );

        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(&bash_script)
            .output()
            .expect("failed to run bash");

        assert!(
            output.status.success(),
            "bash script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let bash_sig = String::from_utf8_lossy(&output.stdout).trim().to_string();

        assert_eq!(
            rust_sig, bash_sig,
            "HMAC mismatch!\n  Rust: {rust_sig}\n  Bash: {bash_sig}\n\
             The pre-receive hook and policy endpoint disagree on the canonical format."
        );
    }

    /// Cross-boundary test with a single ref (simpler case).
    #[test]
    fn bash_hmac_single_ref() {
        let secret = "single-ref-secret";
        let repo_id = "test-repo";
        let repo_owner = "a".repeat(64);
        let pusher = "b".repeat(64);
        let community_id = uuid::Uuid::from_u128(1).to_string();
        let timestamp: u64 = 1700000001;

        let ref_updates = vec![HookRefUpdate {
            old_oid: "1".repeat(40),
            new_oid: "2".repeat(40),
            ref_name: "refs/heads/main".to_string(),
            is_ancestor: true,
            merge_source_is_ancestor: false,
        }];

        let rust_sig = generate_hook_hmac(
            secret.as_bytes(),
            repo_id,
            &repo_owner,
            &community_id,
            &pusher,
            &ref_updates,
            timestamp,
        );

        let bash_script = format!(
            r#"
export LC_ALL=C
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
HMAC_FILE="$WORK_DIR/hmac"
echo "refs/heads/main {old} {new} 1 0" >> "$HMAC_FILE"
BUZZ_REPO_ID="{repo_id}"
REPO_ID_LEN=${{#BUZZ_REPO_ID}}
HMAC_INPUT="${{REPO_ID_LEN}}:${{BUZZ_REPO_ID}}|{owner}|{community_id}|{pusher}|"
sort "$HMAC_FILE" | while IFS=' ' read -r ref_name old_oid new_oid is_anc merge_source_is_anc; do
    REF_LEN=${{#ref_name}}
    printf '%s%s%s:%s%s%s' "$old_oid" "$new_oid" "$REF_LEN" "$ref_name" "$is_anc" "$merge_source_is_anc"
done > "$HMAC_FILE.concat"
HMAC_INPUT="${{HMAC_INPUT}}$(cat "$HMAC_FILE.concat")|0:|{timestamp}"
printf '%s' "$HMAC_INPUT" | openssl dgst -sha256 -hmac "{secret}" -hex 2>/dev/null | sed 's/.*= //'
"#,
            old = "1".repeat(40),
            new = "2".repeat(40),
            repo_id = repo_id,
            owner = repo_owner,
            community_id = community_id,
            pusher = pusher,
            timestamp = timestamp,
            secret = secret,
        );

        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(&bash_script)
            .output()
            .expect("failed to run bash");

        assert!(
            output.status.success(),
            "bash script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let bash_sig = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            rust_sig, bash_sig,
            "Single-ref HMAC mismatch!\n  Rust: {rust_sig}\n  Bash: {bash_sig}"
        );
    }

    // ── hook_policy_check binding gate (requires Postgres) ──────────────

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1

    async fn policy_test_state() -> Arc<AppState> {
        let mut config = crate::config::Config::from_env().expect("default config loads");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_string());
        let pool = sqlx::PgPool::connect(&config.database_url)
            .await
            .expect("connect test DB");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    /// Announce `repo_id` with the given tags, then push to it as its own
    /// announcement author and return the response.
    async fn owner_push_response(
        state: &Arc<AppState>,
        community: buzz_core::CommunityId,
        keys: &nostr::Keys,
        repo_id: &str,
        binding_tags: Vec<nostr::Tag>,
    ) -> axum::response::Response {
        use nostr::{EventBuilder, Kind, Tag};

        let mut tags = vec![Tag::parse(["d", repo_id]).unwrap()];
        tags.extend(binding_tags);
        let event = EventBuilder::new(Kind::Custom(30617), "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign 30617");
        state
            .db
            .insert_event(community, &event, None)
            .await
            .expect("insert 30617");

        let owner_hex = keys.public_key().to_hex();
        let mut req = HookCallbackRequest {
            repo_id: repo_id.to_string(),
            repo_owner: owner_hex.clone(),
            community_id: community.as_uuid().to_string(),
            pusher_pubkey: owner_hex,
            ref_updates: vec![HookRefUpdate {
                old_oid: "0".repeat(40),
                new_oid: "2".repeat(40),
                ref_name: "refs/heads/main".to_string(),
                is_ancestor: false,
                merge_source_is_ancestor: false,
            }],
            merge_authorization: String::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: String::new(),
        };
        let secret = state.config.git_hook_hmac_secret.clone();
        sign_request(&mut req, secret.as_bytes());
        hook_policy_check(State(Arc::clone(state)), Json(req)).await
    }

    async fn body_string(response: axum::response::Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
    }

    async fn signed_policy_response(
        state: &Arc<AppState>,
        mut req: HookCallbackRequest,
    ) -> axum::response::Response {
        let secret = state.config.git_hook_hmac_secret.clone();
        sign_request(&mut req, secret.as_bytes());
        hook_policy_check(State(Arc::clone(state)), Json(req)).await
    }

    /// The tri-state trap the resolver exists to prevent: a broken (malformed
    /// or ambiguous-first) binding must fail closed for EVERYONE on push —
    /// including the announcement author — *before* the owner short-circuit
    /// grants `MemberRole::Owner`. Collapsing `Broken` into "unbound" hands
    /// the owner a push path through a binding the read gate refuses to
    /// honor. The remediation token stays reserved for genuinely NotBound.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn push_gate_denies_owner_through_broken_binding() {
        use nostr::{Keys, Tag};

        let state = policy_test_state().await;
        let host = format!("policy-{}.example", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community")
            .id;
        let keys = Keys::generate();

        // Malformed first + valid-looking second: the ambiguity must deny,
        // and the parseable duplicate must not rescue the push.
        let response = owner_push_response(
            &state,
            community,
            &keys,
            &format!("repo-{}", uuid::Uuid::new_v4().simple()),
            vec![
                Tag::parse(["buzz-channel", "not-a-uuid"]).unwrap(),
                Tag::parse(["buzz-channel", &uuid::Uuid::new_v4().to_string()]).unwrap(),
            ],
        )
        .await;
        let (status, body) = body_string(response).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, "invalid channel binding",
            "owner pushing through a broken binding must be denied generically"
        );
        assert!(
            !body.contains(buzz_core::git_perms::GIT_NO_CHANNEL_BINDING_TOKEN),
            "remediation token is NotBound-only; Broken must never earn it"
        );

        // Control: the same owner pushing a genuinely NEVER-BOUND repo is
        // allowed (owner authority over an unbound announcement is the
        // long-standing push semantics). This pins the denial above to
        // Broken specifically, not to some broader regression.
        let response = owner_push_response(
            &state,
            community,
            &keys,
            &format!("repo-{}", uuid::Uuid::new_v4().simple()),
            vec![],
        )
        .await;
        let (status, body) = body_string(response).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner push to a never-bound repo must remain allowed (got body: {body})"
        );
    }

    /// Full database-backed governance seam: the repository announcement,
    /// pull request and owner-signed merged status must agree exactly before
    /// `require-patch` admits the fast-forward. The quarantined Git check must
    /// additionally prove that the PR head is an ancestor of the pushed result.
    /// Missing proof, an unrelated PR head, a commit mismatch and a
    /// non-fast-forward all remain denied.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn require_patch_accepts_only_exact_owner_signed_pull_request_merge() {
        let state = policy_test_state().await;
        let host = format!("policy-{}.example", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community")
            .id;
        let owner_keys = Keys::generate();
        let owner = owner_keys.public_key().to_hex();
        let author_keys = Keys::generate();
        let repo_id = format!("repo-{}", uuid::Uuid::new_v4().simple());
        let repo_address = format!("30617:{owner}:{repo_id}");
        let old_oid = "a".repeat(40);
        let source_oid = "b".repeat(40);
        let new_oid = "c".repeat(40);

        let repo_event = EventBuilder::new(Kind::Custom(30617), "")
            .tags(vec![
                Tag::parse(["d", repo_id.as_str()]).unwrap(),
                Tag::parse([
                    "buzz-protect",
                    "refs/heads/main",
                    "push:admin",
                    "no-force-push",
                    "no-delete",
                    "require-patch",
                ])
                .unwrap(),
            ])
            .sign_with_keys(&owner_keys)
            .expect("sign repository announcement");
        state
            .db
            .insert_event(community, &repo_event, None)
            .await
            .expect("insert repository announcement");

        let pull_request = EventBuilder::new(Kind::Custom(1618), "merge proposal")
            .tags(vec![
                Tag::parse(["a", repo_address.as_str()]).unwrap(),
                Tag::parse(["p", owner.as_str()]).unwrap(),
                Tag::parse(["c", source_oid.as_str()]).unwrap(),
                Tag::parse(["target-branch", "main"]).unwrap(),
            ])
            .sign_with_keys(&author_keys)
            .expect("sign pull request");
        state
            .db
            .insert_event(community, &pull_request, None)
            .await
            .expect("insert pull request");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let authorization = encoded_merge_authorization(
            &owner_keys,
            &repo_address,
            &pull_request.id.to_hex(),
            "main",
            &source_oid,
            &new_oid,
            now,
        );
        let base_request = HookCallbackRequest {
            repo_id: repo_id.clone(),
            repo_owner: owner.clone(),
            community_id: community.as_uuid().to_string(),
            pusher_pubkey: owner,
            ref_updates: vec![HookRefUpdate {
                old_oid,
                new_oid: new_oid.clone(),
                ref_name: "refs/heads/main".to_string(),
                is_ancestor: true,
                merge_source_is_ancestor: true,
            }],
            merge_authorization: authorization,
            timestamp: now,
            signature: String::new(),
        };

        let (status, body) =
            body_string(signed_policy_response(&state, base_request.clone()).await).await;
        assert_eq!(status, StatusCode::OK, "exact proof must pass: {body}");

        let mut missing = base_request.clone();
        missing.merge_authorization.clear();
        let (status, _) = body_string(signed_policy_response(&state, missing).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let mut unrelated_source = base_request.clone();
        unrelated_source.ref_updates[0].merge_source_is_ancestor = false;
        let (status, _) = body_string(signed_policy_response(&state, unrelated_source).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let mut wrong_commit = base_request.clone();
        wrong_commit.ref_updates[0].new_oid = "d".repeat(40);
        let (status, _) = body_string(signed_policy_response(&state, wrong_commit).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let mut non_fast_forward = base_request;
        non_fast_forward.ref_updates[0].is_ancestor = false;
        let (status, _) = body_string(signed_policy_response(&state, non_fast_forward).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
