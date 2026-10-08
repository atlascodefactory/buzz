//! Strict signed commands from a separately pinned bot-assignment authority.
//!
//! This is not NIP-OA and never changes event authorship. An identity-binding
//! proof, relay login assertion, or ordinary channel member is not an assignment
//! authority. The caller supplies the server-resolved community, authenticated
//! actor, and that community's configured authority. Verification is CPU-bound:
//! async consumers must call it in `spawn_blocking`.
//!
//! This codec alone does not admit bots. The consumer must recheck wall-clock
//! lifetime, current owner membership, assignment generation/revocation and
//! absent/bot CAS under its writer locks. Nonce/event replay must be durable.

use nostr::{Event, EventId, PublicKey};
use uuid::Uuid;

use crate::{kind, verify_event, CommunityId};

/// Maximum wall-clock lifetime of an assignment operation, in seconds.
pub const MAX_COMMAND_LIFETIME_SECONDS: u64 = 60;

/// The only target role preconditions supported by assigned admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedBotRole {
    /// There must be no active target membership.
    Absent,
    /// The target must already be a bot; no existing role may be changed.
    Bot,
}

/// The narrowly scoped operation authorized by a verified command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignedBotOperation {
    /// Admit only the assigned bot to this exact channel.
    Admit {
        /// Exact destination, not a caller-selected fallback.
        channel_id: Uuid,
        /// Compare-and-set precondition for the target's active role.
        expected_role: ExpectedBotRole,
    },
    /// Permanently withdraw this assignment generation, not a channel role.
    Revoke,
    /// Inspect one exact assignment and a bounded page of the owner's channels.
    Inspect {
        /// Exclusive channel UUID cursor, never an alternate owner or tenant.
        cursor: Option<Uuid>,
        /// Optional exact admission/revocation receipt to reconcile a lost ACK.
        receipt: Option<EventId>,
    },
}

/// Verified immutable coordinates; construction requires real signature checks.
#[derive(Debug, Clone)]
pub struct AssignedBotCommand {
    event: Event,
    community: CommunityId,
    authority: PublicKey,
    owner: PublicKey,
    bot: PublicKey,
    assignment_id: Uuid,
    generation: i64,
    nonce: Uuid,
    event_id: EventId,
    created_at: u64,
    expires_at: u64,
    operation: AssignedBotOperation,
}

/// A fail-closed rejection with no payload or credentials in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentCommandError {
    /// No assignment authority is explicitly pinned to this community.
    #[error("assignment authority is not configured")]
    NotConfigured,
    /// The actual authenticated signer does not match the configured authority.
    #[error("assignment authority or authenticated actor mismatch")]
    AuthorityMismatch,
    /// Invalid event ID or Schnorr signature.
    #[error("invalid assignment command signature")]
    Signature,
    /// A field is missing, ambiguous, unknown, or non-canonical.
    #[error("invalid assignment command envelope")]
    Envelope,
    /// The operation is expired, premature, or has an excessive lifetime.
    #[error("assignment command is not currently valid")]
    Lifetime,
}

fn tag<'a>(event: &'a Event, name: &str) -> Result<&'a str, AssignmentCommandError> {
    let mut matches = event
        .tags
        .iter()
        .map(nostr::Tag::as_slice)
        .filter(|tag| tag.first().is_some_and(|key| key == name));
    let value = matches.next().ok_or(AssignmentCommandError::Envelope)?;
    if value.len() != 2 || matches.next().is_some() {
        return Err(AssignmentCommandError::Envelope);
    }
    Ok(&value[1])
}

fn uuid(value: &str) -> Result<Uuid, AssignmentCommandError> {
    let parsed = value
        .parse::<Uuid>()
        .map_err(|_| AssignmentCommandError::Envelope)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(AssignmentCommandError::Envelope);
    }
    Ok(parsed)
}

fn key(value: &str) -> Result<PublicKey, AssignmentCommandError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(AssignmentCommandError::Envelope);
    }
    let key = PublicKey::from_hex(value).map_err(|_| AssignmentCommandError::Envelope)?;
    key.xonly().map_err(|_| AssignmentCommandError::Envelope)?;
    Ok(key)
}

fn decimal(value: &str) -> Result<u64, AssignmentCommandError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| AssignmentCommandError::Envelope)?;
    if parsed.to_string() != value {
        return Err(AssignmentCommandError::Envelope);
    }
    Ok(parsed)
}

impl AssignedBotCommand {
    /// Verify an authority-signed command against trusted request coordinates.
    ///
    /// The event's `community` tag is compared, never used to resolve a tenant.
    /// A `None` pin always denies; no owner/operator/member fallback exists.
    pub fn verify(
        event: &Event,
        community: CommunityId,
        authenticated_actor: &PublicKey,
        configured_authority: Option<&PublicKey>,
        now: u64,
    ) -> Result<Self, AssignmentCommandError> {
        let authority = configured_authority.ok_or(AssignmentCommandError::NotConfigured)?;
        if event.pubkey != *authority || authenticated_actor != authority {
            return Err(AssignmentCommandError::AuthorityMismatch);
        }
        verify_event(event).map_err(|_| AssignmentCommandError::Signature)?;
        let event_kind = crate::kind::event_kind_u32(event);
        let admission = match event_kind {
            kind::KIND_ASSIGNED_BOT_ADMISSION => true,
            kind::KIND_ASSIGNED_BOT_REVOCATION | kind::KIND_ASSIGNED_BOT_INSPECTION => false,
            _ => return Err(AssignmentCommandError::Envelope),
        };
        let inspection = event_kind == kind::KIND_ASSIGNED_BOT_INSPECTION;
        let optional_tag = |name: &str| {
            if event
                .tags
                .iter()
                .any(|t| t.as_slice().first().is_some_and(|key| key == name))
            {
                tag(event, name).map(Some)
            } else {
                Ok(None)
            }
        };
        let cursor = if inspection {
            optional_tag("cursor")?
        } else {
            None
        };
        let receipt = if inspection {
            optional_tag("receipt")?
        } else {
            None
        };
        let expected_tags = if admission {
            10
        } else {
            7 + usize::from(cursor.is_some()) + usize::from(receipt.is_some())
        };
        if !event.content.is_empty() || event.tags.len() != expected_tags {
            return Err(AssignmentCommandError::Envelope);
        }
        if tag(event, "community")? != community.to_string() {
            return Err(AssignmentCommandError::Envelope);
        }
        let owner = key(tag(event, "owner")?)?;
        let bot = key(tag(event, "p")?)?;
        if owner == bot || owner == *authority || bot == *authority {
            return Err(AssignmentCommandError::Envelope);
        }
        let assignment_id = uuid(tag(event, "assignment")?)?;
        let generation = decimal(tag(event, "assignment-version")?)?;
        if generation == 0 || generation > i64::MAX as u64 {
            return Err(AssignmentCommandError::Envelope);
        }
        let nonce = uuid(tag(event, "nonce")?)?;
        let expires_at = decimal(tag(event, "expiration")?)?;
        let created_at = event.created_at.as_secs();
        if expires_at <= created_at
            || expires_at.saturating_sub(created_at) > MAX_COMMAND_LIFETIME_SECONDS
            || created_at > now
            || expires_at <= now
        {
            return Err(AssignmentCommandError::Lifetime);
        }
        let operation = if admission {
            let channel_id = uuid(tag(event, "h")?)?;
            if tag(event, "role")? != "bot" {
                return Err(AssignmentCommandError::Envelope);
            }
            let expected_role = match tag(event, "expected-role")? {
                "absent" => ExpectedBotRole::Absent,
                "bot" => ExpectedBotRole::Bot,
                _ => return Err(AssignmentCommandError::Envelope),
            };
            AssignedBotOperation::Admit {
                channel_id,
                expected_role,
            }
        } else if inspection {
            let receipt = receipt
                .map(|value| {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    {
                        return Err(AssignmentCommandError::Envelope);
                    }
                    EventId::from_hex(value).map_err(|_| AssignmentCommandError::Envelope)
                })
                .transpose()?;
            AssignedBotOperation::Inspect {
                cursor: cursor.map(uuid).transpose()?,
                receipt,
            }
        } else {
            AssignedBotOperation::Revoke
        };
        Ok(Self {
            event: event.clone(),
            community,
            authority: *authority,
            owner,
            bot,
            assignment_id,
            generation: generation as i64,
            nonce,
            event_id: event.id,
            created_at,
            expires_at,
            operation,
        })
    }

    /// Server-resolved community, not the raw claim.
    pub fn community(&self) -> CommunityId {
        self.community
    }
    /// Verified assignment issuer; not the human's key.
    pub fn authority(&self) -> PublicKey {
        self.authority
    }
    /// Atlas-assigned human anchor; not a NIP-OA ownership proof.
    pub fn owner(&self) -> PublicKey {
        self.owner
    }
    /// Exact broker-held bot key.
    pub fn bot(&self) -> PublicKey {
        self.bot
    }
    /// Opaque assignment coordinate; contains no internal user or tenant ID.
    pub fn assignment_id(&self) -> Uuid {
        self.assignment_id
    }
    /// Exact positive lifecycle generation, never an instruction to upgrade it.
    pub fn generation(&self) -> i64 {
        self.generation
    }
    /// Operation nonce; the consumer must atomically retain replay evidence.
    pub fn nonce(&self) -> Uuid {
        self.nonce
    }
    /// Signed event identity; exact duplicate cannot imply current membership.
    pub fn event_id(&self) -> EventId {
        self.event_id
    }
    /// The exact verified event, retained to prevent a caller swapping payloads.
    pub fn event(&self) -> &Event {
        &self.event
    }
    /// Signed expiry; consumers still need a fresh clock after acquiring locks.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Authorized operation, including exact channel and role CAS.
    pub fn operation(&self) -> AssignedBotOperation {
        self.operation
    }
    /// Recheck with the database clock after acquiring all writer locks.
    pub fn valid_at(&self, now: u64) -> bool {
        self.created_at <= now && now < self.expires_at
    }
}

#[cfg(test)]
#[path = "assigned_bot_tests.rs"]
mod tests;
