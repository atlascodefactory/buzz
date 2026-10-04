//! A signed conditional admission command, never a legacy PUT_USER fallback.

use std::sync::Arc;

use buzz_core::tenant::TenantContext;
use buzz_db::channel::{MemberAdmissionPrecondition, MemberRole};
use chrono::DateTime;
use nostr::Event;
use uuid::Uuid;

use super::ingest::{IngestError, IngestResult};
use crate::state::AppState;

struct Admission {
    channel: Uuid,
    target: Vec<u8>,
    precondition: MemberAdmissionPrecondition,
}

fn invalid(reason: &str) -> IngestError {
    IngestError::Rejected(format!("invalid: conditional bot admission: {reason}"))
}

fn singleton<'a>(event: &'a Event, name: &str) -> Result<&'a str, IngestError> {
    let mut matches = event
        .tags
        .iter()
        .map(nostr::Tag::as_slice)
        .filter(|tag| tag.first().is_some_and(|key| key == name));
    let tag = matches
        .next()
        .ok_or_else(|| invalid("missing required tag"))?;
    if tag.len() != 2 || matches.next().is_some() {
        return Err(invalid(
            "required tags must be unique with exactly one value",
        ));
    }
    Ok(&tag[1])
}

fn key(value: &str) -> Result<Vec<u8>, IngestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid("public keys must be canonical lowercase hex"));
    }
    nostr::PublicKey::from_hex(value).map_err(|_| invalid("invalid public key"))?;
    hex::decode(value).map_err(|_| invalid("invalid public key"))
}

fn parse(event: &Event) -> Result<Admission, IngestError> {
    if !event.content.is_empty() || event.tags.len() != 6 {
        return Err(invalid(
            "empty content and exactly six required tags expected",
        ));
    }
    let channel = singleton(event, "h")?
        .parse::<Uuid>()
        .map_err(|_| invalid("invalid channel"))?;
    if singleton(event, "h")? != channel.to_string() {
        return Err(invalid("channel must be a canonical UUID"));
    }
    let target = key(singleton(event, "p")?)?;
    let required_member = key(singleton(event, "required-member")?)?;
    if target == required_member || target == event.pubkey.to_bytes() {
        return Err(invalid("target must differ from actor and required member"));
    }
    if singleton(event, "role")? != "bot" {
        return Err(invalid("only the bot role may be admitted"));
    }
    let expected_role = match singleton(event, "expected-role")? {
        "absent" => None,
        "bot" => Some(MemberRole::Bot),
        _ => return Err(invalid("expected-role must be absent or bot")),
    };
    let expiration = singleton(event, "expiration")?;
    let seconds = expiration
        .parse::<u64>()
        .map_err(|_| invalid("invalid expiration"))?;
    if expiration != seconds.to_string()
        || seconds <= event.created_at.as_secs()
        || seconds.saturating_sub(event.created_at.as_secs()) > 60
    {
        return Err(invalid(
            "expiration must be canonical and within 60 seconds of creation",
        ));
    }
    let expires_at = i64::try_from(seconds)
        .ok()
        .and_then(|s| DateTime::from_timestamp(s, 0))
        .ok_or_else(|| invalid("invalid expiration"))?;
    Ok(Admission {
        channel,
        target,
        precondition: MemberAdmissionPrecondition {
            required_member,
            expected_role,
            expires_at,
        },
    })
}

/// Execute after the common ingest signature, identity, scope and channel gates.
pub async fn accept(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &Event,
) -> Result<IngestResult, IngestError> {
    let admission = parse(event)?;
    let mut tx = state
        .db
        .begin_event_write_transaction()
        .await
        .map_err(|e| IngestError::Internal(format!("error: begin admission: {e}")))?;
    buzz_deletion::store(&state.db)
        .guard_transaction(&mut tx, tenant.community())
        .await
        .map_err(|e| {
            IngestError::Rejected(format!("restricted: community writes are fenced: {e}"))
        })?;
    let inserted = buzz_db::channel::admit_bot_conditionally_in_transaction(
        &mut tx,
        tenant.community(),
        event,
        admission.channel,
        &admission.target,
        &admission.precondition,
    )
    .await
    .map_err(|e| match e {
        buzz_db::DbError::AccessDenied(reason) => {
            IngestError::Rejected(format!("restricted: {reason}"))
        }
        buzz_db::DbError::InvalidData(reason) => {
            IngestError::Rejected(format!("conflict: {reason}"))
        }
        buzz_db::DbError::ChannelNotFound(_) => invalid("channel not found"),
        other => IngestError::Internal(format!("error: conditional admission: {other}")),
    })?;
    tx.commit()
        .await
        .map_err(|e| IngestError::Internal(format!("error: commit admission: {e}")))?;
    state.invalidate_membership(tenant, admission.channel, &admission.target);
    Ok(IngestResult {
        event_id: event.id.to_hex(),
        accepted: true,
        message: if inserted {
            String::new()
        } else {
            "duplicate:".into()
        },
    })
}

/// Publish the current roster after the caller records the durable write trace.
/// A retry repairs this projection, never the membership mutation, and must not
/// emit a member-added notification for a historical command.
pub async fn publish_current_roster(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    channel: Uuid,
) -> Result<(), IngestError> {
    super::side_effects::emit_group_discovery_events(tenant, state, channel)
        .await
        .map_err(|e| {
            IngestError::Internal(format!(
                "error: admission committed; roster publication needs retry: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

    pub(super) fn signed(actor: &Keys, tags: Vec<Vec<String>>, created: u64) -> Event {
        EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CONDITIONAL_BOT_ADMISSION as u16),
            "",
        )
        .custom_created_at(Timestamp::from(created))
        .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .sign_with_keys(actor)
        .unwrap()
    }

    pub(super) fn tags(
        channel: Uuid,
        target: &Keys,
        required: &Keys,
        expected: &str,
        expiry: u64,
    ) -> Vec<Vec<String>> {
        [
            ["h".into(), channel.to_string()],
            ["p".into(), target.public_key().to_hex()],
            ["role".into(), "bot".into()],
            ["required-member".into(), required.public_key().to_hex()],
            ["expected-role".into(), expected.into()],
            ["expiration".into(), expiry.to_string()],
        ]
        .into_iter()
        .map(Vec::from)
        .collect()
    }

    #[test]
    fn conditional_admission_envelope_accepts_both_states() {
        let (actor, target, required) = (Keys::generate(), Keys::generate(), Keys::generate());
        for expected in ["absent", "bot"] {
            let event = signed(
                &actor,
                tags(Uuid::new_v4(), &target, &required, expected, 1060),
                1000,
            );
            assert!(parse(&event).is_ok());
        }
    }

    #[test]
    fn conditional_admission_envelope_fails_closed_on_every_tag_shape() {
        let (actor, target, required) = (Keys::generate(), Keys::generate(), Keys::generate());
        let good = tags(Uuid::new_v4(), &target, &required, "absent", 1060);
        for index in 0..good.len() {
            for malformed in [
                vec![good[index][0].clone()],
                vec![
                    good[index][0].clone(),
                    good[index][1].clone(),
                    "extra".into(),
                ],
                vec!["unknown".into(), good[index][1].clone()],
            ] {
                let mut bad = good.clone();
                bad[index] = malformed;
                assert!(
                    parse(&signed(&actor, bad, 1000)).is_err(),
                    "tag index {index}"
                );
            }
            let mut missing = good.clone();
            missing.remove(index);
            assert!(parse(&signed(&actor, missing, 1000)).is_err());
            let mut duplicate = good.clone();
            duplicate[(index + 1) % good.len()] = good[index].clone();
            assert!(parse(&signed(&actor, duplicate, 1000)).is_err());
        }
    }

    #[test]
    fn conditional_admission_rejects_role_key_uuid_and_expiry_ambiguity() {
        let (actor, target, required) = (Keys::generate(), Keys::generate(), Keys::generate());
        let good = tags(Uuid::new_v4(), &target, &required, "absent", 1060);
        for (index, value) in [
            (0, "bad-uuid"),
            (1, "not-a-key"),
            (2, "owner"),
            (4, "member"),
            (5, "1000"),
            (5, "1061"),
            (5, "01060"),
            (5, "-1"),
            (5, "18446744073709551615"),
        ] {
            let mut bad = good.clone();
            bad[index][1] = value.into();
            assert!(
                parse(&signed(&actor, bad, 1000)).is_err(),
                "{index}:{value}"
            );
        }
        for forbidden in [
            actor.public_key().to_hex(),
            required.public_key().to_hex(),
            target.public_key().to_hex().to_uppercase(),
        ] {
            let mut bad = good.clone();
            bad[1][1] = forbidden;
            assert!(parse(&signed(&actor, bad, 1000)).is_err());
        }
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::super::ingest::{ingest_event, HttpAuthMethod, IngestAuth};
    use super::tests::{signed, tags};
    use super::*;
    use buzz_auth::Scope;
    use buzz_conformance::{TraceAction, TraceStep, Tracer};
    use buzz_db::channel::{ChannelType, ChannelVisibility};
    use nostr::{Keys, Timestamp};
    use std::{sync::Mutex, time::Duration};

    #[derive(Default)]
    struct VecTracer {
        steps: Mutex<Vec<TraceStep>>,
    }

    impl Tracer for VecTracer {
        fn record(&self, step: TraceStep) {
            self.steps.lock().expect("trace lock").push(step);
        }
    }

    struct Fixture {
        state: Arc<AppState>,
        tenant: TenantContext,
        channel: Uuid,
        actor: Keys,
        required: Keys,
        target: Keys,
    }

    async fn fixture(visibility: ChannelVisibility, ttl: Option<i32>) -> Fixture {
        let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
            .await
            .unwrap();
        // Real, isolated Redis backs replay, admission and roster delivery. Do
        // not use an always-fresh guard or an unreachable pubsub test double.
        let mut config = crate::config::Config::for_test();
        config.require_relay_membership = false;
        config.require_auth_token = true;
        config.redis_url = std::env::var("REDIS_URL").expect("isolated REDIS_URL");
        let redis = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis.clone())
                .await
                .unwrap(),
        );
        let db = buzz_db::Db::from_pool(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media = buzz_media::MediaStorage::new(&config.media).unwrap();
        let (state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis,
            None::<buzz_audit::AuditService>,
            pubsub,
            auth,
            search,
            workflow,
            Keys::generate(),
            media,
        );
        let state = Arc::new(state);
        let host = format!("conditional-{}.test", Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .unwrap()
            .id;
        let tenant = TenantContext::resolved(community, host);
        let (actor, required, target) = (Keys::generate(), Keys::generate(), Keys::generate());
        for identity in [&actor, &required, &target] {
            state
                .db
                .ensure_user(community, identity.public_key().as_bytes())
                .await
                .unwrap();
        }
        let channel = state
            .db
            .create_channel(
                community,
                "conditional",
                ChannelType::Stream,
                visibility,
                None,
                actor.public_key().as_bytes(),
                ttl,
            )
            .await
            .unwrap()
            .id;
        state
            .db
            .add_member(
                community,
                channel,
                required.public_key().as_bytes(),
                MemberRole::Member,
                Some(actor.public_key().as_bytes()),
            )
            .await
            .unwrap();
        Fixture {
            state,
            tenant,
            channel,
            actor,
            required,
            target,
        }
    }

    fn auth(actor: &Keys) -> IngestAuth {
        IngestAuth::Http {
            pubkey: actor.public_key(),
            scopes: vec![Scope::AdminChannels],
            auth_method: HttpAuthMethod::Nip98,
        }
    }

    fn request(f: &Fixture, expected: &str) -> Event {
        let now = Timestamp::now().as_secs();
        signed(
            &f.actor,
            tags(f.channel, &f.target, &f.required, expected, now + 60),
            now,
        )
    }

    async fn assert_no_effect(f: &Fixture, event: &Event) {
        assert!(f
            .state
            .db
            .get_member_role(
                f.tenant.community(),
                f.channel,
                f.target.public_key().as_bytes()
            )
            .await
            .unwrap()
            .is_none());
        assert!(
            f.state
                .db
                .get_event_by_id_for_event_write(f.tenant.community(), event.id.as_bytes())
                .await
                .unwrap()
                .is_none(),
            "failed admission must not persist a command"
        );
    }

    async fn wait_for_lock(pool: &sqlx::PgPool, event: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = current_database() \
                     AND wait_event_type = 'Lock' AND wait_event = $1)",
                ).bind(event).fetch_one(pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("production writer must reach the real database lock");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_ingest_positive_replay_and_role_preservation() {
        for visibility in [ChannelVisibility::Open, ChannelVisibility::Private] {
            let f = fixture(visibility, None).await;
            let event = request(&f, "absent");
            assert!(
                ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor))
                    .await
                    .unwrap()
                    .accepted
            );
            assert_eq!(
                f.state
                    .db
                    .get_member_role(
                        f.tenant.community(),
                        f.channel,
                        f.target.public_key().as_bytes()
                    )
                    .await
                    .unwrap()
                    .as_deref(),
                Some("bot")
            );
            f.state
                .db
                .remove_member(
                    f.tenant.community(),
                    f.channel,
                    f.target.public_key().as_bytes(),
                    f.actor.public_key().as_bytes(),
                )
                .await
                .unwrap();
            let replay = ingest_event(&f.state, &f.tenant, event, auth(&f.actor))
                .await
                .unwrap();
            assert_eq!(replay.message, "duplicate:");
            assert!(
                f.state
                    .db
                    .get_member_role(
                        f.tenant.community(),
                        f.channel,
                        f.target.public_key().as_bytes()
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "replay must not resurrect bot"
            );
            f.state
                .db
                .add_member(
                    f.tenant.community(),
                    f.channel,
                    f.target.public_key().as_bytes(),
                    MemberRole::Admin,
                    Some(f.actor.public_key().as_bytes()),
                )
                .await
                .unwrap();
            let conflict = request(&f, "bot");
            assert!(
                matches!(ingest_event(&f.state, &f.tenant, conflict.clone(), auth(&f.actor)).await,
                Err(IngestError::Rejected(reason)) if reason.contains("target membership changed"))
            );
            assert_eq!(
                f.state
                    .db
                    .get_member_role(
                        f.tenant.community(),
                        f.channel,
                        f.target.public_key().as_bytes()
                    )
                    .await
                    .unwrap()
                    .as_deref(),
                Some("admin")
            );
            assert!(f
                .state
                .db
                .get_event_by_id_for_event_write(f.tenant.community(), conflict.id.as_bytes())
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_ingest_rejects_departed_required_member_and_foreign_community() {
        let f = fixture(ChannelVisibility::Open, None).await;
        f.state
            .db
            .remove_member(
                f.tenant.community(),
                f.channel,
                f.required.public_key().as_bytes(),
                f.actor.public_key().as_bytes(),
            )
            .await
            .unwrap();
        let event = request(&f, "absent");
        assert!(
            matches!(ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor)).await,
            Err(IngestError::Rejected(reason)) if reason.contains("required member is no longer active"))
        );
        assert_no_effect(&f, &event).await;

        let foreign = f
            .state
            .db
            .ensure_configured_community(&format!("foreign-{}.test", Uuid::new_v4()))
            .await
            .unwrap()
            .id;
        let foreign_tenant = TenantContext::resolved(foreign, "foreign.test");
        assert!(
            ingest_event(&f.state, &foreign_tenant, event.clone(), auth(&f.actor))
                .await
                .is_err()
        );
        assert!(f
            .state
            .db
            .get_event_by_id_for_event_write(foreign, event.id.as_bytes())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_preserves_signed_actor_policy_and_transport_identity() {
        let f = fixture(ChannelVisibility::Open, None).await;
        f.state
            .db
            .set_agent_owner(
                f.tenant.community(),
                f.target.public_key().as_bytes(),
                f.required.public_key().as_bytes(),
            )
            .await
            .unwrap();
        for policy in ["owner_only", "nobody"] {
            f.state
                .db
                .set_channel_add_policy(
                    f.tenant.community(),
                    f.target.public_key().as_bytes(),
                    policy,
                )
                .await
                .unwrap();
            let event = request(&f, "absent");
            assert!(
                matches!(ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor)).await,
                Err(IngestError::Rejected(reason)) if reason.contains("channel-add policy denied"))
            );
            assert_no_effect(&f, &event).await;
        }
        let event = request(&f, "absent");
        assert!(matches!(
            ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.required)).await,
            Err(IngestError::AuthFailed(_))
        ));
        let no_scope = IngestAuth::Http {
            pubkey: f.actor.public_key(),
            scopes: vec![],
            auth_method: HttpAuthMethod::Nip98,
        };
        assert!(matches!(
            ingest_event(&f.state, &f.tenant, event.clone(), no_scope).await,
            Err(IngestError::AuthFailed(_))
        ));
        assert_no_effect(&f, &event).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_http_nip98_binding_and_replay() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let f = fixture(ChannelVisibility::Private, None).await;
        let mut state = (*f.state).clone();
        Arc::make_mut(&mut state.config).relay_url = format!("wss://{}", f.tenant.host());
        let state = Arc::new(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = crate::router::build_router(state);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let event = request(&f, "absent");
        let body = serde_json::to_vec(&event).unwrap();
        for (signer, expected_status, replay) in [(&f.required, 403, false), (&f.actor, 200, true)]
        {
            let proof = nostr::EventBuilder::new(nostr::Kind::Custom(27235), "")
                .tags([
                    nostr::Tag::parse(["u", &format!("https://{}/events", f.tenant.host())])
                        .unwrap(),
                    nostr::Tag::parse(["method", "POST"]).unwrap(),
                    nostr::Tag::parse(["payload", &hex::encode(Sha256::digest(&body))]).unwrap(),
                    nostr::Tag::parse(["nonce", &Uuid::new_v4().to_string()]).unwrap(),
                ])
                .sign_with_keys(signer)
                .unwrap();
            let authorization = format!(
                "Nostr {}",
                base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&proof).unwrap())
            );
            let send = || {
                client
                    .post(format!("http://{addr}/events"))
                    .header("host", f.tenant.host())
                    .header("authorization", &authorization)
                    .body(body.clone())
                    .send()
            };
            let response = send().await.unwrap();
            assert_eq!(response.status().as_u16(), expected_status);
            if expected_status == 200 {
                assert_eq!(
                    response.json::<serde_json::Value>().await.unwrap()["accepted"],
                    true
                );
            } else {
                assert_no_effect(&f, &event).await;
            }
            if replay {
                let response = send().await.unwrap();
                assert_eq!(
                    response.status(),
                    reqwest::StatusCode::UNAUTHORIZED,
                    "same NIP-98 proof must not satisfy a second request"
                );
            }
        }
        server.abort();
        assert_eq!(
            f.state
                .db
                .get_member_role(
                    f.tenant.community(),
                    f.channel,
                    f.target.public_key().as_bytes()
                )
                .await
                .unwrap()
                .as_deref(),
            Some("bot")
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_retry_repairs_roster_without_readmission() {
        let mut f = fixture(ChannelVisibility::Private, None).await;
        let tracer = Arc::new(VecTracer::default());
        Arc::get_mut(&mut f.state)
            .expect("fixture owns state")
            .tracer = tracer.clone();
        // Fail the real roster store once, after the membership/command commit.
        sqlx::raw_sql("CREATE FUNCTION conditional_fail_roster() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind = 39002 THEN RAISE EXCEPTION 'synthetic roster outage'; END IF; RETURN NEW; END $$; CREATE TRIGGER zz_conditional_fail_roster BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION conditional_fail_roster();")
            .execute(f.state.db.pool()).await.unwrap();
        let event = request(&f, "absent");
        assert!(
            matches!(ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor)).await,
            Err(IngestError::Internal(reason)) if reason.contains("roster publication needs retry"))
        );
        {
            let steps = tracer.steps.lock().unwrap();
            let tail = &steps[steps.len() - 2..];
            assert!(matches!(tail[0].action, TraceAction::WriteInsert { .. }));
            assert!(matches!(tail[1].action, TraceAction::SanitizedError { .. }));
        }
        assert_eq!(
            f.state
                .db
                .get_member_role(
                    f.tenant.community(),
                    f.channel,
                    f.target.public_key().as_bytes()
                )
                .await
                .unwrap()
                .as_deref(),
            Some("bot")
        );
        assert!(
            matches!(ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor)).await,
            Err(IngestError::Internal(reason)) if reason.contains("roster publication needs retry"))
        );
        {
            let steps = tracer.steps.lock().unwrap();
            let tail = &steps[steps.len() - 2..];
            assert!(matches!(tail[0].action, TraceAction::WriteDuplicate { .. }));
            assert!(matches!(tail[1].action, TraceAction::SanitizedError { .. }));
        }
        f.state
            .db
            .remove_member(
                f.tenant.community(),
                f.channel,
                f.target.public_key().as_bytes(),
                f.actor.public_key().as_bytes(),
            )
            .await
            .unwrap();
        sqlx::raw_sql("DROP TRIGGER zz_conditional_fail_roster ON events; DROP FUNCTION conditional_fail_roster();").execute(f.state.db.pool()).await.unwrap();
        let result = ingest_event(&f.state, &f.tenant, event, auth(&f.actor))
            .await
            .unwrap();
        assert_eq!(result.message, "duplicate:");
        assert!(f
            .state
            .db
            .get_member_role(
                f.tenant.community(),
                f.channel,
                f.target.public_key().as_bytes()
            )
            .await
            .unwrap()
            .is_none());
        let rosters: Vec<serde_json::Value> = sqlx::query_scalar("SELECT tags FROM events WHERE community_id = $1 AND channel_id = $2 AND kind = 39002 AND deleted_at IS NULL")
            .bind(f.tenant.community().as_uuid()).bind(f.channel).fetch_all(f.state.db.pool()).await.unwrap();
        assert_eq!(
            rosters.len(),
            1,
            "retry must produce the current durable roster"
        );
        assert!(
            rosters[0]
                .as_array()
                .unwrap()
                .iter()
                .all(|tag| tag[0] != "p" || tag[1] != f.target.public_key().to_hex()),
            "retry must not announce the departed bot"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_owner_policy_and_existing_bot_succeed() {
        let f = fixture(ChannelVisibility::Private, None).await;
        f.state
            .db
            .set_agent_owner(
                f.tenant.community(),
                f.target.public_key().as_bytes(),
                f.required.public_key().as_bytes(),
            )
            .await
            .unwrap();
        f.state
            .db
            .set_channel_add_policy(
                f.tenant.community(),
                f.target.public_key().as_bytes(),
                "owner_only",
            )
            .await
            .unwrap();
        // The actual agent owner is only a normal Member, not a channel admin.
        for expected in ["absent", "bot"] {
            let now = Timestamp::now().as_secs();
            let event = signed(
                &f.required,
                tags(f.channel, &f.target, &f.required, expected, now + 60),
                now,
            );
            assert!(
                ingest_event(&f.state, &f.tenant, event, auth(&f.required))
                    .await
                    .unwrap()
                    .accepted
            );
        }
        assert_eq!(
            f.state
                .db
                .get_member_role(
                    f.tenant.community(),
                    f.channel,
                    f.target.public_key().as_bytes()
                )
                .await
                .unwrap()
                .as_deref(),
            Some("bot")
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_envelope_and_channel_failures_are_atomic() {
        let f = fixture(ChannelVisibility::Open, None).await;
        let now = Timestamp::now().as_secs();
        let mut malformed = tags(f.channel, &f.target, &f.required, "absent", now + 60);
        malformed[4][1] = "admin".into();
        for event in [
            signed(&f.actor, malformed, now),
            signed(
                &f.actor,
                tags(f.channel, &f.target, &f.required, "absent", now - 1),
                now - 61,
            ),
        ] {
            assert!(matches!(
                ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor)).await,
                Err(IngestError::Rejected(_))
            ));
            assert_no_effect(&f, &event).await;
        }
        // Each row change independently tests the production admission guard.
        for update in [
            "UPDATE channels SET max_members = 2 WHERE community_id = $1 AND id = $2",
            "UPDATE channels SET max_members = NULL, channel_type = 'dm' WHERE community_id = $1 AND id = $2",
            "UPDATE channels SET channel_type = 'stream', archived_at = clock_timestamp() WHERE community_id = $1 AND id = $2",
            "UPDATE channels SET archived_at = NULL, ttl_deadline = clock_timestamp() - interval '1 second' WHERE community_id = $1 AND id = $2",
        ] {
            sqlx::query(update).bind(f.tenant.community().as_uuid()).bind(f.channel).execute(f.state.db.pool()).await.unwrap();
            let event = request(&f, "absent");
            assert!(matches!(ingest_event(&f.state, &f.tenant, event.clone(), auth(&f.actor)).await, Err(IngestError::Rejected(_))));
            assert_no_effect(&f, &event).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_revalidates_after_required_member_removal_lock_wait() {
        let f = fixture(ChannelVisibility::Private, None).await;
        let mut holder = f.state.db.pool().begin().await.unwrap();
        buzz_db::channel_members::acquire_channel_membership_lock_in_transaction(
            &mut holder,
            f.tenant.community(),
            f.channel,
        )
        .await
        .unwrap();
        let (state, tenant, event, actor) = (
            f.state.clone(),
            f.tenant.clone(),
            request(&f, "absent"),
            f.actor.clone(),
        );
        let checked = event.clone();
        let writer =
            tokio::spawn(async move { ingest_event(&state, &tenant, event, auth(&actor)).await });
        wait_for_lock(f.state.db.pool(), "advisory").await;
        sqlx::query("UPDATE channel_members SET removed_at = clock_timestamp() WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3")
            .bind(f.tenant.community().as_uuid()).bind(f.channel).bind(f.required.public_key().as_bytes())
            .execute(&mut *holder).await.unwrap();
        holder.commit().await.unwrap();
        assert!(
            matches!(tokio::time::timeout(Duration::from_secs(10), writer).await.unwrap().unwrap(),
            Err(IngestError::Rejected(reason)) if reason.contains("required member is no longer active"))
        );
        assert_no_effect(&f, &checked).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_expiry_is_resampled_after_policy_lock_wait() {
        let f = fixture(ChannelVisibility::Open, None).await;
        let mut holder = f.state.db.pool().begin().await.unwrap();
        sqlx::query("SELECT pubkey FROM users WHERE community_id = $1 AND pubkey = $2 FOR UPDATE")
            .bind(f.tenant.community().as_uuid())
            .bind(f.target.public_key().as_bytes())
            .fetch_one(&mut *holder)
            .await
            .unwrap();
        let now = Timestamp::now().as_secs();
        let event = signed(
            &f.actor,
            tags(f.channel, &f.target, &f.required, "absent", now + 4),
            now,
        );
        let (state, tenant, actor, checked) = (
            f.state.clone(),
            f.tenant.clone(),
            f.actor.clone(),
            event.clone(),
        );
        let writer =
            tokio::spawn(async move { ingest_event(&state, &tenant, event, auth(&actor)).await });
        wait_for_lock(f.state.db.pool(), "transactionid").await;
        sqlx::query("SELECT pg_sleep(4.1)")
            .execute(&mut *holder)
            .await
            .unwrap();
        holder.rollback().await.unwrap();
        assert!(
            matches!(tokio::time::timeout(Duration::from_secs(10), writer).await.unwrap().unwrap(),
            Err(IngestError::Rejected(reason)) if reason.contains("expired while waiting"))
        );
        assert_no_effect(&f, &checked).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conditional_admission_does_not_deadlock_roster_ttl_commit() {
        let f = fixture(ChannelVisibility::Open, Some(120)).await;
        let relay = f.state.relay_keypair.public_key();
        let mut snapshot = f
            .state
            .db
            .lock_member_snapshot(f.tenant.community(), f.channel, relay.as_bytes())
            .await
            .unwrap();
        let mut roster_tags = vec![nostr::Tag::parse(["d", &f.channel.to_string()]).unwrap()];
        for member in &snapshot.members {
            roster_tags.push(
                nostr::Tag::parse(["p", &hex::encode(&member.pubkey), "", &member.role]).unwrap(),
            );
        }
        let roster = nostr::EventBuilder::new(nostr::Kind::Custom(39002), "")
            .tags(roster_tags)
            .sign_with_keys(&f.state.relay_keypair)
            .unwrap();
        snapshot
            .replace_member_event(f.tenant.community(), f.channel, &roster)
            .await
            .unwrap();
        let (state, tenant, actor, event) = (
            f.state.clone(),
            f.tenant.clone(),
            f.actor.clone(),
            request(&f, "absent"),
        );
        let writer =
            tokio::spawn(async move { ingest_event(&state, &tenant, event, auth(&actor)).await });
        wait_for_lock(f.state.db.pool(), "advisory").await;
        tokio::time::timeout(Duration::from_secs(5), snapshot.release())
            .await
            .expect("roster TTL COMMIT must not wait for conditional admission's row lock")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(10), writer)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .accepted
        );
    }
}
