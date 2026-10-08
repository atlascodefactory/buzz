//! Common-ingest and real local HTTP/NIP-98 tests, not official-client E2E.

use super::super::ingest::{ingest_event, HttpAuthMethod, IngestAuth};
use super::*;
use base64::Engine as _;
use buzz_auth::Scope;
use buzz_db::channel::{ChannelType, ChannelVisibility};
use nostr::{EventBuilder, Keys, Kind, Tag};
use sha2::{Digest, Sha256};

#[path = "assigned_bot_gift_wrap_postgres_tests.rs"]
mod gift_wrap_postgres_tests;

fn inspection_request(f: &Fixture) -> Event {
    let base = f.request(&f.authority, true, f.tenant.community().to_string());
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_ASSIGNED_BOT_INSPECTION as u16),
        "",
    )
    .custom_created_at(base.created_at)
    .tags(base.tags.iter().cloned())
    .sign_with_keys(&f.authority)
    .unwrap()
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn inspection_ingress_requires_pin_scope_and_unrestricted_token() {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    for auth in [
        f.ws(Scope::MessagesWrite, None),
        f.ws(Scope::AdminChannels, Some(vec![f.channel])),
    ] {
        assert!(
            ingest_event(&f.state, &f.tenant, inspection_request(&f), auth)
                .await
                .is_err()
        );
    }
    let unpinned = Fixture::new(ChannelVisibility::Private, false).await;
    assert!(ingest_event(
        &unpinned.state,
        &unpinned.tenant,
        inspection_request(&unpinned),
        unpinned.http()
    )
    .await
    .is_err());
    let foreign = IngestAuth::Http {
        pubkey: f.owner.public_key(),
        scopes: vec![Scope::AdminChannels],
        auth_method: HttpAuthMethod::Nip98,
    };
    assert!(
        ingest_event(&f.state, &f.tenant, inspection_request(&f), foreign)
            .await
            .is_err()
    );
    let event = inspection_request(&f);
    let result = ingest_event(
        &f.state,
        &f.tenant,
        event.clone(),
        f.ws(Scope::AdminChannels, None),
    )
    .await
    .unwrap();
    let observation: serde_json::Value = serde_json::from_str(&result.message).unwrap();
    assert_eq!(observation["assignmentState"], "missing");
    assert_eq!(
        observation["channels"][0]["channelId"],
        f.channel.to_string()
    );
    f.no_effect(&event).await;
    assert!(
        ingest_event(&f.state, &f.tenant, event, f.ws(Scope::AdminChannels, None))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn inspection_real_http_ack_returns_private_observation_not_a_public_event() {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    let server = LocalHttpRelay::new(f.state.clone()).await;
    let event = inspection_request(&f);
    let (status, body) = server.event(&f, &f.authority, &event).await;
    assert!(status.is_success(), "{body}");
    assert_eq!(body["accepted"], true, "{body}");
    let observation: serde_json::Value =
        serde_json::from_str(body["message"].as_str().unwrap()).unwrap();
    assert_eq!(observation["assignmentState"], "missing");
    assert_eq!(observation["botPublicKey"], f.bot.public_key().to_hex());
    f.no_effect(&event).await;
    let (_, replay) = server.event(&f, &f.authority, &event).await;
    assert_ne!(replay["accepted"], true, "{replay}");
}

struct Fixture {
    state: Arc<AppState>,
    tenant: TenantContext,
    authority: Keys,
    owner: Keys,
    bot: Keys,
    assignment: Uuid,
    channel: Uuid,
}

impl Fixture {
    async fn new(visibility: ChannelVisibility, pinned: bool) -> Self {
        let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
            .await
            .unwrap();
        let db = buzz_db::Db::from_pool(pool.clone());
        let host = format!("assigned-ingest-{}.test", Uuid::new_v4().simple());
        let community = db.ensure_configured_community(&host).await.unwrap().id;
        let (authority, owner, bot) = (Keys::generate(), Keys::generate(), Keys::generate());
        for key in [&authority, &owner, &bot] {
            db.ensure_user(community, key.public_key().as_bytes())
                .await
                .unwrap();
        }
        for key in [&authority, &owner] {
            buzz_db::relay_members::add_relay_member(
                &pool,
                community,
                &key.public_key().to_hex(),
                "member",
                None,
            )
            .await
            .unwrap();
        }
        buzz_db::user::set_channel_add_policy(
            &pool,
            community,
            bot.public_key().as_bytes(),
            "owner_only",
        )
        .await
        .unwrap();
        let channel = db
            .create_channel(
                community,
                "assigned-ingest",
                ChannelType::Stream,
                visibility,
                None,
                owner.public_key().as_bytes(),
                None,
            )
            .await
            .unwrap()
            .id;
        let mut config = crate::config::Config::for_test();
        config.require_relay_membership = false;
        config.require_auth_token = true;
        config.redis_url = std::env::var("REDIS_URL").expect("isolated REDIS_URL");
        if pinned {
            config.assigned_bot_authority =
                crate::assigned_bot_config::AssignedBotAuthority::parse(
                    Some(&community.to_string()),
                    Some(&authority.public_key().to_hex()),
                )
                .unwrap();
        }
        let redis = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis.clone())
                .await
                .unwrap(),
        );
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool);
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
        Self {
            state: Arc::new(state),
            tenant: TenantContext::resolved(community, host),
            authority,
            owner,
            bot,
            assignment: Uuid::new_v4(),
            channel,
        }
    }

    fn request(&self, signer: &Keys, revoke: bool, claimed: String) -> Event {
        // Avoid cross-clock second-boundary flakes in positive signed fixtures.
        let now = Timestamp::now().as_secs().saturating_sub(1);
        let mut tags = vec![
            vec!["community".into(), claimed],
            vec!["owner".into(), self.owner.public_key().to_hex()],
            vec!["p".into(), self.bot.public_key().to_hex()],
            vec!["assignment".into(), self.assignment.to_string()],
            vec!["assignment-version".into(), "1".into()],
            vec!["nonce".into(), Uuid::new_v4().to_string()],
            vec!["expiration".into(), (now + 60).to_string()],
        ];
        if !revoke {
            tags.extend([
                vec!["h".into(), self.channel.to_string()],
                vec!["role".into(), "bot".into()],
                vec!["expected-role".into(), "absent".into()],
            ]);
        }
        EventBuilder::new(
            Kind::Custom(if revoke {
                buzz_core::kind::KIND_ASSIGNED_BOT_REVOCATION as u16
            } else {
                buzz_core::kind::KIND_ASSIGNED_BOT_ADMISSION as u16
            }),
            "",
        )
        .custom_created_at(Timestamp::from(now))
        .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .sign_with_keys(signer)
        .unwrap()
    }

    fn http(&self) -> IngestAuth {
        IngestAuth::Http {
            pubkey: self.authority.public_key(),
            scopes: vec![Scope::AdminChannels],
            auth_method: HttpAuthMethod::Nip98,
        }
    }

    fn ws(&self, scope: Scope, channels: Option<Vec<Uuid>>) -> IngestAuth {
        IngestAuth::Nip42 {
            pubkey: self.authority.public_key(),
            scopes: vec![scope],
            channel_ids: channels,
            conn_id: Uuid::new_v4(),
        }
    }

    async fn no_effect(&self, event: &Event) {
        assert!(self
            .state
            .db
            .get_member_role(
                self.tenant.community(),
                self.channel,
                self.bot.public_key().as_bytes()
            )
            .await
            .unwrap()
            .is_none());
        assert!(self
            .state
            .db
            .get_event_by_id_for_event_write(self.tenant.community(), event.id.as_bytes())
            .await
            .unwrap()
            .is_none());
    }

    async fn admit(&self) {
        let event = self.request(&self.authority, false, self.tenant.community().to_string());
        assert!(
            ingest_event(&self.state, &self.tenant, event, self.http())
                .await
                .unwrap()
                .accepted
        );
    }

    async fn revoke(&self) {
        let event = self.request(&self.authority, true, self.tenant.community().to_string());
        assert!(
            ingest_event(&self.state, &self.tenant, event, self.http())
                .await
                .unwrap()
                .accepted
        );
    }

    fn bot_http(&self) -> IngestAuth {
        IngestAuth::Http {
            pubkey: self.bot.public_key(),
            scopes: vec![Scope::MessagesWrite],
            auth_method: HttpAuthMethod::Nip98,
        }
    }

    fn message(&self, channel: Option<Uuid>) -> Event {
        let mut builder = EventBuilder::new(
            Kind::Custom(if channel.is_some() { 9 } else { 1 }),
            format!("synthetic assigned access test {}", Uuid::new_v4()),
        );
        if let Some(id) = channel {
            builder = builder.tags([Tag::parse(["h".into(), id.to_string()]).unwrap()]);
        }
        builder.sign_with_keys(&self.bot).unwrap()
    }
}

/// A task-owned loopback server; dropping it never touches another relay.
struct LocalHttpRelay {
    address: std::net::SocketAddr,
    client: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
    requests: std::sync::atomic::AtomicUsize,
}

impl Drop for LocalHttpRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl LocalHttpRelay {
    async fn new(state: Arc<AppState>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = crate::router::build_router(state);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
            task,
            requests: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    async fn post(
        &self,
        signer: &Keys,
        host: &str,
        path: &str,
        signed_body: &[u8],
        body: Vec<u8>,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let request = self
            .requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let started = std::time::Instant::now();
        let auth = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", &format!("http://{host}{path}")]).unwrap(),
                Tag::parse(["method", "POST"]).unwrap(),
                Tag::parse(["payload", &hex::encode(Sha256::digest(signed_body))]).unwrap(),
                Tag::parse(["nonce", &Uuid::new_v4().to_string()]).unwrap(),
            ])
            .sign_with_keys(signer)
            .unwrap();
        let authorization = format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&auth).unwrap())
        );
        let response = self
            .client
            .post(format!("http://{}{path}", self.address))
            .header("host", host)
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "local HTTP request #{request} {path} failed after {:?}: {error}",
                    started.elapsed()
                )
            });
        let status = response.status();
        eprintln!(
            "local HTTP request #{request} {path}: {status} after {:?}",
            started.elapsed()
        );
        let body = response.json().await.unwrap();
        assert!(!self.task.is_finished(), "local relay must still be live");
        (status, body)
    }

    async fn event(
        &self,
        f: &Fixture,
        signer: &Keys,
        event: &Event,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let body = serde_json::to_vec(event).unwrap();
        self.post(signer, f.tenant.host(), "/events", &body, body.clone())
            .await
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_persistence_denial_maps_to_rejection_not_configuration_error() {
    use super::super::ingest::{map_event_persistence_error, IngestError};
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    for revoke in [false, true] {
        let request = f.request(&f.authority, revoke, f.tenant.community().to_string());
        assert!(
            ingest_event(&f.state, &f.tenant, request, f.http())
                .await
                .unwrap()
                .accepted
        );
    }
    let message = EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
        "withdrawn writer",
    )
    .tags([Tag::parse(["h".to_string(), f.channel.to_string()]).unwrap()])
    .sign_with_keys(&f.bot)
    .unwrap();
    let error = buzz_db::event::insert_event(
        f.state.db.pool(),
        f.tenant.community(),
        &message,
        Some(f.channel),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        map_event_persistence_error(error),
        IngestError::Rejected(_)
    ));
    let configuration_error = sqlx::query(
        "DO $$ BEGIN RAISE EXCEPTION 'synthetic configuration denial' USING ERRCODE = 'insufficient_privilege'; END $$"
    ).execute(f.state.db.pool()).await.unwrap_err();
    assert!(matches!(
        map_event_persistence_error(configuration_error.into()),
        IngestError::Internal(_)
    ));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_http_bootstraps_only_own_bot_on_closed_relay_without_nip_oa() {
    let mut f = Fixture::new(ChannelVisibility::Private, true).await;
    let config = Arc::get_mut(&mut Arc::get_mut(&mut f.state).unwrap().config).unwrap();
    config.require_relay_membership = true;
    config.allow_nip_oa_auth = false;
    sqlx::query("DELETE FROM users WHERE community_id = $1 AND pubkey = $2")
        .bind(f.tenant.community().as_uuid())
        .bind(f.bot.public_key().as_bytes())
        .execute(f.state.db.pool())
        .await
        .unwrap();
    let relay = LocalHttpRelay::new(f.state.clone()).await;
    let profile = EventBuilder::new(Kind::Metadata, "{\"name\":\"synthetic Lenny\"}")
        .sign_with_keys(&f.bot)
        .unwrap();
    let (status, _) = relay.event(&f, &f.bot, &profile).await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    let admission = f.request(&f.authority, false, f.tenant.community().to_string());
    let (status, reply) = relay.event(&f, &f.authority, &admission).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
    assert_eq!(reply["accepted"], true);
    let owner: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT agent_owner_pubkey FROM users WHERE community_id = $1 AND pubkey = $2",
    )
    .bind(f.tenant.community().as_uuid())
    .bind(f.bot.public_key().as_bytes())
    .fetch_one(f.state.db.pool())
    .await
    .unwrap();
    assert_eq!(
        owner, None,
        "an assignment must not manufacture NIP-OA ownership"
    );
    assert!(!f
        .state
        .db
        .is_relay_member_writer(f.tenant.community(), &f.bot.public_key().to_hex())
        .await
        .unwrap());
    assert_eq!(
        crate::api::relay_members::check_relay_membership_authoritative(
            &f.state,
            f.tenant.community(),
            f.bot.public_key().as_bytes(),
            None,
            None,
        )
        .await
        .unwrap(),
        crate::api::relay_members::MembershipDecision::AssignedBot
    );
    let (status, reply) = relay.event(&f, &f.bot, &profile).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
    let (status, reply) = relay.event(&f, &f.bot, &f.message(Some(f.channel))).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{reply}");

    // A direct member row must not bypass withdrawal of the stored assignment.
    buzz_db::relay_members::add_relay_member(
        f.state.db.pool(),
        f.tenant.community(),
        &f.bot.public_key().to_hex(),
        "admin",
        None,
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.tenant.community().as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(f.state.db.pool())
        .await
        .unwrap();
    let (status, _) = relay.event(&f, &f.bot, &f.message(Some(f.channel))).await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        crate::api::relay_members::check_relay_membership_authoritative(
            &f.state,
            f.tenant.community(),
            f.bot.public_key().as_bytes(),
            None,
            None,
        )
        .await
        .unwrap(),
        crate::api::relay_members::MembershipDecision::Denied
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_bootstrap_missing_owner_member_rolls_back_registration_and_receipt() {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    sqlx::query("DELETE FROM users WHERE community_id = $1 AND pubkey = $2")
        .bind(f.tenant.community().as_uuid())
        .bind(f.bot.public_key().as_bytes())
        .execute(f.state.db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.tenant.community().as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(f.state.db.pool())
        .await
        .unwrap();
    let admission = f.request(&f.authority, false, f.tenant.community().to_string());
    assert!(
        ingest_event(&f.state, &f.tenant, admission.clone(), f.http())
            .await
            .is_err()
    );
    f.no_effect(&admission).await;
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE community_id = $1 AND pubkey = $2")
            .bind(f.tenant.community().as_uuid())
            .bind(f.bot.public_key().as_bytes())
            .fetch_one(f.state.db.pool())
            .await
            .unwrap();
    assert_eq!(rows, 0);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assigned_bots WHERE community_id = $1")
            .bind(f.tenant.community().as_uuid())
            .fetch_one(f.state.db.pool())
            .await
            .unwrap();
    assert_eq!(rows, 0);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assigned_bot_commands WHERE community_id = $1")
            .bind(f.tenant.community().as_uuid())
            .fetch_one(f.state.db.pool())
            .await
            .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_http_wire_binds_transport_body_host_and_current_owner() {
    for visibility in [ChannelVisibility::Open, ChannelVisibility::Private] {
        let f = Fixture::new(visibility, true).await;
        let relay = LocalHttpRelay::new(f.state.clone()).await;
        let admission = f.request(&f.authority, false, f.tenant.community().to_string());
        let (status, _) = relay.event(&f, &f.owner, &admission).await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
        f.no_effect(&admission).await;

        let body = serde_json::to_vec(&admission).unwrap();
        let altered = f.request(&f.authority, false, f.tenant.community().to_string());
        let (status, _) = relay
            .post(
                &f.authority,
                f.tenant.host(),
                "/events",
                &body,
                serde_json::to_vec(&altered).unwrap(),
            )
            .await;
        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
        f.no_effect(&altered).await;

        let (status, _) = relay
            .post(
                &f.authority,
                "unmapped-assignment.invalid",
                "/events",
                &body,
                body.clone(),
            )
            .await;
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        f.no_effect(&admission).await;

        let (status, reply) = relay.event(&f, &f.authority, &admission).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
        assert_eq!(reply["accepted"], true);
        let (status, replay) = relay.event(&f, &f.authority, &admission).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{replay}");
        assert_eq!(replay["message"], "duplicate:");
        let message = f.message(Some(f.channel));
        let (status, reply) = relay.event(&f, &f.bot, &message).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
        assert_eq!(reply["accepted"], true);
        assert!(f
            .state
            .db
            .get_event_by_id_for_event_write(f.tenant.community(), message.id.as_bytes(),)
            .await
            .unwrap()
            .is_some());

        let successor = Keys::generate();
        f.state
            .db
            .ensure_user(f.tenant.community(), successor.public_key().as_bytes())
            .await
            .unwrap();
        f.state
            .db
            .add_member(
                f.tenant.community(),
                f.channel,
                successor.public_key().as_bytes(),
                buzz_db::channel::MemberRole::Owner,
                Some(f.owner.public_key().as_bytes()),
            )
            .await
            .unwrap();
        f.state
            .db
            .remove_member(
                f.tenant.community(),
                f.channel,
                f.owner.public_key().as_bytes(),
                successor.public_key().as_bytes(),
            )
            .await
            .unwrap();
        let departed_message = f.message(Some(f.channel));
        let (status, reply) = relay.event(&f, &f.bot, &departed_message).await;
        assert!(status.is_client_error(), "{status}: {reply}");
        assert!(f
            .state
            .db
            .get_event_by_id_for_event_write(f.tenant.community(), departed_message.id.as_bytes(),)
            .await
            .unwrap()
            .is_none());

        let revocation = f.request(&f.authority, true, f.tenant.community().to_string());
        let (status, reply) = relay.event(&f, &f.authority, &revocation).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
        assert_eq!(reply["accepted"], true);
        let body = serde_json::to_vec(&serde_json::json!({"kinds": [9]})).unwrap();
        for path in ["/query", "/count"] {
            let (status, _) = relay
                .post(&f.bot, f.tenant.host(), path, &body, body.clone())
                .await;
            assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
        }
        let global = f.message(None);
        let (status, _) = relay.event(&f, &f.bot, &global).await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
        assert!(f
            .state
            .db
            .get_event_by_id_for_event_write(f.tenant.community(), global.id.as_bytes(),)
            .await
            .unwrap()
            .is_none());
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_ingest_http_and_ws_open_and_private_replay() {
    for visibility in [ChannelVisibility::Open, ChannelVisibility::Private] {
        for websocket in [false, true] {
            let f = Fixture::new(visibility, true).await;
            let event = f.request(&f.authority, false, f.tenant.community().to_string());
            let auth = || {
                if websocket {
                    f.ws(Scope::AdminChannels, None)
                } else {
                    f.http()
                }
            };
            assert!(
                ingest_event(&f.state, &f.tenant, event.clone(), auth())
                    .await
                    .unwrap()
                    .accepted
            );
            assert_eq!(
                ingest_event(&f.state, &f.tenant, event, auth())
                    .await
                    .unwrap()
                    .message,
                "duplicate:"
            );
            assert_eq!(
                f.state
                    .db
                    .get_member_role(
                        f.tenant.community(),
                        f.channel,
                        f.bot.public_key().as_bytes()
                    )
                    .await
                    .unwrap()
                    .as_deref(),
                Some("bot")
            );
            assert!(f
                .state
                .db
                .get_member_role(
                    f.tenant.community(),
                    f.channel,
                    f.authority.public_key().as_bytes()
                )
                .await
                .unwrap()
                .is_none());
        }
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_ingest_disabled_and_actor_and_tenant_fail_closed() {
    let disabled = Fixture::new(ChannelVisibility::Private, false).await;
    let event = disabled.request(
        &disabled.authority,
        false,
        disabled.tenant.community().to_string(),
    );
    assert!(ingest_event(
        &disabled.state,
        &disabled.tenant,
        event.clone(),
        disabled.http()
    )
    .await
    .is_err());
    disabled.no_effect(&event).await;
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    for event in [
        f.request(&Keys::generate(), false, f.tenant.community().to_string()),
        f.request(&f.authority, false, Uuid::new_v4().to_string()),
    ] {
        assert!(ingest_event(&f.state, &f.tenant, event.clone(), f.http())
            .await
            .is_err());
        f.no_effect(&event).await;
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_ingest_scope_and_revocation_fence() {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    let event = f.request(&f.authority, false, f.tenant.community().to_string());
    for auth in [
        f.ws(Scope::MessagesWrite, None),
        f.ws(Scope::AdminChannels, Some(vec![Uuid::new_v4()])),
    ] {
        assert!(ingest_event(&f.state, &f.tenant, event.clone(), auth)
            .await
            .is_err());
        f.no_effect(&event).await;
    }
    let revoke = f.request(&f.authority, true, f.tenant.community().to_string());
    assert!(ingest_event(
        &f.state,
        &f.tenant,
        revoke.clone(),
        f.ws(Scope::AdminChannels, Some(vec![f.channel]))
    )
    .await
    .is_err());
    f.no_effect(&revoke).await;
    assert!(
        ingest_event(&f.state, &f.tenant, revoke.clone(), f.http())
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(
        ingest_event(&f.state, &f.tenant, revoke, f.http())
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    assert!(ingest_event(&f.state, &f.tenant, event.clone(), f.http())
        .await
        .is_err());
    f.no_effect(&event).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_revoked_bot_cannot_use_positive_caches_or_open_global_writes() {
    for visibility in [ChannelVisibility::Open, ChannelVisibility::Private] {
        let f = Fixture::new(visibility, true).await;
        f.admit().await;
        let bot = f.bot.public_key().to_bytes();
        assert!(f
            .state
            .is_member_cached(f.tenant.community(), f.channel, &bot)
            .await
            .unwrap());
        f.state
            .membership_cache
            .insert((f.tenant.community(), f.channel, bot.to_vec()), true);
        f.state
            .accessible_channels_cache
            .insert((f.tenant.community(), bot.to_vec()), vec![f.channel]);
        assert!(
            ingest_event(
                &f.state,
                &f.tenant,
                f.message(Some(f.channel)),
                f.bot_http()
            )
            .await
            .unwrap()
            .accepted
        );
        f.revoke().await;
        assert!(!f
            .state
            .is_member_cached(f.tenant.community(), f.channel, &bot)
            .await
            .unwrap());
        assert!(f
            .state
            .get_accessible_channel_ids_cached(f.tenant.community(), &bot)
            .await
            .unwrap()
            .is_empty());
        for channel in [Some(f.channel), None] {
            let event = f.message(channel);
            assert!(f
                .state
                .db
                .get_event_by_id_for_event_write(f.tenant.community(), event.id.as_bytes())
                .await
                .unwrap()
                .is_none());
            assert!(
                ingest_event(&f.state, &f.tenant, event.clone(), f.bot_http())
                    .await
                    .is_err()
            );
            assert!(f
                .state
                .db
                .get_event_by_id_for_event_write(f.tenant.community(), event.id.as_bytes())
                .await
                .unwrap()
                .is_none());
        }
        assert!(crate::api::bridge::enforce_http_admission(
            &f.state,
            &f.tenant,
            &f.bot.public_key()
        )
        .await
        .is_err());
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_owner_departure_blocks_legacy_edit_and_admin_exceptions() {
    use buzz_db::channel::MemberRole;
    for visibility in [ChannelVisibility::Open, ChannelVisibility::Private] {
        let f = Fixture::new(visibility, true).await;
        f.admit().await;
        let target = f.message(Some(f.channel));
        assert!(
            ingest_event(&f.state, &f.tenant, target.clone(), f.bot_http())
                .await
                .unwrap()
                .accepted
        );
        // A real ordinary promotion is allowed while the assignment is active.
        f.state
            .db
            .add_member(
                f.tenant.community(),
                f.channel,
                f.bot.public_key().as_bytes(),
                MemberRole::Admin,
                Some(f.owner.public_key().as_bytes()),
            )
            .await
            .unwrap();
        let edit = || {
            EventBuilder::new(Kind::Custom(40003), "synthetic edited")
                .tags([
                    Tag::parse(["h".into(), f.channel.to_string()]).unwrap(),
                    Tag::parse(["e".into(), target.id.to_hex()]).unwrap(),
                ])
                .sign_with_keys(&f.bot)
                .unwrap()
        };
        let metadata = || {
            EventBuilder::new(Kind::Custom(9002), "")
                .tags([
                    Tag::parse(["h".into(), f.channel.to_string()]).unwrap(),
                    Tag::parse(["name", "synthetic active admin"]).unwrap(),
                ])
                .sign_with_keys(&f.bot)
                .unwrap()
        };
        let admin_auth = || IngestAuth::Http {
            pubkey: f.bot.public_key(),
            scopes: vec![Scope::AdminChannels, Scope::ChannelsWrite],
            auth_method: HttpAuthMethod::Nip98,
        };
        assert!(
            ingest_event(&f.state, &f.tenant, edit(), f.bot_http())
                .await
                .unwrap()
                .accepted
        );
        assert!(
            ingest_event(&f.state, &f.tenant, metadata(), admin_auth())
                .await
                .unwrap()
                .accepted
        );
        let successor = Keys::generate();
        f.state
            .db
            .ensure_user(f.tenant.community(), successor.public_key().as_bytes())
            .await
            .unwrap();
        f.state
            .db
            .add_member(
                f.tenant.community(),
                f.channel,
                successor.public_key().as_bytes(),
                MemberRole::Owner,
                Some(f.owner.public_key().as_bytes()),
            )
            .await
            .unwrap();
        f.state
            .db
            .remove_member(
                f.tenant.community(),
                f.channel,
                f.owner.public_key().as_bytes(),
                successor.public_key().as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(
            buzz_db::assigned_bot::access_status(
                f.state.db.pool(),
                f.tenant.community(),
                f.bot.public_key().as_bytes(),
                None
            )
            .await
            .unwrap(),
            Some(true)
        );
        for (kind, content, extra) in [
            (
                40003,
                "synthetic denied edit",
                Tag::parse(["e".into(), target.id.to_hex()]).unwrap(),
            ),
            (
                9002,
                "",
                Tag::parse(["name", "synthetic denied admin"]).unwrap(),
            ),
        ] {
            let event = EventBuilder::new(Kind::Custom(kind), content)
                .tags([
                    Tag::parse(["h".into(), f.channel.to_string()]).unwrap(),
                    extra,
                ])
                .sign_with_keys(&f.bot)
                .unwrap();
            let auth = if kind == 9002 {
                admin_auth()
            } else {
                f.bot_http()
            };
            assert!(matches!(
                ingest_event(&f.state, &f.tenant, event.clone(), auth).await,
                Err(super::super::ingest::IngestError::Rejected(ref message))
                    if message == "restricted: assigned agent channel access withdrawn"
            ));
            assert!(f
                .state
                .db
                .get_event_by_id_for_event_write(f.tenant.community(), event.id.as_bytes())
                .await
                .unwrap()
                .is_none());
        }
        assert_eq!(
            f.state
                .db
                .get_channel_for_event_write(f.tenant.community(), f.channel)
                .await
                .unwrap()
                .name,
            "synthetic active admin"
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_git_member_and_repo_owner_keep_normal_rights_until_revocation() {
    use crate::api::git::policy::{
        generate_hook_hmac, hook_policy_check, HookCallbackRequest, HookRefUpdate,
    };
    use axum::{extract::State, http::StatusCode, Json};
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    f.admit().await;
    for repo_owner in [&f.owner, &f.bot] {
        let repo = if repo_owner.public_key() == f.bot.public_key() {
            "bot-owned"
        } else {
            "human-owned"
        };
        let channel = f.channel.to_string();
        let announcement = EventBuilder::new(Kind::Custom(30617), "")
            .tags([
                Tag::parse(["d", repo]).unwrap(),
                Tag::parse(["buzz-channel", &channel]).unwrap(),
            ])
            .sign_with_keys(repo_owner)
            .unwrap();
        f.state
            .db
            .insert_event(f.tenant.community(), &announcement, None)
            .await
            .unwrap();
    }
    async fn check(f: &Fixture, owner: &Keys, repo: &str) -> StatusCode {
        let updates = vec![HookRefUpdate {
            old_oid: "0".repeat(40),
            new_oid: "2".repeat(40),
            ref_name: "refs/heads/feature".into(),
            is_ancestor: false,
            merge_source_is_ancestor: false,
        }];
        let mut req = HookCallbackRequest {
            repo_id: repo.into(),
            repo_owner: owner.public_key().to_hex(),
            community_id: f.tenant.community().to_string(),
            pusher_pubkey: f.bot.public_key().to_hex(),
            ref_updates: updates,
            merge_authorization: String::new(),
            timestamp: Timestamp::now().as_secs(),
            signature: String::new(),
        };
        req.signature = generate_hook_hmac(
            f.state.config.git_hook_hmac_secret.as_bytes(),
            &req.repo_id,
            &req.repo_owner,
            &req.community_id,
            &req.pusher_pubkey,
            &req.ref_updates,
            req.timestamp,
        );
        hook_policy_check(State(f.state.clone()), Json(req))
            .await
            .status()
    }
    assert_eq!(check(&f, &f.owner, "human-owned").await, StatusCode::OK);
    assert_eq!(check(&f, &f.bot, "bot-owned").await, StatusCode::OK);
    f.revoke().await;
    assert_eq!(
        check(&f, &f.owner, "human-owned").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(check(&f, &f.bot, "bot-owned").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_fanout_revocation_drops_stale_global_open_and_private_subscribers() {
    use std::{collections::HashMap, sync::atomic::AtomicU8};
    use tokio::sync::{mpsc, Mutex};
    use tokio_util::sync::CancellationToken;
    for visibility in [ChannelVisibility::Open, ChannelVisibility::Private] {
        let f = Fixture::new(visibility, true).await;
        f.admit().await;
        let register = |keys: &Keys| {
            let id = Uuid::new_v4();
            f.state.conn_manager.register(
                id,
                mpsc::channel(1).0,
                mpsc::channel(1).0,
                mpsc::channel(1).0,
                None,
                CancellationToken::new(),
                f.tenant.community(),
                Arc::new(AtomicU8::new(0)),
                Arc::new(Mutex::new(HashMap::new())),
                3,
                crate::state::CommunityConnectionControl::new(CancellationToken::new()),
            );
            f.state
                .conn_manager
                .set_authenticated_pubkey(id, keys.public_key().to_bytes().to_vec());
            id
        };
        let bot = register(&f.bot);
        let owner = register(&f.owner);
        let matches = vec![(bot, "stale".to_string()), (owner, "legacy".to_string())];
        for revoked in [false, true] {
            if revoked {
                f.revoke().await;
            }
            for channel in [None, Some(f.channel)] {
                let stored = buzz_core::StoredEvent::new(f.message(channel), channel);
                let out = crate::handlers::event::filter_fanout_by_access(
                    &f.state,
                    f.tenant.community(),
                    &stored,
                    matches.clone(),
                    None,
                )
                .await;
                assert_eq!(out.contains(&(bot, "stale".to_string())), !revoked);
                assert!(out.contains(&(owner, "legacy".to_string())));
            }
        }
    }
}
