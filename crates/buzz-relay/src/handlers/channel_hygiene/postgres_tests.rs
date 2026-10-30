//! Production-seam regression tests: verified ownership, ingest, HTTP and WS.

use super::*;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue},
};
use base64::Engine;
use buzz_db::channel::{ChannelType, ChannelVisibility};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::{json, Value};

use crate::handlers::ingest::{ingest_event, HttpAuthMethod, IngestAuth};

async fn state(owner: &Keys, owner_fallback: bool) -> (Arc<AppState>, sqlx::PgPool, TenantContext) {
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .unwrap();
    let db = buzz_db::Db::from_pool(pool.clone());
    let host = format!("hygiene-{}.example", Uuid::new_v4().simple());
    let community = db.ensure_configured_community(&host).await.unwrap().id;
    let mut config = crate::config::Config::from_env().unwrap();
    config.require_relay_membership = false;
    config.relay_url = format!("wss://{host}");
    config.relay_operator_pubkeys = if owner_fallback {
        vec![]
    } else {
        vec![owner.public_key().to_hex()]
    };
    config.relay_owner_pubkey = Some(owner.public_key().to_hex());
    let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .unwrap();
    let pubsub = Arc::new(
        buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
            .await
            .unwrap(),
    );
    let audit = buzz_audit::AuditService::new(pool.clone());
    let auth = buzz_auth::AuthService::new(config.auth.clone());
    let search = buzz_search::SearchService::new(pool.clone());
    let workflows = Arc::new(buzz_workflow::WorkflowEngine::new(
        db.clone(),
        Default::default(),
    ));
    let media = buzz_media::MediaStorage::new(&config.media).unwrap();
    let (state, _shutdown) = AppState::new(
        config,
        db,
        redis_pool,
        audit,
        pubsub,
        auth,
        search,
        workflows,
        Keys::generate(),
        media,
    );
    (
        Arc::new(state),
        pool,
        TenantContext::resolved(community, &host),
    )
}

async fn bind(state: &AppState, tenant: &TenantContext, agent: &Keys, owner: &Keys) {
    for keys in [agent, owner] {
        state
            .db
            .ensure_user(tenant.community(), &keys.public_key().to_bytes())
            .await
            .unwrap();
    }
    assert!(state
        .db
        .set_agent_owner_for_authorization(
            tenant.community(),
            &agent.public_key().to_bytes(),
            &owner.public_key().to_bytes()
        )
        .await
        .unwrap());
}

async fn channel(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    owner: &Keys,
    kind: ChannelType,
    name: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    state
        .db
        .create_channel_with_id(
            tenant.community(),
            id,
            name,
            kind,
            ChannelVisibility::Private,
            Some("Description"),
            &owner.public_key().to_bytes(),
            None,
        )
        .await
        .unwrap();
    super::super::side_effects::emit_group_discovery_events(tenant, state, id)
        .await
        .unwrap();
    id
}

fn edit(keys: &Keys, channel: Uuid, name: &str, extra: Option<(&str, &str)>) -> Event {
    let mut tags = vec![
        Tag::parse(["h", &channel.to_string()]).unwrap(),
        Tag::parse(["name", name]).unwrap(),
    ];
    if let Some((key, value)) = extra {
        tags.push(Tag::parse([key, value]).unwrap());
    }
    EventBuilder::new(Kind::Custom(9002), "")
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap()
}

async fn ingest(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: Event,
) -> Result<super::super::ingest::IngestResult, super::super::ingest::IngestError> {
    let auth = IngestAuth::Http {
        pubkey: event.pubkey,
        scopes: buzz_auth::Scope::all_known(),
        auth_method: HttpAuthMethod::Nip98,
    };
    ingest_event(state, tenant, event, auth).await
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn verified_operator_binding_is_tenant_local_and_revoked_on_next_request() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let (state, _, tenant) = state(&owner, true).await;
    assert_eq!(
        operator_owner(&state, tenant.community(), &agent.public_key().to_bytes())
            .await
            .unwrap(),
        None
    );
    bind(&state, &tenant, &agent, &owner).await;
    assert_eq!(
        operator_owner(&state, tenant.community(), &agent.public_key().to_bytes())
            .await
            .unwrap(),
        Some(owner.public_key().to_bytes())
    );
    let other = state
        .db
        .ensure_configured_community(&format!("other-{}.example", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    assert_eq!(
        operator_owner(&state, other, &agent.public_key().to_bytes())
            .await
            .unwrap(),
        None
    );
    let db_owner = Keys::generate();
    let db_agent = Keys::generate();
    bind(&state, &tenant, &db_agent, &db_owner).await;
    let pk = db_owner.public_key().to_bytes();
    state
        .db
        .upsert_relay_operator(&pk, "moderator", &owner.public_key().to_bytes(), true)
        .await
        .unwrap();
    assert!(operator_owner(
        &state,
        tenant.community(),
        &db_agent.public_key().to_bytes()
    )
    .await
    .unwrap()
    .is_none());
    state
        .db
        .upsert_relay_operator(&pk, "operator", &owner.public_key().to_bytes(), true)
        .await
        .unwrap();
    assert!(operator_owner(
        &state,
        tenant.community(),
        &db_agent.public_key().to_bytes()
    )
    .await
    .unwrap()
    .is_some());
    state
        .db
        .remove_relay_operator(&pk, &owner.public_key().to_bytes(), true)
        .await
        .unwrap();
    assert!(operator_owner(
        &state,
        tenant.community(),
        &db_agent.public_key().to_bytes()
    )
    .await
    .unwrap()
    .is_none());
    // A second credential cannot relabel the already-bound agent as its own.
    assert!(!state
        .db
        .set_agent_owner_for_authorization(
            tenant.community(),
            &agent.public_key().to_bytes(),
            &db_owner.public_key().to_bytes()
        )
        .await
        .unwrap());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_delegates_only_names_and_preserves_existing_channel_owner_deletion() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let creator = Keys::generate();
    let (state, pool, tenant) = state(&owner, false).await;
    bind(&state, &tenant, &agent, &owner).await;
    let ch = channel(&state, &tenant, &creator, ChannelType::Stream, "old-name").await;
    assert!(!state
        .db
        .is_member(tenant.community(), ch, &agent.public_key().to_bytes())
        .await
        .unwrap());
    // Current production labels and discovery identity must survive an atomic rename.
    sqlx::query(
        "UPDATE channels SET labels=ARRAY['customer']::text[] WHERE community_id=$1 AND id=$2",
    )
    .bind(tenant.community().as_uuid())
    .bind(ch)
    .execute(&pool)
    .await
    .unwrap();
    // Exactly the unchanged CLI/SDK format, including injected NIP-OA auth.
    let credential = buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "").unwrap();
    let event = buzz_sdk::build_update_channel(ch, Some("new-name"), None, None, None)
        .unwrap()
        .tags([buzz_sdk::nip_oa::parse_auth_tag(&credential).unwrap()])
        .sign_with_keys(&agent)
        .unwrap();
    assert!(
        ingest(&state, &tenant, event.clone())
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(
        state
            .db
            .get_channel_for_event_write(tenant.community(), ch)
            .await
            .unwrap()
            .name,
        "new-name"
    );
    assert_eq!(
        ingest(&state, &tenant, event.clone())
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    let audit: Vec<Value> = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE community_id=$1 AND action='channel_updated'",
    )
    .bind(tenant.community().as_uuid())
    .fetch_all(&pool)
    .await
    .unwrap();
    let metadata = http_query(
        &state,
        &tenant,
        &agent,
        json!([{"kinds":[39000],"#h":[ch]}]),
    )
    .await;
    assert_eq!(metadata.len(), 1);
    let tags = metadata[0]["tags"].as_array().unwrap();
    assert!(tags.contains(&json!(["t", "customer"])));
    assert!(tags.contains(&json!(["P", creator.public_key().to_hex()])));
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["old_name"], "old-name");
    assert_eq!(audit[0]["new_name"], "new-name");
    assert_eq!(audit[0]["operator_owner"], owner.public_key().to_hex());
    for key in ["about", "visibility", "archived", "ttl", "topic", "purpose"] {
        assert!(
            ingest(
                &state,
                &tenant,
                edit(&agent, ch, "forbidden", Some((key, "value")))
            )
            .await
            .is_err(),
            "{key}"
        );
    }
    let deletion = |id: Uuid| {
        EventBuilder::new(Kind::Custom(9008), "")
            .tags([Tag::parse(["h", &id.to_string()]).unwrap()])
            .sign_with_keys(&agent)
            .unwrap()
    };
    assert!(ingest(&state, &tenant, deletion(ch)).await.is_err());
    let dm = channel(&state, &tenant, &creator, ChannelType::Dm, "private-dm").await;
    assert!(ingest(&state, &tenant, edit(&agent, dm, "dm-leak", None))
        .await
        .is_err());
    let own = channel(&state, &tenant, &agent, ChannelType::Stream, "agent-owned").await;
    assert!(
        ingest(&state, &tenant, deletion(own))
            .await
            .unwrap()
            .accepted
    );
    let ordinary_agent = Keys::generate();
    let created = Uuid::new_v4();
    let create =
        buzz_sdk::build_create_channel(created, "ordinary-agent-created", None, None, None, None)
            .unwrap()
            .sign_with_keys(&ordinary_agent)
            .unwrap();
    assert!(ingest(&state, &tenant, create).await.unwrap().accepted);
    let restricted = IngestAuth::Nip42 {
        pubkey: agent.public_key(),
        scopes: buzz_auth::Scope::all_known(),
        channel_ids: Some(vec![]),
        conn_id: Uuid::new_v4(),
    };
    assert!(ingest_event(
        &state,
        &tenant,
        edit(&agent, ch, "scope-escape", None),
        restricted
    )
    .await
    .is_err());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn stale_and_conflicting_plans_rollback_signed_event_name_and_audit() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let creator = Keys::generate();
    let (state, pool, tenant) = state(&owner, false).await;
    bind(&state, &tenant, &agent, &owner).await;
    let ch = channel(&state, &tenant, &creator, ChannelType::Stream, "before").await;
    channel(&state, &tenant, &creator, ChannelType::Forum, "reserved").await;
    let first = edit(&agent, ch, "after-a", Some(("expected-name", "before")));
    let second = edit(&agent, ch, "after-b", Some(("expected-name", "before")));
    let (a, b) = tokio::join!(
        ingest(&state, &tenant, first.clone()),
        ingest(&state, &tenant, second.clone())
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one same-preview edit can win: {:?} / {:?}",
        a.as_ref().err(),
        b.as_ref().err()
    );
    let (current, loser) = if a.is_ok() {
        ("after-a", second)
    } else {
        ("after-b", first)
    };
    let loser_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE community_id=$1 AND id=$2")
            .bind(tenant.community().as_uuid())
            .bind(loser.id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(loser_count, 0, "rejected intent is rolled back");
    assert!(ingest(
        &state,
        &tenant,
        edit(&agent, ch, "RESERVED", Some(("expected-name", current)))
    )
    .await
    .is_err());
    assert_eq!(
        state
            .db
            .get_channel_for_event_write(tenant.community(), ch)
            .await
            .unwrap()
            .name,
        current
    );
    // Undo is a new signed rename, guarded against overwriting someone else's work.
    assert!(
        ingest(
            &state,
            &tenant,
            edit(&agent, ch, "before", Some(("expected-name", current)))
        )
        .await
        .unwrap()
        .accepted
    );
    let service = buzz_audit::AuditService::new(pool.clone());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE community_id=$1")
        .bind(tenant.community().as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(service
        .verify_chain(tenant.community(), 1, count)
        .await
        .unwrap());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn failed_discovery_insert_rolls_back_name_signed_request_and_audit() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let creator = Keys::generate();
    let (state, pool, tenant) = state(&owner, false).await;
    bind(&state, &tenant, &agent, &owner).await;
    let ch = channel(
        &state,
        &tenant,
        &creator,
        ChannelType::Stream,
        "before-fault",
    )
    .await;
    let suffix = Uuid::new_v4().simple().to_string();
    let function = format!("hygiene_fault_{suffix}");
    let trigger = format!("hygiene_fault_trigger_{suffix}");
    // Only generated UUIDs enter these test-only DDL identifiers/literals.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF NEW.kind=39000 AND NEW.channel_id='{ch}'::uuid THEN RAISE EXCEPTION 'injected snapshot failure'; END IF; \
         RETURN NEW; END $$; CREATE TRIGGER {trigger} BEFORE INSERT ON events \
         FOR EACH ROW EXECUTE FUNCTION {function}();"
    ))).execute(&pool).await.unwrap();
    let event = edit(&agent, ch, "after-fault", None);
    assert!(matches!(
        ingest(&state, &tenant, event.clone()).await,
        Err(super::super::ingest::IngestError::Internal(_))
    ));
    assert_eq!(
        state
            .db
            .get_channel_for_event_write(tenant.community(), ch)
            .await
            .unwrap()
            .name,
        "before-fault"
    );
    let intents: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE community_id=$1 AND id=$2")
            .bind(tenant.community().as_uuid())
            .bind(event.id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    let audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE community_id=$1 AND action='channel_updated'",
    )
    .bind(tenant.community().as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((intents, audit), (0, 0));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;"
    )))
    .execute(&pool)
    .await
    .unwrap();
    assert!(ingest(&state, &tenant, event).await.unwrap().accepted);
    let metadata = http_query(
        &state,
        &tenant,
        &agent,
        json!([{"kinds":[39000],"#d":[ch]}]),
    )
    .await;
    assert_eq!(metadata.len(), 1);
    assert!(metadata[0]["tags"]
        .as_array()
        .unwrap()
        .contains(&json!(["name", "after-fault"])));
}

async fn http_query(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    agent: &Keys,
    filters: Value,
) -> Vec<Value> {
    use sha2::{Digest, Sha256};
    let body = serde_json::to_vec(&filters).unwrap();
    let auth = EventBuilder::new(Kind::Custom(27235), "")
        .tags([
            Tag::parse(["u", &format!("https://{}/query", tenant.host())]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            Tag::parse(["payload", &hex::encode(Sha256::digest(&body))]).unwrap(),
            Tag::parse(["nonce", &Uuid::new_v4().to_string()]).unwrap(),
        ])
        .sign_with_keys(agent)
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_str(tenant.host()).unwrap());
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&auth).unwrap())
        ))
        .unwrap(),
    );
    let response =
        crate::api::bridge::query_events(State(state.clone()), headers, Bytes::from(body))
            .await
            .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice::<Value>(&body)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

async fn ws_query(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    agent: &Keys,
    filters: Vec<Filter>,
    allowed: Option<Vec<Uuid>>,
) -> Vec<Value> {
    use crate::connection::{AuthState, ConnectionState};
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let (ctrl_tx, _) = tokio::sync::mpsc::channel(1);
    let cancel = tokio_util::sync::CancellationToken::new();
    let conn = Arc::new(ConnectionState {
        conn_id: Uuid::new_v4(),
        tenant: tenant.clone(),
        remote_addr: "127.0.0.1:12345".parse().unwrap(),
        auth_state: std::sync::Mutex::new(AuthState::Authenticated(buzz_auth::AuthContext {
            pubkey: agent.public_key(),
            scopes: vec![],
            channel_ids: allowed,
            auth_method: buzz_auth::AuthMethod::Nip98,
            agent_owner_pubkey: None,
        })),
        subscriptions: Default::default(),
        send_tx: tx,
        ctrl_tx,
        terminal_ctrl_tx: tokio::sync::mpsc::channel(1).0,
        cancel: cancel.clone(),
        nip_fi_assertion: None,
        session_deadline: None,
        nip_fi_gate: crate::nip_fi_gate::SessionAdmissionGate::off_mode(cancel.clone()),
        community_control: crate::state::CommunityConnectionControl::new(cancel),
        backpressure_count: Default::default(),
        grace_limit: 3,
    });
    super::super::req::handle_req(
        "hygiene".into(),
        filters,
        vec![],
        conn.clone(),
        state.clone(),
    )
    .await;
    let mut events = vec![];
    while let Ok(frame) = rx.try_recv() {
        if let axum::extract::ws::Message::Text(text) = frame {
            let value: Value = serde_json::from_str(text.as_str()).unwrap();
            if value[0] == "EVENT" {
                events.push(value[2].clone());
            }
        }
    }
    events
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_http_and_ws_do_not_grant_messages_rosters_dms_or_token_scope() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let creator = Keys::generate();
    let (state, _, tenant) = state(&owner, false).await;
    bind(&state, &tenant, &agent, &owner).await;
    let ch = channel(
        &state,
        &tenant,
        &creator,
        ChannelType::Stream,
        "hidden-name",
    )
    .await;
    channel(&state, &tenant, &creator, ChannelType::Dm, "hidden-dm").await;
    let message = EventBuilder::new(Kind::Custom(9), "SECRET")
        .tags([Tag::parse(["h", &ch.to_string()]).unwrap()])
        .sign_with_keys(&creator)
        .unwrap();
    assert!(ingest(&state, &tenant, message).await.unwrap().accepted);
    let raw = json!([{"kinds":[39000],"limit":100}]);
    let http = http_query(&state, &tenant, &agent, raw.clone()).await;
    assert_eq!(http.len(), 1);
    let outsider = Keys::generate();
    assert!(http_query(&state, &tenant, &outsider, raw.clone())
        .await
        .is_empty());
    let explicit = json!([{"kinds":[39000],"#h":[ch]}]);
    assert_eq!(
        ws_query(
            &state,
            &tenant,
            &agent,
            serde_json::from_value(explicit.clone()).unwrap(),
            None
        )
        .await
        .len(),
        1
    );
    assert_eq!(http_query(&state, &tenant, &agent, explicit).await.len(), 1);

    let filters: Vec<Filter> = serde_json::from_value(raw).unwrap();
    let ws = ws_query(&state, &tenant, &agent, filters.clone(), None).await;
    assert_eq!(ws.len(), 1);
    assert_eq!(http[0]["id"], ws[0]["id"]);
    assert!(ws_query(&state, &tenant, &agent, filters, Some(vec![]))
        .await
        .is_empty());
    for kind in [9, 39001, 39002, 40100] {
        assert!(
            http_query(&state, &tenant, &agent, json!([{"kinds":[kind],"#h":[ch]}]))
                .await
                .is_empty(),
            "kind {kind}"
        );
    }
    for raw in [
        json!([{"kinds":[9,39000]}]),
        json!([{"kinds":[39000]}, {"kinds":[9],"#h":[ch]}]),
    ] {
        let separate_metadata_filter = raw.as_array().unwrap().len() == 2;
        let http = http_query(&state, &tenant, &agent, raw.clone()).await;
        let ws = ws_query(
            &state,
            &tenant,
            &agent,
            serde_json::from_value(raw).unwrap(),
            None,
        )
        .await;
        assert!(http.iter().chain(&ws).all(|e| e["kind"] == 39000));
        if separate_metadata_filter {
            assert_eq!(http.len(), 1);
            assert_eq!(ws.len(), 1);
        } else {
            assert!(http.is_empty() && ws.is_empty());
        }
    }
    assert!(
        http_query(
            &state,
            &tenant,
            &creator,
            json!([{"kinds":[39000],"#d":[ch]}])
        )
        .await
        .len()
            == 1
    );
    assert!(!state
        .db
        .is_member(tenant.community(), ch, &agent.public_key().to_bytes())
        .await
        .unwrap());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn archived_channel_stays_read_only_and_existing_owner_can_unarchive() {
    let operator = Keys::generate();
    let agent = Keys::generate();
    let creator = Keys::generate();
    let (state, pool, tenant) = state(&operator, false).await;
    bind(&state, &tenant, &agent, &operator).await;
    let ch = channel(
        &state,
        &tenant,
        &creator,
        ChannelType::Stream,
        "archived-before",
    )
    .await;
    sqlx::query("UPDATE channels SET archived_at=now() WHERE community_id=$1 AND id=$2")
        .bind(tenant.community().as_uuid())
        .bind(ch)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        ingest(&state, &tenant, edit(&agent, ch, "inherited-denied", None))
            .await
            .is_err()
    );
    assert!(
        ingest(&state, &tenant, edit(&creator, ch, "owner-denied", None))
            .await
            .is_err()
    );
    let unarchive = EventBuilder::new(Kind::Custom(9002), "")
        .tags([
            Tag::parse(["h", &ch.to_string()]).unwrap(),
            Tag::parse(["archived", "false"]).unwrap(),
        ])
        .sign_with_keys(&creator)
        .unwrap();
    assert!(ingest(&state, &tenant, unarchive).await.unwrap().accepted);
    assert!(
        ingest(&state, &tenant, edit(&creator, ch, "owner-allowed", None))
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(
        state
            .db
            .get_channel_for_event_write(tenant.community(), ch)
            .await
            .unwrap()
            .name,
        "owner-allowed"
    );
}
