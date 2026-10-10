//! Actual handle_req regression: fail its database only after authorization
//! and live registration, then assert failure cannot masquerade as empty EOSE.
use super::*;
use std::sync::atomic::AtomicU8;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn history_database_failure_closes_without_eose_and_releases_topics() {
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("owned test database");
    let state = crate::state::tests::test_state_with_database_pool(pool.clone()).await;
    let keys = nostr::Keys::generate();
    let community = buzz_core::tenant::CommunityId::from_uuid(uuid::Uuid::new_v4());
    let channel = uuid::Uuid::new_v4();
    let cancel = CancellationToken::new();
    let (send_tx, mut send_rx) = mpsc::channel(8);
    let (ctrl_tx, _ctrl_rx) = mpsc::channel(1);
    let (terminal_ctrl_tx, _terminal_ctrl_rx) = mpsc::channel(1);
    let conn = Arc::new(ConnectionState {
        conn_id: uuid::Uuid::new_v4(),
        tenant: buzz_core::tenant::TenantContext::resolved(community, "test.local".to_string()),
        remote_addr: "127.0.0.1:1234".parse().expect("address"),
        auth_state: std::sync::Mutex::new(AuthState::Authenticated(buzz_auth::AuthContext {
            pubkey: keys.public_key(),
            scopes: vec![],
            channel_ids: None,
            auth_method: buzz_auth::AuthMethod::Nip42,
            agent_owner_pubkey: None,
        })),
        subscriptions: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        send_tx,
        ctrl_tx,
        terminal_ctrl_tx,
        cancel: cancel.clone(),
        backpressure_count: Arc::new(AtomicU8::new(0)),
        grace_limit: 3,
        nip_fi_assertion: None,
        session_deadline: None,
        nip_fi_gate: crate::nip_fi_gate::SessionAdmissionGate::off_mode(cancel.clone()),
        community_control: crate::state::CommunityConnectionControl::new(cancel),
    });
    state.accessible_channels_cache.insert(
        (community, keys.public_key().to_bytes().to_vec()),
        vec![channel],
    );
    let filter = Filter::new()
        .kind(nostr::Kind::Custom(9))
        .author(keys.public_key())
        .custom_tag(
            nostr::SingleLetterTag::lowercase(nostr::Alphabet::H),
            channel.to_string(),
        )
        .limit(65);
    let (arrived, release) = crate::nip_fi_test_hooks::req_history_hook::arm(community);
    let task = tokio::spawn(handle_req(
        "personal-history".to_string(),
        vec![filter],
        vec![],
        Arc::clone(&conn),
        Arc::clone(&state),
    ));
    tokio::time::timeout(Duration::from_secs(5), arrived)
        .await
        .expect("history reached after authorization")
        .expect("history hook");
    let topic = EventTopic::Channel(channel);
    assert_eq!(state.pubsub.topic_refcount(&conn.tenant, topic).await, 1);
    assert!(conn
        .subscriptions
        .lock()
        .await
        .contains_key("personal-history"));

    // A real, deterministic non-timeout DB failure at the production seam.
    pool.close().await;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("failed history terminates")
        .expect("handler did not panic");
    let frames: Vec<String> = std::iter::from_fn(|| send_rx.try_recv().ok())
        .map(|frame| match frame {
            axum::extract::ws::Message::Text(text) => text.to_string(),
            other => panic!("unexpected frame: {other:?}"),
        })
        .collect();
    assert_eq!(
        frames,
        vec![r#"["CLOSED","personal-history","error: database error"]"#],
        "database failure must never produce successful EOSE or raw database details"
    );
    assert!(conn.subscriptions.lock().await.is_empty());
    assert!(state
        .sub_registry
        .get_filters(conn.conn_id, "personal-history")
        .is_none());
    assert_eq!(state.pubsub.topic_refcount(&conn.tenant, topic).await, 0);
}
