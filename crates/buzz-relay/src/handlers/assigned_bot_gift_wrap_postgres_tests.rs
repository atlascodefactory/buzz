//! Authenticated transport actor is not the gift-wrap's ephemeral signer.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn frame(socket: &mut TestSocket, kind: &str, id: Option<&str>) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let message = socket.next().await.unwrap().unwrap();
            if let Message::Text(text) = message {
                let value: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                if value[0] == kind && id.is_none_or(|id| value[1] == id) {
                    return value;
                }
            }
        }
    })
    .await
    .unwrap()
}

fn gift_wrap(recipient: &Keys) -> Event {
    EventBuilder::new(Kind::GiftWrap, "synthetic opaque envelope")
        .tags([Tag::public_key(recipient.public_key())])
        .sign_with_keys(&Keys::generate())
        .unwrap()
}

fn actor_auth(actor: &Keys) -> IngestAuth {
    IngestAuth::Nip42 {
        pubkey: actor.public_key(),
        scopes: vec![Scope::MessagesWrite],
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    }
}

async fn assert_pending_withdrawal(commit: bool) {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    f.admit().await;
    let event = gift_wrap(&f.owner);
    assert_ne!(event.pubkey, f.bot.public_key());
    let event_id = event.id;
    let mut withdrawal = f.state.db.pool().begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *withdrawal)
        .await
        .unwrap();
    sqlx::query("UPDATE assigned_bots SET revoked_at = clock_timestamp() WHERE community_id = $1 AND bot_pubkey = $2")
        .bind(f.tenant.community().as_uuid())
        .bind(f.bot.public_key().as_bytes())
        .execute(&mut *withdrawal).await.unwrap();
    // Early nonlocking auth must still see the committed active assignment.
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
    let (state, tenant, auth) = (f.state.clone(), f.tenant.clone(), actor_auth(&f.bot));
    let mut request = tokio::spawn(async move { ingest_event(&state, &tenant, event, auth).await });
    let waited = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)))",
            ).bind(blocker).fetch_one(f.state.db.pool()).await.unwrap();
            if waiting { return true; }
            if request.is_finished() { return false; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    if commit {
        withdrawal.commit().await.unwrap();
    } else {
        withdrawal.rollback().await.unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(5), &mut request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        waited,
        "actual ingest must wait for the authenticated actor withdrawal"
    );
    if commit {
        assert!(
            matches!(result, Err(super::super::super::ingest::IngestError::Rejected(ref reason))
            if reason == "restricted: assigned agent write withdrawn")
        );
    } else {
        assert!(result.unwrap().accepted);
    }
    let stored = f
        .state
        .db
        .get_event_by_id_for_event_write(f.tenant.community(), event_id.as_bytes())
        .await
        .unwrap();
    assert_eq!(stored.is_some(), !commit);
    let mentions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM event_mentions WHERE community_id = $1 AND event_id = $2",
    )
    .bind(f.tenant.community().as_uuid())
    .bind(event_id.as_bytes())
    .fetch_one(f.state.db.pool())
    .await
    .unwrap();
    assert_eq!(mentions, i64::from(!commit));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_ingest_fences_authenticated_actor_revocation_commit() {
    assert_pending_withdrawal(true).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_ingest_fences_authenticated_actor_revocation_rollback() {
    assert_pending_withdrawal(false).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_ingest_preserves_active_and_legacy_actors_and_http_denial() {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    f.admit().await;
    for actor in [&f.bot, &f.owner] {
        let event = gift_wrap(&f.owner);
        assert_ne!(event.pubkey, actor.public_key());
        assert!(
            ingest_event(&f.state, &f.tenant, event.clone(), actor_auth(actor))
                .await
                .unwrap()
                .accepted
        );
        let replay = ingest_event(&f.state, &f.tenant, event, actor_auth(actor))
            .await
            .unwrap();
        assert!(replay.accepted);
        assert_eq!(replay.message, "duplicate:");
    }
    let event = gift_wrap(&f.owner);
    assert!(
        matches!(ingest_event(&f.state, &f.tenant, event, f.bot_http()).await,
        Err(super::super::super::ingest::IngestError::Rejected(ref reason))
        if reason.contains("only accepted via WebSocket"))
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_real_websocket_auth_and_midflight_withdrawal() {
    let f = Fixture::new(ChannelVisibility::Private, true).await;
    f.admit().await;
    let server = LocalHttpRelay::new(f.state.clone()).await;
    let mut request = format!("ws://{}/", server.address)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("host", f.tenant.host().parse().unwrap());
    let (mut socket, _) = connect_async(request).await.unwrap();
    let challenge = frame(&mut socket, "AUTH", None).await;
    let relay = crate::api::bridge::nip42_expected_relay_url(&f.state.config.relay_url, &f.tenant);
    let auth = EventBuilder::auth(challenge[1].as_str().unwrap(), relay.parse().unwrap())
        .sign_with_keys(&f.bot)
        .unwrap();
    socket
        .send(Message::Text(
            serde_json::json!(["AUTH", auth]).to_string().into(),
        ))
        .await
        .unwrap();
    let accepted = frame(&mut socket, "OK", Some(&auth.id.to_hex())).await;
    assert_eq!(accepted[2], true, "{accepted}");
    let first = gift_wrap(&f.owner);
    socket
        .send(Message::Text(
            serde_json::json!(["EVENT", first]).to_string().into(),
        ))
        .await
        .unwrap();
    let accepted = frame(&mut socket, "OK", Some(&first.id.to_hex())).await;
    assert_eq!(accepted[2], true, "{accepted}");
    assert!(f
        .state
        .db
        .get_event_by_id_for_event_write(f.tenant.community(), first.id.as_bytes())
        .await
        .unwrap()
        .is_some());

    let mut withdrawal = f.state.db.pool().begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *withdrawal)
        .await
        .unwrap();
    sqlx::query("UPDATE assigned_bots SET revoked_at = clock_timestamp() WHERE community_id = $1 AND bot_pubkey = $2")
        .bind(f.tenant.community().as_uuid()).bind(f.bot.public_key().as_bytes())
        .execute(&mut *withdrawal).await.unwrap();
    let second = gift_wrap(&f.owner);
    socket
        .send(Message::Text(
            serde_json::json!(["EVENT", second]).to_string().into(),
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)))")
                .bind(blocker).fetch_one(f.state.db.pool()).await.unwrap();
            if waiting { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    withdrawal.commit().await.unwrap();
    let denied = frame(&mut socket, "OK", Some(&second.id.to_hex())).await;
    assert_eq!(denied[2], false, "{denied}");
    assert_eq!(denied[3], "restricted: assigned agent write withdrawn");
    assert!(f
        .state
        .db
        .get_event_by_id_for_event_write(f.tenant.community(), second.id.as_bytes())
        .await
        .unwrap()
        .is_none());
    let mentions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM event_mentions WHERE community_id = $1 AND event_id = $2",
    )
    .bind(f.tenant.community().as_uuid())
    .bind(second.id.as_bytes())
    .fetch_one(f.state.db.pool())
    .await
    .unwrap();
    assert_eq!(mentions, 0);
    socket.close(None).await.unwrap();
}
