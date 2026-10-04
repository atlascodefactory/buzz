//! Command-seam tests: the HTTP peer is synthetic, not relay acceptance evidence.

use std::sync::{Arc, Mutex};

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use nostr::{Event, Keys};
use tokio::task::JoinHandle;

use super::cmd_admit_bot;
use crate::client::BuzzClient;

async fn peer(accept: bool) -> (String, Arc<Mutex<Vec<Event>>>, JoinHandle<()>) {
    let submitted = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/events",
            post(
                move |State(events): State<Arc<Mutex<Vec<Event>>>>, body: Bytes| async move {
                    let event: Event = serde_json::from_slice(&body).unwrap();
                    event.verify().unwrap();
                    let id = event.id.to_hex();
                    events.lock().unwrap().push(event);
                    if accept {
                        (
                            StatusCode::OK,
                            axum::Json(
                                serde_json::json!({"event_id":id,"accepted":true,"message":""}),
                            ),
                        )
                    } else {
                        (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({"error":"unsupported kind"})),
                        )
                    }
                },
            ),
        )
        .with_state(submitted.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), submitted, server)
}

#[tokio::test]
async fn conditional_bot_command_signs_exact_bounded_envelope() {
    let (url, submitted, server) = peer(true).await;
    let (actor, bot, member) = (Keys::generate(), Keys::generate(), Keys::generate());
    let client = BuzzClient::new(url, actor.clone(), None, None).unwrap();
    let channel = uuid::Uuid::new_v4().to_string();
    cmd_admit_bot(
        &client,
        &channel,
        &bot.public_key().to_hex(),
        &member.public_key().to_hex(),
        "absent",
    )
    .await
    .unwrap();
    server.abort();
    let events = submitted.lock().unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.pubkey, actor.public_key());
    assert_eq!(
        event.kind.as_u16(),
        buzz_core::kind::KIND_CONDITIONAL_BOT_ADMISSION as u16
    );
    assert!(event.content.is_empty());
    assert_eq!(event.tags.len(), 6);
    for (name, value) in [
        ("h", channel),
        ("p", bot.public_key().to_hex()),
        ("role", "bot".into()),
        ("required-member", member.public_key().to_hex()),
        ("expected-role", "absent".into()),
        ("expiration", (event.created_at.as_secs() + 60).to_string()),
    ] {
        assert!(event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == [name, value.as_str()]));
    }
}

#[tokio::test]
async fn conditional_bot_command_rejects_bad_state_and_never_falls_back() {
    let (url, submitted, server) = peer(false).await;
    let (actor, bot, member) = (Keys::generate(), Keys::generate(), Keys::generate());
    let client = BuzzClient::new(url, actor, None, None).unwrap();
    let channel = uuid::Uuid::new_v4().to_string();
    assert!(cmd_admit_bot(
        &client,
        &channel,
        &bot.public_key().to_hex(),
        &member.public_key().to_hex(),
        "admin"
    )
    .await
    .is_err());
    assert!(submitted.lock().unwrap().is_empty());
    assert!(cmd_admit_bot(
        &client,
        &channel,
        &bot.public_key().to_hex(),
        &member.public_key().to_hex(),
        "absent"
    )
    .await
    .is_err());
    server.abort();
    let events = submitted.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "unsupported command must not become unconditional kind9000"
    );
    assert_eq!(
        events[0].kind.as_u16(),
        buzz_core::kind::KIND_CONDITIONAL_BOT_ADMISSION as u16
    );
}
