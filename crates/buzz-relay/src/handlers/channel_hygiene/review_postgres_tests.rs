//! Regressions for the production-line review's assignment and lock boundaries.
use super::*;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn operator_owned_assignment_does_not_expand_channel_discovery() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let stranger = Keys::generate();
    let authority = Keys::generate();
    let (state, pool, tenant) = state(&owner, false).await;
    bind(&state, &tenant, &agent, &owner).await;
    let admitted = channel(&state, &tenant, &owner, ChannelType::Stream, "assigned").await;
    let outside = channel(&state, &tenant, &stranger, ChannelType::Stream, "outside").await;
    buzz_db::relay_members::add_relay_member(
        &pool,
        tenant.community(),
        &owner.public_key().to_hex(),
        "member",
        None,
    )
    .await
    .unwrap();
    let filters = json!([{"kinds":[39000],"limit":100}]);
    assert_eq!(
        http_query(&state, &tenant, &agent, filters.clone())
            .await
            .len(),
        2
    );
    let now = nostr::Timestamp::now().as_secs().saturating_sub(1);
    let tags = [
        ("community", tenant.community().to_string()),
        ("owner", owner.public_key().to_hex()),
        ("p", agent.public_key().to_hex()),
        ("assignment", Uuid::new_v4().to_string()),
        ("assignment-version", "1".into()),
        ("nonce", Uuid::new_v4().to_string()),
        ("expiration", (now + 60).to_string()),
        ("h", admitted.to_string()),
        ("role", "bot".into()),
        ("expected-role", "absent".into()),
    ];
    let event = EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_ASSIGNED_BOT_ADMISSION as u16),
        "",
    )
    .custom_created_at(nostr::Timestamp::from(now))
    .tags(
        tags.into_iter()
            .map(|(key, value)| Tag::parse([key.to_owned(), value]).unwrap()),
    )
    .sign_with_keys(&authority)
    .unwrap();
    let command = buzz_core::assigned_bot::AssignedBotCommand::verify(
        &event,
        tenant.community(),
        &authority.public_key(),
        Some(&authority.public_key()),
        now,
    )
    .unwrap();
    let mut tx = state
        .db
        .begin_event_write_transaction(tenant.community())
        .await
        .unwrap();
    assert!(
        buzz_db::assigned_bot::apply_in_transaction(&mut tx, &command)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let http = http_query(&state, &tenant, &agent, filters.clone()).await;
    let ws = ws_query(
        &state,
        &tenant,
        &agent,
        serde_json::from_value(filters).unwrap(),
        None,
    )
    .await;
    assert_eq!(http.len(), 1);
    assert_eq!(ws.len(), 1);
    assert_eq!(http[0]["id"], ws[0]["id"]);
    assert!(http[0]["tags"]
        .as_array()
        .unwrap()
        .contains(&json!(["d", admitted.to_string()])));
    assert!(http_query(
        &state,
        &tenant,
        &agent,
        json!([{"kinds":[39000],"#h":[outside]}])
    )
    .await
    .is_empty());
    assert!(
        ingest(&state, &tenant, edit(&agent, outside, "forbidden", None))
            .await
            .is_err()
    );
    // Losing either membership must also remove the assignment's metadata view.
    state
        .db
        .remove_member(
            tenant.community(),
            admitted,
            &agent.public_key().to_bytes(),
            &owner.public_key().to_bytes(),
        )
        .await
        .unwrap();
    assert!(metadata_channels(
        &state,
        tenant.community(),
        &agent.public_key().to_bytes(),
        &[Filter::new().kind(Kind::Custom(39000))],
        None
    )
    .await
    .unwrap()
    .is_empty());
}

async fn wait_for_advisory_waiter(pool: &sqlx::PgPool) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid \
                 WHERE a.datname=current_database() AND l.locktype='advisory' AND NOT l.granted)",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn rename_waits_before_channel_row(discovery: bool) {
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
        "before-lock",
    )
    .await;
    sqlx::query("UPDATE channels SET ttl_seconds=60 WHERE community_id=$1 AND id=$2")
        .bind(tenant.community().as_uuid())
        .bind(ch)
        .execute(&pool)
        .await
        .unwrap();
    let mut publisher = state
        .db
        .begin_event_write_transaction(tenant.community())
        .await
        .unwrap();
    let mut transition = pool.begin().await.unwrap();
    if discovery {
        let metadata = EventBuilder::new(Kind::Custom(39000), "")
            .tags([
                Tag::parse(["d", &ch.to_string()]).unwrap(),
                Tag::parse(["h", &ch.to_string()]).unwrap(),
                Tag::parse(["name", "before-lock"]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(
                nostr::Timestamp::now().as_secs() + 60,
            ))
            .sign_with_keys(&state.relay_keypair)
            .unwrap();
        assert!(
            state
                .db
                .replace_addressable_event_in_transaction(&mut publisher, &metadata, Some(ch))
                .await
                .unwrap()
                .1
        );
    } else {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("buzz_channel_ttl:{}:{}", tenant.community(), ch))
            .execute(&mut *transition)
            .await
            .unwrap();
    }
    let (rename_state, rename_tenant) = (state.clone(), tenant.clone());
    let rename = tokio::spawn(async move {
        ingest(
            &rename_state,
            &rename_tenant,
            edit(&agent, ch, "after-lock", None),
        )
        .await
    });
    wait_for_advisory_waiter(&pool).await;
    // The waiting rename must not block a publisher's deferred TTL refresh or
    // a TTL transition's channel UPDATE. NOWAIT makes the old inversion observable.
    let unlocked =
        sqlx::query("SELECT id FROM channels WHERE community_id=$1 AND id=$2 FOR UPDATE NOWAIT")
            .bind(tenant.community().as_uuid())
            .bind(ch)
            .fetch_one(&pool)
            .await;
    publisher.commit().await.unwrap();
    transition.commit().await.unwrap();
    let renamed = tokio::time::timeout(std::time::Duration::from_secs(5), rename)
        .await
        .unwrap()
        .unwrap();
    assert!(
        unlocked.is_ok(),
        "rename locked the channel before its discovery/TTL dependency: {unlocked:?}"
    );
    assert!(renamed.unwrap().accepted);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn rename_waits_for_discovery_before_channel_row() {
    rename_waits_before_channel_row(true).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn rename_waits_for_ttl_transition_before_channel_row() {
    rename_waits_before_channel_row(false).await;
}
