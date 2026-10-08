//! The transport actor, envelope signer and mentions share a durable commit.
use super::*;
use std::time::Duration;

fn envelope(f: &Fixture, signer: &Keys) -> nostr::Event {
    EventBuilder::new(Kind::GiftWrap, Uuid::new_v4().to_string())
        .tags([Tag::public_key(f.owner.public_key())])
        .sign_with_keys(signer)
        .unwrap()
}

async fn assert_persisted(f: &Fixture, event: &nostr::Event, expected: i64) {
    for (table, query) in [
        (
            "events",
            "SELECT count(*) FROM events WHERE community_id = $1 AND id = $2",
        ),
        (
            "event_mentions",
            "SELECT count(*) FROM event_mentions WHERE community_id = $1 AND event_id = $2",
        ),
    ] {
        let count: i64 = sqlx::query_scalar(query)
            .bind(f.community.as_uuid())
            .bind(event.id.as_bytes())
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(count, expected, "{table}");
    }
}

async fn actor_author_matrix() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let db = crate::Db::from_pool(f.pool.clone());
    let ephemeral = Keys::generate();
    for (actor, signer) in [(&f.bot, &ephemeral), (&f.bot, &f.bot), (&f.owner, &f.bot)] {
        let event = envelope(&f, signer);
        let (stored, inserted) = db
            .insert_authenticated_gift_wrap(f.community, &event, &actor.public_key())
            .await
            .unwrap();
        assert!(inserted);
        assert_eq!(stored.event, event);
        assert_eq!(stored.channel_id, None);
        assert_persisted(&f, &event, 1).await;
        assert!(
            !db.insert_authenticated_gift_wrap(f.community, &event, &actor.public_key())
                .await
                .unwrap()
                .1
        );
        assert_persisted(&f, &event, 1).await;
    }
    f.apply(&f.command(true, 1, Uuid::new_v4())).await.unwrap();
    for (actor, signer) in [(&f.bot, &ephemeral), (&f.bot, &f.bot), (&f.owner, &f.bot)] {
        let event = envelope(&f, signer);
        assert_sql_state(
            db.insert_authenticated_gift_wrap(f.community, &event, &actor.public_key())
                .await
                .unwrap_err(),
            "42501",
        );
        assert_persisted(&f, &event, 0).await;
    }
    let legacy = envelope(&f, &ephemeral);
    assert!(
        db.insert_authenticated_gift_wrap(f.community, &legacy, &f.owner.public_key())
            .await
            .unwrap()
            .1
    );
    assert_persisted(&f, &legacy, 1).await;
    assert!(matches!(
        db.insert_authenticated_gift_wrap(f.community, &bot_message(&f), &f.owner.public_key())
            .await,
        Err(DbError::InvalidData(_))
    ));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_actor_author_and_same_principal_matrix() {
    actor_author_matrix().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn migration_schema_gift_wrap_actor_author_matrix() {
    actor_author_matrix().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_keeps_actor_locked_after_insert_until_commit() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let db = crate::Db::from_pool(f.pool.clone());
    let event = envelope(&f, &Keys::generate());
    let mut insertion = db.begin_event_write_transaction().await.unwrap();
    db.insert_authenticated_gift_wrap_in_transaction(
        &mut insertion,
        f.community,
        &event,
        &f.bot.public_key(),
    )
    .await
    .unwrap();
    assert_persisted(&f, &event, 0).await;
    let command = f.command(true, 1, Uuid::new_v4());
    let pool = f.pool.clone();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let revoke = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        started.send(pid).unwrap();
        let result = apply_in_transaction(&mut tx, &command).await.unwrap();
        tx.commit().await.unwrap();
        result
    });
    wait_for_backend_lock(&f.pool, waiting.await.unwrap(), "advisory").await;
    insertion.commit().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), revoke)
        .await
        .unwrap()
        .unwrap());
    assert_persisted(&f, &event, 1).await;
    let next = envelope(&f, &Keys::generate());
    assert_sql_state(
        db.insert_authenticated_gift_wrap(f.community, &next, &f.bot.public_key())
            .await
            .unwrap_err(),
        "42501",
    );
    assert_persisted(&f, &next, 0).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gift_wrap_mention_failure_rolls_back_event_and_allows_retry() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let db = crate::Db::from_pool(f.pool.clone());
    // This database belongs to this one test. Fault the actual mention INSERT,
    // after the event INSERT, not a test-only persistence implementation.
    sqlx::raw_sql("CREATE FUNCTION fail_gift_wrap_mention() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic mention failure' USING ERRCODE = '23514'; END $$;
        CREATE TRIGGER synthetic_mention_failure BEFORE INSERT ON event_mentions FOR EACH ROW EXECUTE FUNCTION fail_gift_wrap_mention();")
        .execute(&f.pool).await.unwrap();
    let event = envelope(&f, &Keys::generate());
    assert_sql_state(
        db.insert_authenticated_gift_wrap(f.community, &event, &f.bot.public_key())
            .await
            .unwrap_err(),
        "23514",
    );
    assert_persisted(&f, &event, 0).await;
    sqlx::raw_sql("DROP TRIGGER synthetic_mention_failure ON event_mentions; DROP FUNCTION fail_gift_wrap_mention();")
        .execute(&f.pool).await.unwrap();
    assert!(
        db.insert_authenticated_gift_wrap(f.community, &event, &f.bot.public_key())
            .await
            .unwrap()
            .1
    );
    assert_persisted(&f, &event, 1).await;
}
