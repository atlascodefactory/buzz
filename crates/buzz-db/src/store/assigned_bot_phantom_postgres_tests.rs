//! Real concurrent mutations at the durable INSERT boundary, not query mocks.
use super::*;
use std::time::Duration;

async fn ban(tx: &mut Transaction<'_, Postgres>, f: &Fixture, owner: bool) {
    let target = if owner { &f.owner } else { &f.bot };
    sqlx::query(
        "INSERT INTO community_bans (community_id, pubkey, banned, actor_pubkey) \
         VALUES ($1, $2, true, $3) ON CONFLICT (community_id, pubkey) \
         DO UPDATE SET banned = true, ban_expires_at = NULL",
    )
    .bind(f.community.as_uuid())
    .bind(target.public_key().as_bytes())
    .bind(f.authority.public_key().as_bytes())
    .execute(&mut **tx)
    .await
    .unwrap();
}

async fn raw_tombstone(tx: &mut Transaction<'_, Postgres>, f: &Fixture) {
    sqlx::query(
        "INSERT INTO assigned_bots (community_id, bot_pubkey, assignment_id, \
         authority_pubkey, owner_pubkey, generation, revoked_at) \
         VALUES ($1, $2, $3, $4, $5, 1, clock_timestamp())",
    )
    .bind(f.community.as_uuid())
    .bind(f.bot.public_key().as_bytes())
    .bind(f.assignment)
    .bind(f.authority.public_key().as_bytes())
    .bind(f.owner.public_key().as_bytes())
    .execute(&mut **tx)
    .await
    .unwrap();
}

async fn spawn_insert(f: &Fixture) -> (i32, tokio::task::JoinHandle<Result<bool>>) {
    let (pool, community, channel, event) =
        (f.pool.clone(), f.community, f.channel, bot_message(f));
    let (started, waiting) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        started.send(pid).unwrap();
        let result =
            crate::event::insert_event_in_transaction(&mut tx, community, &event, Some(channel))
                .await;
        match result {
            Ok((_, inserted)) => {
                tx.commit().await.unwrap();
                Ok(inserted)
            }
            Err(error) => {
                tx.rollback().await.unwrap();
                Err(error)
            }
        }
    });
    (waiting.await.unwrap(), handle)
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn absent_assignment_is_locked_through_event_commit() {
    let f = Fixture::new().await;
    let mut event_tx = f.pool.begin().await.unwrap();
    // Unassigned legacy author still succeeds; absence itself must be fenced.
    crate::event::insert_event_in_transaction(
        &mut event_tx,
        f.community,
        &bot_message(&f),
        Some(f.channel),
    )
    .await
    .unwrap();
    let pool = f.pool.clone();
    let observe = f.pool.clone();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        started.send(pid).unwrap();
        raw_tombstone(&mut tx, &f).await;
        tx.commit().await.unwrap();
        f
    });
    wait_for_backend_lock(&observe, waiting.await.unwrap(), "advisory").await;
    event_tx.commit().await.unwrap();
    let f = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .unwrap()
        .unwrap();
    assert_sql_state(
        crate::event::insert_event(&f.pool, f.community, &bot_message(&f), Some(f.channel))
            .await
            .unwrap_err(),
        "42501",
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn new_assignment_is_rechecked_after_commit_or_rollback() {
    for commit in [true, false] {
        let f = Fixture::new().await;
        let mut mutation = f.pool.begin().await.unwrap();
        raw_tombstone(&mut mutation, &f).await;
        let (pid, insert) = spawn_insert(&f).await;
        wait_for_backend_lock(&f.pool, pid, "advisory").await;
        if commit {
            mutation.commit().await.unwrap();
        } else {
            mutation.rollback().await.unwrap();
        }
        let result = tokio::time::timeout(Duration::from_secs(5), insert)
            .await
            .unwrap()
            .unwrap();
        if commit {
            assert_sql_state(result.unwrap_err(), "42501");
        } else {
            assert!(result.unwrap());
        }
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn absent_owner_and_bot_bans_are_locked_through_event_commit() {
    for owner in [true, false] {
        let f = Fixture::new().await;
        f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
        let mut event_tx = f.pool.begin().await.unwrap();
        crate::event::insert_event_in_transaction(
            &mut event_tx,
            f.community,
            &bot_message(&f),
            Some(f.channel),
        )
        .await
        .unwrap();
        let pool = f.pool.clone();
        let observe = f.pool.clone();
        let (started, waiting) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            started.send(pid).unwrap();
            ban(&mut tx, &f, owner).await;
            tx.commit().await.unwrap();
            f
        });
        wait_for_backend_lock(&observe, waiting.await.unwrap(), "advisory").await;
        event_tx.commit().await.unwrap();
        let f = tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap();
        assert_sql_state(
            crate::event::insert_event(&f.pool, f.community, &bot_message(&f), Some(f.channel))
                .await
                .unwrap_err(),
            "42501",
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn bans_are_rechecked_after_insert_update_commit_and_rollback() {
    for owner in [true, false] {
        for existing in [true, false] {
            for commit in [true, false] {
                let f = Fixture::new().await;
                f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
                let key = if owner { &f.owner } else { &f.bot };
                if existing {
                    // Exercise the ordinary production UPSERT and unban path.
                    crate::moderation::ban_member(
                        &f.pool,
                        f.community,
                        key.public_key().as_bytes(),
                        f.authority.public_key().as_bytes(),
                        None,
                        None,
                    )
                    .await
                    .unwrap();
                    crate::moderation::unban_member(
                        &f.pool,
                        f.community,
                        key.public_key().as_bytes(),
                        f.authority.public_key().as_bytes(),
                    )
                    .await
                    .unwrap();
                }
                let mut mutation = f.pool.begin().await.unwrap();
                if existing {
                    // A plain UPDATE must be fenced independently of INSERT's
                    // trigger; an UPSERT alone would not detect that omission.
                    sqlx::query("UPDATE community_bans SET banned = true WHERE community_id = $1 AND pubkey = $2")
                        .bind(f.community.as_uuid()).bind(key.public_key().as_bytes())
                        .execute(&mut *mutation).await.unwrap();
                } else {
                    ban(&mut mutation, &f, owner).await;
                }
                let (pid, insert) = spawn_insert(&f).await;
                wait_for_backend_lock(&f.pool, pid, "advisory").await;
                if commit {
                    mutation.commit().await.unwrap();
                } else {
                    mutation.rollback().await.unwrap();
                }
                let result = tokio::time::timeout(Duration::from_secs(5), insert)
                    .await
                    .unwrap()
                    .unwrap();
                if commit {
                    assert_sql_state(result.unwrap_err(), "42501");
                } else {
                    assert!(result.unwrap());
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn same_principal_in_foreign_community_does_not_block_event() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let other = Fixture::new().await;
    let mut mutation = f.pool.begin().await.unwrap();
    sqlx::query("INSERT INTO community_bans (community_id, pubkey, banned, actor_pubkey) VALUES ($1, $2, true, $3)")
        .bind(other.community.as_uuid()).bind(f.bot.public_key().as_bytes())
        .bind(f.authority.public_key().as_bytes()).execute(&mut *mutation).await.unwrap();
    sqlx::query("INSERT INTO assigned_bots (community_id, bot_pubkey, assignment_id, authority_pubkey, owner_pubkey, generation, revoked_at) VALUES ($1, $2, $3, $4, $5, 1, clock_timestamp())")
        .bind(other.community.as_uuid()).bind(f.bot.public_key().as_bytes()).bind(f.assignment)
        .bind(f.authority.public_key().as_bytes()).bind(f.owner.public_key().as_bytes())
        .execute(&mut *mutation).await.unwrap();
    let (_, insert) = spawn_insert(&f).await;
    assert!(tokio::time::timeout(Duration::from_secs(5), insert)
        .await
        .unwrap()
        .unwrap()
        .unwrap());
    mutation.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn migration_schema_predicate_fences_cover_assignment_and_ban_absence() {
    let f = Fixture::new().await;
    let mut assignment = f.pool.begin().await.unwrap();
    raw_tombstone(&mut assignment, &f).await;
    let (pid, insert) = spawn_insert(&f).await;
    wait_for_backend_lock(&f.pool, pid, "advisory").await;
    assignment.rollback().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), insert)
        .await
        .unwrap()
        .unwrap()
        .unwrap());
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let mut restriction = f.pool.begin().await.unwrap();
    ban(&mut restriction, &f, true).await;
    let (pid, insert) = spawn_insert(&f).await;
    wait_for_backend_lock(&f.pool, pid, "advisory").await;
    restriction.commit().await.unwrap();
    assert_sql_state(
        tokio::time::timeout(Duration::from_secs(5), insert)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err(),
        "42501",
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ban_moves_lock_old_and_new_principal_independently() {
    for from_bot in [true, false] {
        let f = Fixture::new().await;
        f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
        let (old, new) = if from_bot {
            (&f.bot, &f.authority)
        } else {
            (&f.authority, &f.owner)
        };
        crate::moderation::ban_member(
            &f.pool,
            f.community,
            old.public_key().as_bytes(),
            f.authority.public_key().as_bytes(),
            None,
            None,
        )
        .await
        .unwrap();
        crate::moderation::unban_member(
            &f.pool,
            f.community,
            old.public_key().as_bytes(),
            f.authority.public_key().as_bytes(),
        )
        .await
        .unwrap();
        let mut mutation = f.pool.begin().await.unwrap();
        sqlx::query("UPDATE community_bans SET pubkey = $3, banned = true WHERE community_id = $1 AND pubkey = $2")
            .bind(f.community.as_uuid()).bind(old.public_key().as_bytes()).bind(new.public_key().as_bytes())
            .execute(&mut *mutation).await.unwrap();
        let (pid, insert) = spawn_insert(&f).await;
        wait_for_backend_lock(&f.pool, pid, "advisory").await;
        mutation.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), insert)
            .await
            .unwrap()
            .unwrap();
        if from_bot {
            assert!(result.unwrap());
        } else {
            assert_sql_state(result.unwrap_err(), "42501");
        }
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ban_delete_retains_predicate_lock_until_commit() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    crate::moderation::ban_member(
        &f.pool,
        f.community,
        f.bot.public_key().as_bytes(),
        f.authority.public_key().as_bytes(),
        None,
        None,
    )
    .await
    .unwrap();
    let mut mutation = f.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM community_bans WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.bot.public_key().as_bytes())
        .execute(&mut *mutation)
        .await
        .unwrap();
    let (pid, insert) = spawn_insert(&f).await;
    wait_for_backend_lock(&f.pool, pid, "advisory").await;
    mutation.commit().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), insert)
        .await
        .unwrap()
        .unwrap()
        .unwrap());
}
