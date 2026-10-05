use super::*;
use buzz_core::assigned_bot::{AssignedBotCommand, AssignedBotOperation};
use buzz_core::kind;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use uuid::Uuid;

#[path = "assigned_bot_phantom_postgres_tests.rs"]
mod phantom_postgres_tests;

#[path = "assigned_bot_gift_wrap_postgres_tests.rs"]
mod gift_wrap_postgres_tests;

struct Fixture {
    pool: PgPool,
    community: CommunityId,
    authority: Keys,
    owner: Keys,
    bot: Keys,
    assignment: Uuid,
    channel: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let pool = PgPool::connect(&crate::test_support::database_url())
            .await
            .unwrap();
        if std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref() != Ok("desired") {
            crate::migration::run_migrations(&pool).await.unwrap();
        }
        let community = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community.as_uuid())
            .bind(format!("assigned-{}.invalid", community))
            .execute(&pool)
            .await
            .unwrap();
        let (authority, owner, bot) = (Keys::generate(), Keys::generate(), Keys::generate());
        for key in [&owner, &bot] {
            crate::user::ensure_user(&pool, community, &key.public_key().to_bytes())
                .await
                .unwrap();
        }
        crate::relay_members::add_relay_member(
            &pool,
            community,
            &owner.public_key().to_hex(),
            "member",
            None,
        )
        .await
        .unwrap();
        // Atlas-assigned bot, deliberately without a forged NIP-OA owner.
        crate::user::set_channel_add_policy(
            &pool,
            community,
            &bot.public_key().to_bytes(),
            "owner_only",
        )
        .await
        .unwrap();
        let channel = crate::channel::create_channel(
            &pool,
            community,
            "assigned-test",
            crate::channel::ChannelType::Stream,
            crate::channel::ChannelVisibility::Private,
            None,
            &owner.public_key().to_bytes(),
            None,
        )
        .await
        .unwrap()
        .id;
        Self {
            pool,
            community,
            authority,
            owner,
            bot,
            assignment: Uuid::new_v4(),
            channel,
        }
    }

    fn command(&self, revoke: bool, generation: i64, nonce: Uuid) -> AssignedBotCommand {
        self.command_at(
            revoke,
            generation,
            nonce,
            &self.owner,
            Timestamp::now().as_secs(),
            60,
        )
    }

    fn command_at(
        &self,
        revoke: bool,
        generation: i64,
        nonce: Uuid,
        owner: &Keys,
        now: u64,
        ttl: u64,
    ) -> AssignedBotCommand {
        let mut tags = vec![
            vec!["community".into(), self.community.to_string()],
            vec!["owner".into(), owner.public_key().to_hex()],
            vec!["p".into(), self.bot.public_key().to_hex()],
            vec!["assignment".into(), self.assignment.to_string()],
            vec!["assignment-version".into(), generation.to_string()],
            vec!["nonce".into(), nonce.to_string()],
            vec!["expiration".into(), (now + ttl).to_string()],
        ];
        if !revoke {
            tags.extend([
                vec!["h".into(), self.channel.to_string()],
                vec!["role".into(), "bot".into()],
                vec!["expected-role".into(), "absent".into()],
            ]);
        }
        let event = EventBuilder::new(
            Kind::Custom(if revoke {
                kind::KIND_ASSIGNED_BOT_REVOCATION as u16
            } else {
                kind::KIND_ASSIGNED_BOT_ADMISSION as u16
            }),
            "",
        )
        .custom_created_at(Timestamp::from(now))
        .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .sign_with_keys(&self.authority)
        .unwrap();
        AssignedBotCommand::verify(
            &event,
            self.community,
            &self.authority.public_key(),
            Some(&self.authority.public_key()),
            now,
        )
        .unwrap()
    }

    async fn apply(&self, command: &AssignedBotCommand) -> Result<bool> {
        apply(&self.pool, command).await
    }
    async fn role(&self) -> Option<String> {
        crate::channel::get_member_role(
            &self.pool,
            self.community,
            self.channel,
            &self.bot.public_key().to_bytes(),
        )
        .await
        .unwrap()
    }
    async fn count(&self, table: &str) -> i64 {
        let query = match table {
            "assigned_bots" => "SELECT count(*) FROM assigned_bots WHERE community_id = $1",
            "assigned_bot_commands" => {
                "SELECT count(*) FROM assigned_bot_commands WHERE community_id = $1"
            }
            _ => panic!("unknown fixture table"),
        };
        sqlx::query_scalar(query)
            .bind(self.community.as_uuid())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

async fn apply(pool: &PgPool, command: &AssignedBotCommand) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let outcome = apply_in_transaction(&mut tx, command).await;
    match outcome {
        Ok(inserted) => {
            tx.commit().await?;
            Ok(inserted)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

fn bot_message(f: &Fixture) -> nostr::Event {
    EventBuilder::new(
        Kind::Custom(kind::KIND_STREAM_MESSAGE as u16),
        Uuid::new_v4().to_string(),
    )
    .tags([Tag::parse(["h".to_string(), f.channel.to_string()]).unwrap()])
    .sign_with_keys(&f.bot)
    .unwrap()
}

fn assert_sql_state(error: DbError, expected: &str) {
    match error {
        DbError::Sqlx(sqlx::Error::Database(error)) => {
            assert_eq!(error.code().as_deref(), Some(expected));
        }
        other => panic!("expected SQLSTATE {expected}, got {other}"),
    }
}

async fn wait_for_backend_lock(pool: &PgPool, pid: i32, lock_type: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND locktype = $2 AND NOT granted)"
            ).bind(pid).bind(lock_type).fetch_one(pool).await.unwrap();
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn durable_insert_rechecks_assignment_after_earlier_allow() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    assert_eq!(
        access_status(
            &f.pool,
            f.community,
            f.bot.public_key().as_bytes(),
            Some(f.channel)
        )
        .await
        .unwrap(),
        Some(true)
    );
    f.apply(&f.command(true, 1, Uuid::new_v4())).await.unwrap();
    let event = bot_message(&f);
    let error = crate::event::insert_event(&f.pool, f.community, &event, Some(f.channel))
        .await
        .unwrap_err();
    assert_sql_state(error, "42501");
    assert!(
        crate::event::get_event_by_id(&f.pool, f.community, event.id.as_bytes())
            .await
            .unwrap()
            .is_none()
    );
    // The restriction does not become a blanket channel write ban for humans.
    let legacy = EventBuilder::new(
        Kind::Custom(kind::KIND_STREAM_MESSAGE as u16),
        "legacy human",
    )
    .tags([Tag::parse(["h".to_string(), f.channel.to_string()]).unwrap()])
    .sign_with_keys(&f.owner)
    .unwrap();
    assert!(
        crate::event::insert_event(&f.pool, f.community, &legacy, Some(f.channel))
            .await
            .unwrap()
            .1
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn durable_insert_holds_assignment_until_its_commit() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let mut insert = f.pool.begin().await.unwrap();
    let event = bot_message(&f);
    assert!(
        crate::event::insert_event_in_transaction(
            &mut insert,
            f.community,
            &event,
            Some(f.channel)
        )
        .await
        .unwrap()
        .1
    );
    let mut withdrawal = f.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '100ms'")
        .execute(&mut *withdrawal)
        .await
        .unwrap();
    let revoke = f.command(true, 1, Uuid::new_v4());
    let error = apply_in_transaction(&mut withdrawal, &revoke)
        .await
        .unwrap_err();
    assert_sql_state(error, "55P03");
    withdrawal.rollback().await.unwrap();
    insert.commit().await.unwrap();
    assert!(f.apply(&revoke).await.unwrap());
    assert!(
        crate::event::get_event_by_id(&f.pool, f.community, event.id.as_bytes())
            .await
            .unwrap()
            .is_some()
    );
    assert_sql_state(
        crate::event::insert_event(&f.pool, f.community, &bot_message(&f), Some(f.channel))
            .await
            .unwrap_err(),
        "42501",
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn durable_insert_holds_current_owner_membership_until_commit() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let mut insert = f.pool.begin().await.unwrap();
    assert!(
        crate::event::insert_event_in_transaction(
            &mut insert,
            f.community,
            &bot_message(&f),
            Some(f.channel)
        )
        .await
        .unwrap()
        .1
    );
    let mut removal = f.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '100ms'")
        .execute(&mut *removal)
        .await
        .unwrap();
    let error = sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(&mut *removal)
        .await
        .unwrap_err();
    assert_sql_state(error.into(), "55P03");
    removal.rollback().await.unwrap();
    insert.commit().await.unwrap();
    sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(&f.pool)
        .await
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
async fn durable_insert_after_waiting_for_owner_removal_uses_fresh_snapshot() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let mut removal = f.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(&mut *removal)
        .await
        .unwrap();
    let pool = f.pool.clone();
    let (community, channel, event) = (f.community, f.channel, bot_message(&f));
    let event_id = event.id.to_bytes();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let insert = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        started.send(pid).unwrap();
        let result =
            crate::event::insert_event_in_transaction(&mut tx, community, &event, Some(channel))
                .await;
        tx.rollback().await.unwrap();
        result
    });
    wait_for_backend_lock(&f.pool, waiting.await.unwrap(), "transactionid").await;
    removal.commit().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), insert)
        .await
        .unwrap()
        .unwrap();
    assert_sql_state(result.unwrap_err(), "42501");
    assert!(
        crate::event::get_event_by_id(&f.pool, f.community, &event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn durable_ephemeral_inserts_do_not_share_to_update_deadlock() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    crate::channel::update_channel(
        &f.pool,
        f.community,
        f.channel,
        crate::channel::ChannelUpdate {
            ttl_seconds: Some(Some(3600)),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let before: DateTime<Utc> =
        sqlx::query_scalar("SELECT ttl_deadline FROM channels WHERE community_id = $1 AND id = $2")
            .bind(f.community.as_uuid())
            .bind(f.channel)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let mut first = f.pool.begin().await.unwrap();
    crate::event::insert_event_in_transaction(
        &mut first,
        f.community,
        &bot_message(&f),
        Some(f.channel),
    )
    .await
    .unwrap();
    let (pool, community, channel, event) =
        (f.pool.clone(), f.community, f.channel, bot_message(&f));
    let (started, waiting) = tokio::sync::oneshot::channel();
    let (inserted, insertion_observed) = tokio::sync::oneshot::channel();
    let (release_commit, may_commit) = tokio::sync::oneshot::channel();
    let second = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        started.send(pid).unwrap();
        let result =
            crate::event::insert_event_in_transaction(&mut tx, community, &event, Some(channel))
                .await
                .unwrap();
        inserted.send(()).unwrap();
        may_commit.await.unwrap();
        tx.commit().await.unwrap();
        result
    });
    wait_for_backend_lock(&f.pool, waiting.await.unwrap(), "transactionid").await;
    first.commit().await.unwrap();
    let after_first: DateTime<Utc> =
        sqlx::query_scalar("SELECT ttl_deadline FROM channels WHERE community_id = $1 AND id = $2")
            .bind(f.community.as_uuid())
            .bind(f.channel)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(after_first > before, "first commit must refresh the TTL");
    tokio::time::timeout(std::time::Duration::from_secs(5), insertion_observed)
        .await
        .unwrap()
        .unwrap();
    release_commit.send(()).unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap()
            .1
    );
    let after: DateTime<Utc> =
        sqlx::query_scalar("SELECT ttl_deadline FROM channels WHERE community_id = $1 AND id = $2")
            .bind(f.community.as_uuid())
            .bind(f.channel)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(
        after > after_first,
        "second commit must also refresh the TTL"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn durable_insert_takes_ttl_lock_before_channel_row() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    // Pause a real TTL transition after its production advisory-lock protocol,
    // before the UPDATE, so the inverse lock order is falsifiable.
    let mut transition = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("buzz_channel_ttl:{}:{}", f.community, f.channel))
        .execute(&mut *transition)
        .await
        .unwrap();
    let (pool, community, channel, event) =
        (f.pool.clone(), f.community, f.channel, bot_message(&f));
    let (started, waiting) = tokio::sync::oneshot::channel();
    let insert = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        started.send(pid).unwrap();
        let result =
            crate::event::insert_event_in_transaction(&mut tx, community, &event, Some(channel))
                .await;
        tx.commit().await.unwrap();
        result
    });
    wait_for_backend_lock(&f.pool, waiting.await.unwrap(), "advisory").await;
    sqlx::query("SET LOCAL lock_timeout = '100ms'")
        .execute(&mut *transition)
        .await
        .unwrap();
    assert_eq!(sqlx::query(
        "UPDATE channels SET ttl_seconds = 3600, ttl_deadline = clock_timestamp() + interval '1 hour' WHERE community_id = $1 AND id = $2"
    ).bind(f.community.as_uuid()).bind(f.channel).execute(&mut *transition).await.unwrap()
        .rows_affected(), 1);
    transition.commit().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), insert)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .1
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn admission_uses_current_owner_without_minting_nip_oa() {
    let f = Fixture::new().await;
    assert!(f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap());
    assert_eq!(f.role().await.as_deref(), Some("bot"));
    let (policy, owner) =
        crate::user::get_agent_channel_policy(&f.pool, f.community, &f.bot.public_key().to_bytes())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(policy, "owner_only");
    assert!(owner.is_none());
    assert_eq!(f.count("assigned_bot_commands").await, 1);
    assert!(
        !is_revoked(&f.pool, f.community, &f.bot.public_key().to_bytes())
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn removed_owner_rolls_back_assignment_receipt_and_membership() {
    let f = Fixture::new().await;
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() WHERE community_id = $1 AND channel_id = $2",
    )
    .bind(f.community.as_uuid())
    .bind(f.channel)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(f.apply(&f.command(false, 1, Uuid::new_v4())).await.is_err());
    assert!(f.role().await.is_none());
    assert_eq!(f.count("assigned_bots").await, 0);
    assert_eq!(f.count("assigned_bot_commands").await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn replay_after_bot_removal_does_not_resurrect_membership() {
    let f = Fixture::new().await;
    let command = f.command(false, 1, Uuid::new_v4());
    assert!(f.apply(&command).await.unwrap());
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() WHERE community_id = $1 AND pubkey = $2",
    )
    .bind(f.community.as_uuid())
    .bind(f.bot.public_key().to_bytes().as_slice())
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(!f.apply(&command).await.unwrap());
    assert!(f.role().await.is_none());
    assert_eq!(f.count("assigned_bot_commands").await, 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn tombstone_before_first_admission_and_late_replay_are_terminal() {
    let f = Fixture::new().await;
    let admission = f.command(false, 1, Uuid::new_v4());
    let revoke = f.command(true, 1, Uuid::new_v4());
    assert!(f.apply(&revoke).await.unwrap());
    assert!(!f.apply(&revoke).await.unwrap());
    assert!(f.apply(&admission).await.is_err());
    assert!(f.role().await.is_none());
    assert!(
        is_revoked(&f.pool, f.community, &f.bot.public_key().to_bytes())
            .await
            .unwrap()
    );
    assert_eq!(f.count("assigned_bot_commands").await, 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn generation_advance_requires_withdrawal_and_rejects_old_commands() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    assert!(f.apply(&f.command(false, 2, Uuid::new_v4())).await.is_err());
    f.apply(&f.command(true, 1, Uuid::new_v4())).await.unwrap();
    // Physical membership is not proof of an active lifecycle. Remove it before
    // this absent-role CAS; existing-role bot renewals are a separate contract.
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() WHERE community_id = $1 AND pubkey = $2",
    )
    .bind(f.community.as_uuid())
    .bind(f.bot.public_key().to_bytes().as_slice())
    .execute(&f.pool)
    .await
    .unwrap();
    f.apply(&f.command(false, 2, Uuid::new_v4())).await.unwrap();
    assert!(
        !is_revoked(&f.pool, f.community, &f.bot.public_key().to_bytes())
            .await
            .unwrap()
    );
    assert!(f.apply(&f.command(true, 1, Uuid::new_v4())).await.is_err());
    assert!(f.apply(&f.command(false, 1, Uuid::new_v4())).await.is_err());
    assert_eq!(f.role().await.as_deref(), Some("bot"));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn nonce_reuse_and_owner_rebinding_fail_without_new_receipts() {
    let f = Fixture::new().await;
    let nonce = Uuid::new_v4();
    f.apply(&f.command(false, 1, nonce)).await.unwrap();
    assert!(f.apply(&f.command(true, 1, nonce)).await.is_err());
    let foreign = Keys::generate();
    let command = f.command_at(
        true,
        1,
        Uuid::new_v4(),
        &foreign,
        Timestamp::now().as_secs(),
        60,
    );
    assert!(f.apply(&command).await.is_err());
    assert_eq!(f.count("assigned_bot_commands").await, 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn bootstrap_does_not_reactivate_an_existing_bot_identity() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE users SET deactivated_at = NOW() WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.bot.public_key().as_bytes())
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(f.apply(&f.command(false, 1, Uuid::new_v4())).await.is_err());
    let remains_inactive: bool = sqlx::query_scalar(
        "SELECT deactivated_at IS NOT NULL FROM users WHERE community_id = $1 AND pubkey = $2",
    )
    .bind(f.community.as_uuid())
    .bind(f.bot.public_key().as_bytes())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(remains_inactive);
    assert!(f.role().await.is_none());
    assert_eq!(f.count("assigned_bots").await, 0);
    assert_eq!(f.count("assigned_bot_commands").await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn admission_holds_owner_relay_membership_until_commit() {
    let f = Fixture::new().await;
    let mut admission = f.pool.begin().await.unwrap();
    assert!(
        apply_in_transaction(&mut admission, &f.command(false, 1, Uuid::new_v4()))
            .await
            .unwrap()
    );
    let mut removal = f.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '100ms'")
        .execute(&mut *removal)
        .await
        .unwrap();
    let error = sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(&mut *removal)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    removal.rollback().await.unwrap();
    admission.commit().await.unwrap();
    assert_eq!(f.role().await.as_deref(), Some("bot"));
    sqlx::query("DELETE FROM relay_members WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(f.owner.public_key().to_hex())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        access_status(
            &f.pool,
            f.community,
            f.bot.public_key().as_bytes(),
            Some(f.channel)
        )
        .await
        .unwrap(),
        Some(false)
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn nobody_and_existing_privileged_roles_never_get_overwritten() {
    let f = Fixture::new().await;
    crate::user::set_channel_add_policy(
        &f.pool,
        f.community,
        &f.bot.public_key().to_bytes(),
        "nobody",
    )
    .await
    .unwrap();
    assert!(f.apply(&f.command(false, 1, Uuid::new_v4())).await.is_err());
    crate::user::set_channel_add_policy(
        &f.pool,
        f.community,
        &f.bot.public_key().to_bytes(),
        "owner_only",
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO channel_members (community_id, channel_id, pubkey, role) VALUES ($1, $2, $3, 'admin')")
        .bind(f.community.as_uuid()).bind(f.channel).bind(f.bot.public_key().to_bytes().as_slice())
        .execute(&f.pool).await.unwrap();
    assert!(f.apply(&f.command(false, 1, Uuid::new_v4())).await.is_err());
    assert_eq!(f.role().await.as_deref(), Some("admin"));
    assert_eq!(f.count("assigned_bots").await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn membership_removed_while_waiting_is_checked_under_writer_lock() {
    let f = Fixture::new().await;
    let mut holder = f.pool.begin().await.unwrap();
    crate::channel_members::acquire_channel_membership_lock_in_transaction(
        &mut holder,
        f.community,
        f.channel,
    )
    .await
    .unwrap();
    let pool = f.pool.clone();
    let command = f.command(false, 1, Uuid::new_v4());
    let task = tokio::spawn(async move { apply(&pool, &command).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!task.is_finished());
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() WHERE community_id = $1 AND channel_id = $2",
    )
    .bind(f.community.as_uuid())
    .bind(f.channel)
    .execute(&mut *holder)
    .await
    .unwrap();
    holder.commit().await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(f.role().await.is_none());
    assert_eq!(f.count("assigned_bots").await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn expired_command_cannot_first_register_or_resurrect() {
    let f = Fixture::new().await;
    let command = f.command_at(
        false,
        1,
        Uuid::new_v4(),
        &f.owner,
        Timestamp::now().as_secs(),
        1,
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(f.apply(&command).await.is_err());
    assert_eq!(f.count("assigned_bots").await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn migration_schema_assignment_and_tombstone_match_desired_contract() {
    let f = Fixture::new().await;
    let command = f.command(true, 7, Uuid::new_v4());
    assert_eq!(command.operation(), AssignedBotOperation::Revoke);
    assert!(f.apply(&command).await.unwrap());
    assert!(f.apply(&f.command(false, 7, Uuid::new_v4())).await.is_err());
    assert!(crate::deletion::EXPECTED_SCOPED_TABLES.contains(&"assigned_bots"));
    assert!(crate::deletion::EXPECTED_SCOPED_TABLES.contains(&"assigned_bot_commands"));
    let db = crate::Db::from_pool(f.pool.clone());
    db.validate_deletion_serving_catalog().await.unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('buzz.deletion_executor_community', $1, true), set_config('buzz.deletion_fence_generation', '1', true)")
        .bind(f.community.to_string()).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE communities SET deletion_state = 'fenced', deletion_fence_generation = 1 WHERE id = $1")
        .bind(f.community.as_uuid()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let mut blocked = f.pool.begin().await.unwrap();
    assert!(db
        .deletion_store()
        .guard_transaction(&mut blocked, f.community)
        .await
        .is_err());
    blocked.rollback().await.unwrap();
    let error =
        sqlx::query("UPDATE assigned_bots SET generation = generation + 1 WHERE community_id = $1")
            .bind(f.community.as_uuid())
            .execute(&f.pool)
            .await
            .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
    let error =
        sqlx::query("UPDATE assigned_bot_commands SET event_id = event_id WHERE community_id = $1")
            .bind(f.community.as_uuid())
            .execute(&f.pool)
            .await
            .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn higher_generation_cannot_rebind_owner_and_reactivate_old_private_rooms() {
    let mut f = Fixture::new().await;
    let old_channel = f.channel;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    f.apply(&f.command(true, 1, Uuid::new_v4())).await.unwrap();
    let foreign = Keys::generate();
    crate::user::ensure_user(&f.pool, f.community, &foreign.public_key().to_bytes())
        .await
        .unwrap();
    f.channel = crate::channel::create_channel(
        &f.pool,
        f.community,
        "foreign-private",
        crate::channel::ChannelType::Stream,
        crate::channel::ChannelVisibility::Private,
        None,
        &foreign.public_key().to_bytes(),
        None,
    )
    .await
    .unwrap()
    .id;
    for revoke in [false, true] {
        let command = f.command_at(
            revoke,
            2,
            Uuid::new_v4(),
            &foreign,
            Timestamp::now().as_secs(),
            60,
        );
        let error = f.apply(&command).await.unwrap_err();
        assert!(error.to_string().contains("assignment coordinates"));
    }
    assert!(
        is_revoked(&f.pool, f.community, &f.bot.public_key().to_bytes())
            .await
            .unwrap()
    );
    assert!(f.role().await.is_none());
    assert_eq!(
        crate::channel::get_member_role(
            &f.pool,
            f.community,
            old_channel,
            &f.bot.public_key().to_bytes()
        )
        .await
        .unwrap()
        .as_deref(),
        None
    );
    // The denied authorization must not rely on deleting the stale physical row.
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM channel_members WHERE community_id = $1 \
         AND channel_id = $2 AND pubkey = $3 AND removed_at IS NULL)",
    )
    .bind(f.community.as_uuid())
    .bind(old_channel)
    .bind(f.bot.public_key().as_bytes())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(retained);
    assert_eq!(f.count("assigned_bot_commands").await, 2);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_revocation_overrides_stale_membership_and_preserves_legacy() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let bot = f.bot.public_key().to_bytes();
    let owner = f.owner.public_key().to_bytes();
    assert_eq!(
        access_status(&f.pool, f.community, &bot, Some(f.channel))
            .await
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        access_status(&f.pool, f.community, &owner, Some(f.channel))
            .await
            .unwrap(),
        None
    );
    f.apply(&f.command(true, 1, Uuid::new_v4())).await.unwrap();
    assert_eq!(
        access_status(&f.pool, f.community, &bot, None)
            .await
            .unwrap(),
        Some(false)
    );
    assert!(
        !crate::channel::is_member(&f.pool, f.community, f.channel, &bot)
            .await
            .unwrap()
    );
    assert!(
        crate::channel::get_member_role(&f.pool, f.community, f.channel, &bot)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        crate::channel::get_accessible_channel_ids(&f.pool, f.community, &bot)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        filter_recipients(
            &f.pool,
            f.community,
            &[bot.to_vec(), owner.to_vec()],
            None,
            false
        )
        .await
        .unwrap(),
        vec![owner.to_vec()]
    );
    assert!(
        crate::channel::is_member(&f.pool, f.community, f.channel, &owner)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_open_rooms_require_current_owner_and_bot_memberships() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let bot = f.bot.public_key().to_bytes();
    let open = crate::channel::create_channel(
        &f.pool,
        f.community,
        "open-not-admitted",
        crate::channel::ChannelType::Stream,
        crate::channel::ChannelVisibility::Open,
        None,
        f.owner.public_key().as_bytes(),
        None,
    )
    .await
    .unwrap()
    .id;
    assert_eq!(
        access_status(&f.pool, f.community, &bot, Some(open))
            .await
            .unwrap(),
        Some(false)
    );
    assert!(
        !crate::channel::get_accessible_channel_ids(&f.pool, f.community, &bot)
            .await
            .unwrap()
            .contains(&open)
    );
    let other = Keys::generate();
    crate::user::ensure_user(&f.pool, f.community, other.public_key().as_bytes())
        .await
        .unwrap();
    crate::channel::add_member(
        &f.pool,
        f.community,
        f.channel,
        other.public_key().as_bytes(),
        crate::channel::MemberRole::Owner,
        Some(f.owner.public_key().as_bytes()),
    )
    .await
    .unwrap();
    crate::channel::remove_member(
        &f.pool,
        f.community,
        f.channel,
        f.owner.public_key().as_bytes(),
        other.public_key().as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(
        access_status(&f.pool, f.community, &bot, None)
            .await
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        access_status(&f.pool, f.community, &bot, Some(f.channel))
            .await
            .unwrap(),
        Some(false)
    );
    assert!(
        filter_recipients(&f.pool, f.community, &[bot.to_vec()], Some(f.channel), true)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn assigned_access_owner_deactivation_ban_and_timeout_are_current() {
    let f = Fixture::new().await;
    f.apply(&f.command(false, 1, Uuid::new_v4())).await.unwrap();
    let bot = f.bot.public_key().to_bytes();
    let owner = f.owner.public_key().to_bytes();
    crate::moderation::timeout_member(
        &f.pool,
        f.community,
        &owner,
        f.authority.public_key().as_bytes(),
        Utc::now() + chrono::Duration::minutes(1),
        None,
    )
    .await
    .unwrap();
    assert!(
        crate::moderation::restriction_state(&f.pool, f.community, &bot)
            .await
            .unwrap()
            .muted_until
            .is_some()
    );
    // Timeout restricts writes, not read access. A ban restricts both.
    assert_eq!(
        access_status(&f.pool, f.community, &bot, None)
            .await
            .unwrap(),
        Some(true)
    );
    crate::moderation::ban_member(
        &f.pool,
        f.community,
        &owner,
        f.authority.public_key().as_bytes(),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        access_status(&f.pool, f.community, &bot, None)
            .await
            .unwrap(),
        Some(false)
    );
    crate::moderation::unban_member(
        &f.pool,
        f.community,
        &owner,
        f.authority.public_key().as_bytes(),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE users SET deactivated_at = NOW() WHERE community_id = $1 AND pubkey = $2")
        .bind(f.community.as_uuid())
        .bind(owner.as_slice())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        access_status(&f.pool, f.community, &bot, None)
            .await
            .unwrap(),
        Some(false)
    );
}
