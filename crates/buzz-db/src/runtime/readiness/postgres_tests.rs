use super::super::{Db, DbReadinessOutcome};
use sqlx::{Connection, PgConnection, PgPool};
use std::time::Duration;
use tokio::time::{timeout, Instant};

async fn fixture() -> (Db, PgPool, PgConnection) {
    let url = crate::test_support::database_url();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let observer = PgConnection::connect(&url).await.unwrap();
    (Db::from_pool(pool.clone()), pool, observer)
}

async fn backend_pid(pool: &PgPool) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn wait_for_live_query(observer: &mut PgConnection, pid: i32, query: &str) {
    timeout(Duration::from_secs(2), async {
        loop {
            let sleeping: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                 WHERE pid = $1 AND datname = current_database()
                   AND state = 'active' AND query = $2 AND wait_event = 'PgSleep')",
            )
            .bind(pid)
            .bind(query)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
            if sleeping {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("observe the exact server query before cancellation");
}

async fn assert_pool_recovered(db: &Db, pool: &PgPool, abandoned_pid: i32) {
    let started = Instant::now();
    let before = db.pool_stats();
    let outcome = db
        .readiness_check(Instant::now() + Duration::from_secs(1))
        .await;
    let after = db.pool_stats();
    assert_eq!(
        outcome,
        DbReadinessOutcome::Success,
        "an abandoned 30-second query must not retain the sole pool permit; \
         elapsed={:?}, before_size={}, before_idle={}, after_size={}, after_idle={}",
        started.elapsed(),
        before.size,
        before.idle,
        after.size,
        after.idle
    );
    assert_ne!(backend_pid(pool).await, abandoned_pid);
    timeout(Duration::from_secs(1), async {
        loop {
            let stats = db.pool_stats();
            assert!(stats.size <= 1, "respect the configured pool ceiling");
            if stats.idle == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement connection returns to the size-one pool");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cluster_global_task_abort_discards_an_observed_live_readiness_query() {
    const SQL: &str = "SELECT pg_sleep(30) /* readiness_abort_control */";
    let (db, pool, mut observer) = fixture().await;
    let pid = backend_pid(&pool).await;
    let querying_db = db.clone();
    let task = tokio::spawn(async move {
        querying_db
            .readiness_check_sql(Instant::now() + Duration::from_secs(60), SQL)
            .await
    });
    wait_for_live_query(&mut observer, pid, SQL).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_pool_recovered(&db, &pool, pid).await;
    // This proves discarding and replacement, not an out-of-band CancelRequest
    // or instantaneous termination of the server's abandoned read-only query.
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cluster_global_timeout_discards_an_observed_live_readiness_query() {
    const SQL: &str = "SELECT pg_sleep(30) /* readiness_timeout_control */";
    let (db, pool, mut observer) = fixture().await;
    let pid = backend_pid(&pool).await;
    let querying_db = db.clone();
    let task = tokio::spawn(async move {
        querying_db
            .readiness_check_sql(Instant::now() + Duration::from_secs(1), SQL)
            .await
    });
    wait_for_live_query(&mut observer, pid, SQL).await;
    assert_eq!(task.await.unwrap(), DbReadinessOutcome::QueryTimeout);
    assert_pool_recovered(&db, &pool, pid).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn successful_readiness_reuses_the_same_backend() {
    let (db, pool, _observer) = fixture().await;
    let pid = backend_pid(&pool).await;
    for _ in 0..3 {
        assert_eq!(
            db.readiness_check(Instant::now() + Duration::from_secs(1))
                .await,
            DbReadinessOutcome::Success
        );
        assert_eq!(backend_pid(&pool).await, pid);
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn completed_query_error_keeps_normal_backend_reuse() {
    let (db, pool, _observer) = fixture().await;
    let pid = backend_pid(&pool).await;
    assert_eq!(
        db.readiness_check_sql(Instant::now() + Duration::from_secs(1), "SELECT 1 / 0")
            .await,
        DbReadinessOutcome::QueryError
    );
    assert_eq!(backend_pid(&pool).await, pid);
    assert_eq!(
        db.readiness_check(Instant::now() + Duration::from_secs(1))
            .await,
        DbReadinessOutcome::Success
    );
    assert_eq!(backend_pid(&pool).await, pid);
}
