use sqlx::pool::PoolConnection;
use sqlx::postgres::PgQueryResult;
use sqlx::Postgres;

struct ReadinessQuery {
    connection: PoolConnection<Postgres>,
    completed: bool,
}

impl Drop for ReadinessQuery {
    fn drop(&mut self) {
        if !self.completed {
            // Normal pool return pings/drains a pending query. On cancellation
            // discard it using SQLx's bounded close path instead.
            self.connection.close_on_drop();
        }
    }
}

pub(super) async fn execute(
    connection: PoolConnection<Postgres>,
    deadline: tokio::time::Instant,
    sql: &'static str,
) -> Result<sqlx::Result<PgQueryResult>, tokio::time::error::Elapsed> {
    let mut query = ReadinessQuery {
        connection,
        completed: false,
    };
    let result =
        tokio::time::timeout_at(deadline, sqlx::query(sql).execute(&mut *query.connection)).await;
    // Both success and a completed SQL error keep normal pool reuse. A timeout
    // or a dropped enclosing future leaves the guard armed.
    query.completed = result.is_ok();
    result
}

#[cfg(test)]
mod postgres_tests;
