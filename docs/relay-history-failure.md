# History failures must not acknowledge missing events

## Contract

A normal non-search REQ whose historical database read fails must end with
`CLOSED`, not `EOSE`. `EOSE` tells catch-up clients that history is complete;
turning a database error into that success boundary can advance a durable
receiver past events it never received.

The change preserves the existing statement-timeout reason
`error: query timed out`. Other database failures return only
`error: database error`; database diagnostics stay in server logs. Retirement
uses the existing subscription-owner fence, after the session-cancellation
race and effect-permit release. It removes the subscription, fan-out entry
and retained topics without closing a replacement request with the same ID.

No authorization, membership, signing, event storage, migration, HTTP API or
client configuration changes. This is not an arrival cursor and does not by
itself guarantee delivery of arbitrary late/backdated events.

## Regression evidence (2026-10-10)

- `cargo test -p buzz-relay --lib handlers::req:: -- --test-threads=2`:
  65 passed, six PostgreSQL tests intentionally outside the infrastructure-free
  lane. The new database regression was run separately, not counted as waived.
- `history_database_failure_closes_without_eose_and_releases_topics` uses the
  production `handle_req`, an owned freshly bootstrapped PostgreSQL database,
  synthetic identity and an existing history barrier. Authorization and live
  registration complete before its real pool is closed. It then asserts exactly
  one generic CLOSED frame, no EOSE, no remaining subscription/registry entry
  and zero topic references. Passed with the fix.
- Mutation check: restoring only the old error-to-EOSE behavior makes that same
  test fail with actual `["EOSE","personal-history"]` instead of CLOSED.
- `cargo fmt --all -- --check`, PostgreSQL discovery guard and
  `cargo clippy -p buzz-relay --lib --tests -- -D warnings` passed.
- Atlas's real loopback WebSocket regression rejects valid partial events
  followed by CLOSED, even with a queued EOSE afterwards. Its full Bridge suite
  passed477 tests with nine existing opt-in skips. This is client-side evidence,
  not proof of a deployed Relay.

Run the database test with the repository's isolated PostgreSQL lane:

```sh
scripts/postgres-test-run.sh -p buzz-relay --lib -E 'test(history_database_failure)'
```

The lane requires an explicitly owned test cluster and the documented
`BUZZ_POSTGRES_ADMIN_URL` / PostgreSQL bootstrap settings. Do not point it at a
shared development or production database.

## Remaining release checks

Full repository CI, a real Relay WebSocket workflow, human test confirmation
or an explicit applicable waiver, review and exact-head merge approval remain.
No merge or deployment is implied by this local regression evidence.
