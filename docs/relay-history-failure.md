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
- A built `buzz-relay` process was also exercised over its actual WebSocket
  endpoint with fresh PostgreSQL16/Redis7 fixtures and synthetic NIP-42 keys.
  A signed kind9 event was seeded directly into the owned database (event
  publishing is not part of this proof). An ordinary runtime DB role first
  returned that event plus EOSE; revoking its SELECT on `events` then produced
  exactly generic CLOSED, no EVENT/EOSE for the failed subscription. After
  restoring SELECT, a new REQ on the same authenticated connection returned
  the original event plus EOSE. Owned process and containers were removed
  before success was emitted. This tests a real database permission failure,
  not simulated WebSocket responses; it is not an official-client test.
  Git/media object-store probes were disabled only in this isolated fixture;
  those unrelated features and deployment configuration are not validated.

## Scoped agent review

Main-agent review, not an independent review: history failures now propagate
through the existing owner-fenced retirement path, after releasing the request
permit. Statement-timeout behavior is unchanged; a replacement subscription is
not closed by an old request. The new test binds the production handler and is
falsifiable by restoring the old EOSE branch. No new authority or resource loop
is introduced. No blocking defect found in this bounded change. Minimalism,
correctness and clarity meet the scoped review bar; this does not approve the
larger Atlas receiver or establish lossless late-event recovery.

Run the database test with the repository's isolated PostgreSQL lane:

```sh
scripts/postgres-test-run.sh -p buzz-relay --lib -E 'test(history_database_failure)'
```

The lane requires an explicitly owned test cluster and the documented
`BUZZ_POSTGRES_ADMIN_URL` / PostgreSQL bootstrap settings. Do not point it at a
shared development or production database.

## Remaining release checks

Independent read-only source review10Oct2026 by Codex verifier
review_receive_expiry compared61b016157 to574a4acf2 and found no concrete blocker.
It traced the production error branch, permit/cancellation ordering and
close_if_owner's shared lifecycle lock, including the terminal frame and stale
replacement fence. Minimalism, correctness and clarity each met9/10 for this
bounded patch. The reviewer did not rerun tests; search REQs, official clients
and production activation were outside its review. Fresh main-agent rerun:
format PASS, targeted handler suite65PASS/6Postgres cases ignored in the unit
lane. The separate actual PostgreSQL/socket/mutation evidence above remains
distinct. No source behavior changed after the documented full local CI run.

Full local repository `just ci` completed successfully (session23081, exit0,
10Oct2026) at source adc0e117b8f31b52f52709bc30f4cab0b59b8f8b. Static checks,
Rust unit lanes, desktop JS6784 tests, admin JS139 tests, desktop build/Tauri
checks, Tauri Rust3419 tests (19 existing ignored), and Mobile lanes passed.
Existing opt-in/infrastructure skips are not claimed as executed by this lane;
the added real PostgreSQL regression and real WebSocket proof ran separately
as documented above. This is local CI evidence, not hosted checks or deployment.

On10October2026 Michael explicitly waived his personal Relay test for this
history-failure patch in the Lenny/Buzz task. The agent-run regression and CI
above are not represented as human testing; the checklist-attestation marker
is deliberately not asserted. This waiver does not cover hosted checks,
exact-head merge approval, deployment or official-client acceptance.
Hosted checks and exact-head merge approval remain.
No merge or deployment is implied by this local regression evidence.
