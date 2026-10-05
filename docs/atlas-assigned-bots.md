# Atlas-attested assigned bots (prepared integration)

This is a Relay-side foundation, not a completed Atlas activation or an official
client compatibility claim. No installed app, production configuration or keys
are changed by this patch. No NIP-OA ownership assertion is manufactured.

## Trust and wire contract

The server resolves the community from the authenticated transport. An explicitly
pinned service authority may sign kind 9011 admission and kind 9012 revocation.
`BUZZ_ASSIGNED_BOT_COMMUNITY_ID` and `BUZZ_ASSIGNED_BOT_AUTHORITY_PUBKEY` must both
be absent (commands disabled) or both canonical and valid. A pin for another
community never authorizes the command. Neither setting contains a private key.
Removing a pin disables new commands; it does not disable stored withdrawal checks.

The actual event signature and ID are verified, and the authenticated transport
principal must equal the event signer and pin. Admission requires `admin:channels`
scope; a scoped token must cover its channel. Revocation requires a global token.
The exact empty-content envelope contains distinct valid owner/bot/authority keys,
canonical non-nil assignment and nonce UUIDs, a positive generation, and expiration
no more than 60 seconds after creation. Creation cannot be in the future and the
command must remain unexpired at the database mutation boundary. Extra/duplicate
tags, malformed values and substitution of an unverified event are rejected.

Admission's exact tags are `community`, `owner`, `p`, `assignment`,
`assignment-version`, `nonce`, `expiration`, `h`, `role=bot`, and
`expected-role=absent|bot`. Revocation contains the first seven tags only and is
global. These commands are not advertised as an implemented public NIP descriptor.

## Storage, replay and withdrawal

Migration 0056 is additive; historical migration checksums stay unchanged. The
desired bootstrap schema has the same lifecycle tables and community write
fences. Both tables participate in community deletion inventory and purge order.
Command receipt, lifecycle mutation and admission commit together. Exact replay
does not recreate removed membership. Nonce reuse with a different event fails.
Revocation can precede admission; that generation cannot be resurrected. Higher
admission requires a withdrawn predecessor. Assignment, authority and owner are
immutable across generations, so owner-key recovery needs a fresh bot identity.

Admission locks and rechecks the registered active owner and bot, current owner
membership, target add policy, channel TTL/archive state and expected target role.
It cannot overwrite an existing privileged role or a genuine conflicting NIP-OA
owner. It writes no `agent_owner_pubkey` ownership substitute.

Human-approved bootstrap extension (2026-10-05): admission may atomically create
the missing bot's minimal public `users` row with `agent_type=atlas-assigned` and
`channel_add_policy=owner_only`. It does not reactivate or overwrite existing
identities, fabricate a NIP-OA owner, or add a permanent `relay_members` grant.
The current active owner must be a direct member of that same Relay community;
that membership row is held through the admission commit. Closed Relay auth may
admit only a currently valid stored assignment using writer-side checks, with no
owner assertion returned to legacy NIP-OA/observer paths. Owner departure, bans,
deactivation and assignment revocation override even a bot's direct member row.
The bootstrap is not an official-app discovery or whole-product acceptance claim.

Stored assignment access is checked on the writer, even with admission disabled.
Revocation, owner/bot deactivation or ban denies the assigned principal. Channel
access additionally requires both current memberships and a non-deleted channel,
including open channels. The common ingress checks assigned channel access before
legacy own-edit/admin exceptions; edits also check the stored target channel.
Legacy principals retain their ordinary authorization. Fanout uses a deduplicated
writer batch for assignment and private membership checks, including when a
subscription or visibility cache is stale. Anonymous legacy public delivery is
unchanged; private and owner/author-only restrictions still apply.

These are statement-time decisions, not a proved serialization fence for every
already-running write, historical read, HTTP response or Git effect. Do not claim
instantaneous in-flight revocation from a `STABLE` SQL function. The remaining
effect/commit-boundary and historical-response coverage is a launch prerequisite.

The event table additionally fences author-bound durable INSERTs in their actual
database transaction: existing assignment, owner/bot identity, direct owner Relay
membership and both channel memberships stay locked until commit. A volatile
check takes a fresh snapshot after lock waits. Channel writes acquire the existing
TTL shared lock before a `NO KEY UPDATE` channel-row lock, avoiding deferred TTL
refresh lock upgrades. Legacy authors without a stored assignment are unchanged.
The same trigger is inherited by event partitions; desired-state reconciliation
removes only standalone copies before PostgreSQL recreates inherited triggers.
Its named `42501` denial becomes a restricted write rejection in the common
persist branches; unrelated database privilege failures remain internal errors.

This partial fence does not cover a new assignment or ban inserted after a legacy
absence check, or NIP-59 gift wraps whose event signer differs from their assigned
authenticated transport principal. Separate post-commit side effects, Git CAS,
historical responses and live delivery still require their own authority fences.
It is not permission to activate the complete product.

## Git rights, not a blanket denial

An active assigned bot remains eligible for ordinary repository/branch/approval
permissions. Assignment checks precede the Git push owner shortcut, Git read and
settings-manager shortcuts; withdrawal must not be bypassed by owning the repo.
The assignment command creates no separate Git grant. The existing Relay mapping
of a channel `bot` role to Git `Member` is unchanged: admission can make those
existing bound-repository permissions effective. This is not evidence that Atlas
per-actor/per-branch capability enforcement is deployed. Communication membership
must not be represented as a global repository-write grant.

## Open activation prerequisites

Atlas still needs a verified-link lifecycle producer using the configured signing
authority and current tenant/user/bot generation, reconciliation and revocation.
Link proof remains identity proof, not forged owner consent. No extra user approval
dialog or custom harness is part of the agreed UX. First mentions in unmapped
private native channels, area/project executable routes, native Agents-grid
discovery without fabricated NIP-OA, ordinary Atlas Git capabilities, and private/
internal source-publication policy still need end-to-end verification. Final
acceptance uses the unchanged official Desktop and Mobile apps, pinned approved
deployment, positive replies and foreign/revoked/departed-owner negative cases.
