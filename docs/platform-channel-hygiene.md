# Channel hygiene by an operator-owned agent

This is a relay capability. Official desktop, mobile, web and agent CLI binaries
do not need a new build. No agent is promoted to channel admin automatically.

## Authority

An agent's verified, first-write-wins `users.agent_owner_pubkey` binding is
resolved in the request's community. Its owner must currently be a deployment
**Operator**, using the same config/owner-fallback/database roster resolution as
the admin API. Community admins, platform Moderators and self-asserted profile
fields do not confer this capability. Database roster revocation takes effect
on the next request; config grants retain their existing precedence.

The additional capabilities are:

- Historical discovery of stream/forum metadata, including private channels,
  within that community. Names, descriptions, topics and purposes are therefore
  visible to these trusted agents. DMs and workflow channels are excluded.
- A name-only kind:9002 edit of an active stream/forum, including a channel the
  agent has not joined. Channel creation retains its existing policy.

This grants no message, canvas, search-content or member-list access. It grants
no delete, membership, visibility, description, archive or TTL mutation. Existing
channel owner/admin rights, including their existing deletion behavior, still
apply independently. The agent does not become an Operator itself and cannot
manage the operator roster. Token scopes and channel restrictions still apply. Authority-assigned bots also
retain their assignment boundary: both bot and owner must remain channel
members, even when that owner is an Operator.

## Existing commands

Find a name and rename one channel using the unchanged CLI:

```sh
buzz channels search --query 'customer'
buzz channels get --channel <uuid>
buzz channels update --channel <uuid> --name 'customer-example'
```

Use only `--name` when relying on inherited authority. Combining it with
description, visibility or TTL changes still requires the existing channel role.
The CLI's normal optional NIP-OA `auth` tag is supported.

`channels list` lists visible metadata and now includes the inherited inventory
for an authorized agent; `--member` still restricts it to joined channels. It
defaults to 500 results, so use an explicit adequate `--limit` and check for
truncation. `channels search` requires a nonempty search string. CLI projections
omit optional aggregate tags. For raw metadata and explicit pagination, an agent
can use the existing signed NIP-98 `POST /query` bridge or NIP-42 WebSocket REQ
with a metadata-only filter:

```json
[{"kinds":[39000],"limit":500}]
```

Paginate using the existing `until`/`before_id` cursor contract; do not interpret
the first page as the whole inventory. Query/count behavior for other kinds is
unchanged. COUNT does not inherit the metadata exception. A filter mixing kinds
39000 and 9 does not inherit it either. Separate OR filters keep separate access
scopes. Only relay-signed metadata qualifies. Historical exceptions never enter
membership caches or live subscription scopes; re-query for a fresh inventory.
The authorization inventory is bounded to 4096 non-deleted stream/forum channels
per community and fails explicitly if exceeded.

## Review, preview, apply, undo

The agent performs analysis in its normal conversation; no new client panel or
automatic naming convention is introduced. Ask it to:

1. Fetch all metadata pages and propose a table of channel UUID, old name,
   proposed name, reason and conflicts. Compare names case-insensitively and
   flag duplicate target names before applying anything.
2. Report missing descriptions/topics/purposes, archived channels, duplicate
   names and aggregate ownerless/empty-channel hints. New metadata snapshots
   include optional `owner-count` and `member-count` tags. Missing tags on older
   snapshots mean **unknown**, not zero. These are structural hints, not proof
   that a channel is unused; message activity stays inaccessible.
3. Apply the requested naming plan and retain its old/new names and accepted
   event IDs. The existing CLI handles simple edits. An agent using the existing
   signed-event bridge may include the optional `expected-name` tag to protect
   each edit against a stale preview:

   ```json
   {"kind":9002,"content":"","tags":[
     ["h","<channel-uuid>"],["name","customer-example"],
     ["expected-name","Old customer name"]
   ]}
   ```

   This is the unsigned event body illustration; sign and authenticate it using
   the agent's existing key and transport. No human private key is needed.
   `expected-name` must occur at most once and can only accompany a single
   name-only edit. Stock CLI updates remain unconditional; do not claim that
   they send this optional precondition.
4. Re-query metadata and report each applied, rejected or pending entry. A batch
   is a sequence of individually atomic renames, not an all-or-nothing bulk
   transaction. Inherited-agent edits reject an already-used target name; the
   rule does not impose a new uniqueness constraint on legacy metadata edits.
5. Undo by issuing a **new** rename back to the recorded old name, with
   `expected-name` equal to the name applied by the plan. If another actor has
   renamed it since, stop and refresh the plan rather than overwrite their work.

Each plain name edit atomically commits the signed request, canonical channel
name, relay-signed kind:39000 metadata and a hash-chained `channel_updated` audit
entry with event ID, actor, old/new names and resolved operator-owner key. Failed
persistence rolls all four back. Exact retries do not append a second rename
audit entry. The audit is stored server-side; this change adds no audit-history
button or new CLI command. Event content and credentials are not copied into
the audit detail.

Renames do not rewrite UUIDs, messages or links. Do not automatically merge,
delete, unarchive, reassign ownership, change visibility, repair membership or
invent labels while doing naming hygiene. Report those suggestions to the human.

## Verification

Production-seam tests live in
`crates/buzz-relay/src/handlers/channel_hygiene/postgres_tests.rs`. They exercise
verified ownership and revocation, real ingest, concurrent stale-plan rejection,
unchanged owner deletion, HTTP and WS reads, token fences, and rollback under an
injected metadata-insert failure. They use generated keys and isolated databases.
No production channel is renamed by these tests.
