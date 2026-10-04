# Conditional bot admission (Buzz extension, version 1)

This extension adds signed kind **9010**, distinct from ordinary NIP-29
PUT_USER (9000). It admits a registered target as `bot` only if another specified
identity is still an active member and the target's active role still matches
the requested state. It grants no agent ownership, application permissions or
authority to the specified identity. Existing 9000 behavior is unchanged.

## Envelope

Content must be empty. Exactly six tags, each with exactly one value:

```json
[
  ["h", "<canonical lowercase channel UUID>"],
  ["p", "<target lowercase 64-hex public key>"],
  ["role", "bot"],
  ["required-member", "<required lowercase 64-hex public key>"],
  ["expected-role", "absent"],
  ["expiration", "<canonical Unix seconds>"]
]
```

`expected-role` is either `absent` (no active membership, including a removed
row) or `bot`. No existing non-bot role is overwritten. The target must differ
from both the signer and required member. Expiration must be after creation
and no more than 60 seconds later. Creation cannot be in the future at admission.
The standard transport's signature, identity, timestamp, scope and channel-token
checks still apply; the required scope is `admin:channels`.

The signer **and** required member must be active in the same channel/community,
including open channels. Only active stream/forum channels are eligible; an
archived/deleted/expired channel or a reached member limit refuses admission.
The target must already be registered in this community. Its existing
`channel_add_policy` is checked against the **signer**, not `required-member`:
`owner_only` still needs the actual owner signer, and `nobody` refuses. A service
signer cannot use this extension to bypass an owner-only policy.

## Atomicity, replay and compatibility

The community write fence, per-channel membership lock, shared TTL lock,
channel metadata row and target policy row protect the checks and mutation.
The command event and membership commit in one transaction. A failed check
rolls back both; it must not return an accepted ACK or leave a command that
deduplication would later treat as successful. Expiry/TTL are sampled again
after lock waits. The current signed membership roster is published after commit,
including on exact replay. Publication errors propagate to the client: retry the
same event to repair the current roster, without repeating the membership write.
Unlike kind 9000, this command emits no separate member-added notification, which
would misleadingly imply a new admission on a historical retry. An ACK proves
durable roster publication, not successful delivery to every online subscriber.

An exact accepted event replay performs no membership mutation. `duplicate:`
confirms historical processing, **not** present membership or renewed consent.
A new request must use fresh state and a newly signed event. State matching is
not an ABA/generation guarantee: a removed and rejoined member is currently
active, and an absent target remains eligible if its old removed row exists.
Do not treat this as a membership-version or application-grant protocol.

NIP-11 advertises `buzz-conditional-bot-admission-v1`. Clients must not retry an
unsupported/conflicting request as unconditional kind 9000. Older Buzz relays
reject the unknown kind; no compatibility fallback is implemented. Mixed-version
deployments require routing to capable instances before enabling this command.

## CLI

```bash
buzz channels admit-bot --channel <uuid> --pubkey <bot-hex> \
  --required-member <member-hex> --expected-role absent
```

The CLI signs a 60-second request and reports the relay result. It does not
alter local harnesses, target policy or application authorization. After success
clients still need fresh roster readback before treating membership as current.
