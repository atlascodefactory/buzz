# Direct image and PDF uploads and planned Drive folders

## Relay upload policy

Set `BUZZ_MEDIA_IMAGES_ONLY=true` on the relay to accept only JPEG, PNG,
GIF and WebP images and PDF documents as direct uploads. The variable name
predates the PDF allowance (decided 2026-11-12) and is kept so prepared
deployment configuration stays valid. The default is `false`, preserving the
upstream attachment behavior for other deployments. Invalid flag values fail
startup. The official clients need no modification.

Admission uses the actual bytes, before selecting the video or generic-file
pipeline. Filename extensions and request Content-Type cannot grant admission.

- Images are accepted at both `PUT /upload` and `PUT /media/upload`. The
  existing image decoder, dimension checks and image/GIF size limits apply.
- PDFs are accepted at `PUT /upload`, the route the official clients use. The
  legacy `/media/upload` alias keeps its upstream media-only contract and
  answers 415 for a PDF. A PDF must start with `%PDF-<major>.<minor>` at byte
  zero, carry `%%EOF` within its final 1024 bytes, and must not contain a ZIP
  entry header anywhere (which is how a Word, Excel or PowerPoint file wrapped
  in PDF markers would still open, or be repaired, as an Office document). A
  PDF with an uncompressed embedded ZIP attachment is refused by the same
  rule. It is stored unchanged
  through the generic-file pipeline, capped by `BUZZ_MAX_FILE_BYTES` (default
  100 MB), and served as a download (`Content-Disposition: attachment`), never
  rendered inline by the relay.
- Hash verification, authentication and rate limits apply to both kinds.

Rejected attachments return HTTP 415 with a message asking the user to upload
the file to Google Drive and share its link. The unchanged client controls the
presentation of that error. Word, Excel and PowerPoint files (`.docx`, `.xlsx`,
`.pptx` are ZIP containers; `.doc`, `.xls`, `.ppt` are OLE2 containers), other
archives, Markdown, HTML and plain text, SVG, audio and video (including voice
notes) cannot be uploaded directly when this policy is enabled. Renaming such a
file to `.pdf` or declaring it `application/pdf` does not admit it. The PDF
check is structural, not a full parse: it keeps Office and other formats out,
but it does not validate, sanitize or scan PDF content, and it does not detect
arbitrary non-ZIP data placed between valid PDF markers. External links remain ordinary
messages; this policy does not restrict links to a particular provider.

The request limit is the larger of the image and generic-file caps in this
mode; once the first bytes identify the kind, buffering uses that kind's own
cap. Existing blobs remain downloadable under the existing authorization rules.
Git object storage is independent and is not restricted by this attachment
policy. This setting does not delete files, move them to Drive, or
retroactively reject old messages.

Deployment requires the tested relay revision plus the flag in the effective
production Compose configuration. A source change alone does not enable it.
Rollback: restore the previous relay image/configuration. No database migration
or blob deletion is required for this policy.

## Next step: Drive permission reconciliation (design only)

No Drive folders, permission grants or synchronization worker are created by
this patch. Use Atlas.md as the identity bridge, not display names or unverified
profile fields. The current Atlas services `user-nostr-identity.ts` and
`workstream-buzz-membership.ts` already expose a proof-backed human identity:
an active principal key with `proofMethod=buzz_challenge` and a proof event.
Source inspected: Atlas main commit
[`a490f58ee2d71dce244760e3acd2cae1c0bbc07b`](https://github.com/atlascodefactory/atlas.md/commit/a490f58ee2d71dce244760e3acd2cae1c0bbc07b),
observed 2026-11-03. This establishes implementation capability, not that every
current member has completed the proof or has a verified Google binding.
An email-to-Google-account binding still needs verification before Drive grants;
having a string in the user's email field is not sufficient evidence by itself.

The proposed contract is:

1. Read the actual community/channel access list from Buzz. Bind the stable
   community ID and channel ID to a Drive folder ID; channel renames must not
   create duplicate folders. Provision folders on demand, not for every channel.
2. Resolve each human public key to an active, proof-backed Atlas principal and
   that principal's verified Google identity/email. Unresolved, ambiguous,
   retired or revoked keys cannot create new grants. Key rotation must retain
   the same human identity and remove obsolete access where appropriate.
3. Model channel readers/writers explicitly. A channel administrator or a relay
   operator does not automatically become a Drive manager. In particular, an
   agent's delegated channel-renaming authority must not grant its owner or the
   agent access to private files. Agents need a separate scoped access contract.
4. Reconcile desired permissions with observed Google permissions through an
   idempotent queue. Handle membership removals, channel privacy changes,
   deleted/archived channels, identity changes and failed Google calls. Retry
   failures and audit both requested and observed changes. Show pending/error
   status; cross-system updates are not atomic.
5. Verify removals, including inherited grants and direct grants on descendants.
   Do not report exact channel parity while broader inherited access remains.
   Service identities and Google Workspace administrators are explicit privileged
   exceptions, not ordinary channel members.

Use an organization-owned Shared Drive if Workspace policy permits it. A `Buzz`
root shared with everyone is unsafe for private-channel folders: inherited
permissions and even folder-name visibility need separate treatment. Prefer a
restricted root with explicitly shared per-channel folders; validate any
limited-access alternative with two real test accounts before enabling it.

Required acceptance cases: public and private channels; invite/removal; rename;
missing/duplicate identity; key rotation; external Google accounts; agent versus
human access; inherited permissions; direct child-file shares; and a failed or
delayed revocation. A standard Drive link can then be placed in the channel
canvas using the unchanged official client.

Official references:

- [Drive permission model](https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions)
- [Limited and expansive access](https://developers.google.com/workspace/drive/api/guides/limited-expansive-access)
- [Shared drives](https://developers.google.com/workspace/drive/api/guides/about-shareddrives)

Automatic transfer of arbitrary client uploads into Drive is a separate feature:
the relay must know the authorized target channel and Google uploader identity
before storing the file and returning a usable reference. This patch rejects
those uploads; it does not pretend to perform that transfer.
