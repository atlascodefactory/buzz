# Atlas relay upstream integration

The product branch is `atlas/relay`. Preserve Atlas-specific admission,
assigned-bot lifecycle, read authorization, readiness, Git permissions, and
separate media/Git object stores when merging `block/buzz/main`.

## Migration history

Atlas deployed `0056_assigned_bot_lifecycle.sql` before upstream introduced its
own migration 0056. Never rename or change the deployed Atlas migration, and
never overwrite an applied SQLx checksum. For this integration, upstream
0056–0065 are stored as fork 0057–0066, with identical SQL bytes. The exact
mapping and hashes are in `atlas-upstream-migration-map.json`.

On subsequent merges, extend the mapping for new upstream migrations and check
for duplicate version numbers. Update migration lookup tests, include paths,
and migration cutover thresholds deliberately; Atlas version 56 remains Atlas
version 56. Preserve all previously published fork SQL bytes. This fork's
migration history is not interchangeable with an already migrated upstream DB.

Verify both desired-state bootstrap and upgrade from a restored production
database. Compare applied checksums before and after, and run the migrator a
second time to prove it is a no-op. `schema/atlas_assigned_bots.sql` retains
Atlas's additional functions, tables and triggers in the modular upstream
schema; never remove its `zz_assigned_bot_*` guards when upstream retires its
push and TTL triggers.

## Cutover prerequisites

- Fork migration 0061 requires no active push leases and no gateway
  installations. Read current aggregate counts. Do not delete or deactivate
  user registrations just to satisfy the migration.
- Fork migrations 0064 and 0066 retire push/TTL database triggers in favor of
  application follow-up. An old binary that depends on those triggers is not
  a valid in-place rollback. Use a tested restoration procedure or a separately
  validated compatible fallback; preserve writes made after cutover.
- Validate operator listener consumers against signed kind-24245 registration
  and v2 notification payloads before upgrading an installation that uses them.
- Keep optional personal-read endpoints disabled until channel-scoped Atlas
  agent restrictions and the router regression tests pass.
- Use exact reviewed revisions and immutable images, current backup/restore
  evidence, required CI/reviews and a human workflow check. Check for other
  active Atlas/bridge deployments before switching production.

Do not treat a source merge, a healthy process, or an inherited CI result as
proof that the release was successfully deployed and exercised.
