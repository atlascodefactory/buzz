# Temporary Buzz dependency patches

These source patches address the six findings blocking the October 2026 relay
update. They are part of the normal Cargo dependency graph, license checks and
security audit; no advisory is ignored. Remove each patch when an upstream
release provides the fix without breaking Buzz's integration.

`PROVENANCE.json` records the original versions, Mesh commit and SHA-256 of every
upstream source file. Original licenses are included beside each crate.

## Mesh 0.76.2 and ZIP 9.0.5

The three copied Mesh crates retain version 0.76.2 and all original runtime
sources. Their manifests resolve inherited workspace values explicitly and pin
internal dependencies to the same official v0.76.2 Git tag. Both Buzz workspaces
apply the same patches, preventing duplicate incompatible Mesh types.

ZIP is upgraded from 8.6 to 9.0.5, addressing RUSTSEC-2026-0367, -0368 and -0369.
The plugin-manager diagnostic uses `name_raw`, following upstream commit
450b0848c33697dd3433b920a0d5c011991eba00. Copied documentation fixtures retain
upstream tests without relying on the original checkout's directory layout.
The separate desktop Node installer propagates ZIP 9 filename-decoding errors.
No archive validation is relaxed.

## Keyring 4.2.0 v1 facade

This is a Buzz-specific **library-only** patch, not a general-purpose replacement
for the standalone Keyring CLI. Buzz and Mesh use the default v1 `Entry` facade;
no consumer enables Keyring 4's CLI. The unused CLI implementation, examples and
backend feature matrix are deliberately not distributed in this patch.

The v1 API, `inner`, `store_status`, Apple Keychain and Windows Credential Manager
selection are unchanged. On Unix, the maintained official D-Bus Secret Service
store replaces the ZBus store. It uses the same Secret Service collections,
`service`/`username`/`target` attributes and item labels. Mesh's service
`mesh-llm` and username `owner-keystore` remain unchanged. No credentials are
migrated, exported or regenerated. This removes the old ZBus chain and its
RUSTSEC-2026-0370, -0371 and -0372 findings from the relay workspace.

## D-Bus Secret Service 4.1.0

The upstream release used non-cryptographic Fastrand for DH private keys and
AES IVs. The patch uses OS `getrandom::fill` and propagates failures through
`Error::Crypto` before OpenSession, SetSecret or CreateItem. Both RustCrypto and
OpenSSL paths have the same behavior. There is no plaintext fallback or panic
on entropy failure. Failure injection exists only under `cfg(test)`.

This also fixes the already-present D-Bus dependency of Buzz's Keyring 3 facade.
The published archive SHA-256 is
`708b509edf7889e53d7efb0ffadd994cc6c2345ccb62f55cfd6b0682165e4fa6`.
Keyring 4.2.0's archive SHA-256 is
`2270074a3d26bcac93c1dc5d2845eb4c089e8d761ccf6e0ea266a16004640627`.

## Validation

`scripts/security/run-keyring-compat.sh` builds a separately locked test harness
and runs it against a private D-Bus session and temporary Gnome keyring. It checks
old-write/new-read and new-write/old-read, updates, Unicode/binary secrets,
attributes/labels, named targets, ambiguity, deletion and duplicate prevention.
The old ZBus implementation exists only in that compatibility harness; it is
not a production dependency. Crypto unit tests inject entropy failure and check
round-trip encryption with independent IVs. CI runs these tests in its required
Security job. Test credentials are synthetic; real keychains are never used.

The D-Bus prompt loop additionally pins the unique provider owner and detects
provider disappearance/replacement while a dialog is pending. This prevents an
indefinite wait on a still-live session bus. A synthetic provider tests locked,
denied, approved and provider-exit paths; recorded protocol milestones ensure a
failure cannot pass before the intended prompt. All item/collection creation and
secret writes are observed. A separate no-bus process tests startup failure.

## Desktop updater ZIP dependency

The desktop workspace patches the published `tauri-plugin-updater` 2.10.1
manifest to use ZIP 9.0.5 on Windows instead of ZIP 4.6.1. The runtime source, installer
selection, HTTPS configuration and Minisign verification are unchanged. Added
Windows tests exercise the real extraction method with MSI/NSIS packages,
Unicode filenames, corrupt input and directory traversal. Published
updater 2.14.0 still uses ZIP 4, so updating that package alone does not close
RUSTSEC-2026-0367, -0368 and -0369. Remove this patch once an official release
uses the patched ZIP API. The exact original file hashes are in PROVENANCE.json.
The upstream standalone Cargo.lock is omitted; the desktop workspace lockfile
is authoritative for this library dependency.

This patch does not resolve the separate GTK/proc-macro-error and ZBus maintenance
advisories. They require upstream framework migrations and remain visible in the
desktop advisory check. `user-idle` remains Windows-only; its macOS dependencies
still appear in Cargo's all-platform lockfile, but macOS now queries the native
Core Graphics event source through the maintained objc2 binding.
