//! Pre-receive hook script generation and injection.
//!
//! The hook is a shell script that:
//! 1. Reads `old_oid new_oid ref_name` lines from stdin
//! 2. For each non-create/non-delete, runs `git merge-base --is-ancestor`
//!    (inheriting quarantine env vars)
//! 3. POSTs the payload to the relay's internal policy endpoint with HMAC
//! 4. Exits non-zero on ANY non-200 response (fail-closed)
//!
//! Security invariants:
//! - Fail-closed: curl failure, timeout, non-200 → exit 1
//! - Quarantine vars inherited for ancestry checks
//! - HMAC binds callback to specific push operation

use std::path::Path;

use tokio::fs;
use tracing::{error, info};

/// The pre-receive hook script content.
///
/// Environment variables set by the relay before spawning git receive-pack:
/// - `BUZZ_HOOK_URL` — internal policy endpoint (http://127.0.0.1:{port}/internal/git/policy)
/// - `BUZZ_HOOK_SECRET` — per-push HMAC secret
/// - `BUZZ_REPO_ID` — repo identifier (d-tag)
/// - `BUZZ_COMMUNITY_ID` — server-resolved community UUID for the git HTTP request
/// - `BUZZ_PUSHER_PUBKEY` — authenticated pusher's hex pubkey
/// - `BUZZ_MERGE_SOURCE_COMMIT` — PR head from the signed merge proof, or empty
///
/// Git sets automatically (quarantine):
/// - `GIT_OBJECT_DIRECTORY` — quarantine object store
/// - `GIT_ALTERNATE_OBJECT_DIRECTORIES` — includes the real object store
const PRE_RECEIVE_HOOK: &str = r#"#!/usr/bin/env bash
# Buzz pre-receive hook — FAIL-CLOSED
# ANY error, timeout, or non-200 response → reject the push.
set -eo pipefail

# Force C locale for deterministic sort order and byte-accurate string lengths.
# Rust uses byte-order comparison and byte lengths — locale-aware sort/strlen would mismatch.
export LC_ALL=C

ZERO="0000000000000000000000000000000000000000"

# Fail-closed: required env vars must be set by the relay.
: "${BUZZ_REPO_ID:?error: BUZZ_REPO_ID not set}"
: "${BUZZ_REPO_OWNER:?error: BUZZ_REPO_OWNER not set}"
: "${BUZZ_COMMUNITY_ID:?error: BUZZ_COMMUNITY_ID not set}"
: "${BUZZ_PUSHER_PUBKEY:?error: BUZZ_PUSHER_PUBKEY not set}"
: "${BUZZ_HOOK_URL:?error: BUZZ_HOOK_URL not set}"
: "${BUZZ_HOOK_SECRET:?error: BUZZ_HOOK_SECRET not set}"
# Optional URL-safe base64 NIP-34 merge proof. The relay always sets the
# variable; an empty value means this is an ordinary direct push.
BUZZ_MERGE_AUTHORIZATION="${BUZZ_MERGE_AUTHORIZATION:-}"
# The relay derives this value from the same signed proof. Keep the hook
# defensive because it interpolates the value into a git argv position.
BUZZ_MERGE_SOURCE_COMMIT="${BUZZ_MERGE_SOURCE_COMMIT:-}"
if [ -n "$BUZZ_MERGE_SOURCE_COMMIT" ] && ! [[ "$BUZZ_MERGE_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: invalid merge source commit" >&2
    exit 1
fi

WORK_DIR=$(mktemp -d) || { echo "error: cannot create temp dir" >&2; exit 1; }
REFS_FILE="$WORK_DIR/refs"
HMAC_FILE="$WORK_DIR/hmac"
RESP_FILE="$WORK_DIR/resp"
trap 'rm -rf "$WORK_DIR"' EXIT

# Phase 1: Read ref updates from stdin, classify each, build JSON + HMAC lines.
# We write two files in parallel:
#   REFS_FILE: JSON entries (unsorted, for the request body)
#   HMAC_FILE: "ref_name old_oid new_oid" lines (for sorting → HMAC input)
REFS=""
while read -r old_oid new_oid ref_name; do
    # Ancestry check for FF detection.
    # CRITICAL: GIT_OBJECT_DIRECTORY and GIT_ALTERNATE_OBJECT_DIRECTORIES are
    # inherited from our environment (git sets them for quarantine). Any git
    # subprocess we call sees the quarantined objects automatically.
    IS_ANCESTOR="false"
    if [ "$old_oid" != "$ZERO" ] && [ "$new_oid" != "$ZERO" ]; then
        # Exit 0 = is ancestor (FF), exit 1 = not ancestor (NFF),
        # exit 128 = error → treat as NFF (fail-closed).
        # Replacement refs are repository-controlled and must not redefine the
        # object graph used for a branch-protection decision.
        if GIT_NO_REPLACE_OBJECTS=1 git merge-base --is-ancestor "$old_oid" "$new_oid" 2>/dev/null; then
            IS_ANCESTOR="true"
        fi
    fi

    # A protected PR merge must contain the PR head, not merely be a
    # fast-forward from the target's prior tip. The proof's source commit is
    # extracted by the relay and checked here while quarantined objects are
    # visible. The policy endpoint later binds this result back to the stored
    # PR and the exact signed/pushed target tip.
    MERGE_SOURCE_IS_ANCESTOR="false"
    if [ -n "$BUZZ_MERGE_SOURCE_COMMIT" ] && [ "$new_oid" != "$ZERO" ]; then
        if GIT_NO_REPLACE_OBJECTS=1 git merge-base --is-ancestor "$BUZZ_MERGE_SOURCE_COMMIT" "$new_oid" 2>/dev/null; then
            MERGE_SOURCE_IS_ANCESTOR="true"
        fi
    fi

    # JSON entry for request body.
    # Escape any special JSON characters in ref_name (defense against injection).
    # Git ref names can't contain most special chars, but belt-and-suspenders.
    SAFE_REF=$(printf '%s' "$ref_name" | sed 's/\\/\\\\/g; s/"/\\"/g')

    if [ -n "$REFS" ]; then
        REFS="${REFS},"
    fi
    REFS="${REFS}{\"old_oid\":\"${old_oid}\",\"new_oid\":\"${new_oid}\",\"ref_name\":\"${SAFE_REF}\",\"is_ancestor\":${IS_ANCESTOR},\"merge_source_is_ancestor\":${MERGE_SOURCE_IS_ANCESTOR}}"

    # HMAC line: ref_name first (for sorting), then oids + is_ancestor.
    # is_ancestor as "1" or "0" to match Rust's b"1"/b"0".
    if [ "$IS_ANCESTOR" = "true" ]; then IS_ANCESTOR_HMAC="1"; else IS_ANCESTOR_HMAC="0"; fi
    if [ "$MERGE_SOURCE_IS_ANCESTOR" = "true" ]; then MERGE_SOURCE_IS_ANCESTOR_HMAC="1"; else MERGE_SOURCE_IS_ANCESTOR_HMAC="0"; fi
    echo "${ref_name} ${old_oid} ${new_oid} ${IS_ANCESTOR_HMAC} ${MERGE_SOURCE_IS_ANCESTOR_HMAC}" >> "$HMAC_FILE"
done

# Phase 2: Compute HMAC-SHA256 signature.
# Payload format MUST match relay's compute_hmac() in policy.rs:
#   repo_id | repo_owner | community_id | pusher_pubkey | refs | merge_authorization | timestamp
TIMESTAMP=$(date +%s)

# Structurally unambiguous HMAC format (matches Rust's compute_hmac):
# len(repo_id):repo_id | repo_owner | pusher | (old_oid + new_oid + len(ref):ref + is_anc)* | timestamp
REPO_ID_LEN=${#BUZZ_REPO_ID}
HMAC_INPUT="${REPO_ID_LEN}:${BUZZ_REPO_ID}|${BUZZ_REPO_OWNER}|${BUZZ_COMMUNITY_ID}|${BUZZ_PUSHER_PUBKEY}|"
# Sort by ref_name (field 1) — matches Rust's sort_by(|a, b| a.ref_name.cmp(&b.ref_name))
if [ -f "$HMAC_FILE" ]; then
    sort "$HMAC_FILE" | while IFS=' ' read ref_name old_oid new_oid is_anc merge_source_is_anc; do
        REF_LEN=${#ref_name}
        printf '%s%s%s:%s%s%s' "$old_oid" "$new_oid" "$REF_LEN" "$ref_name" "$is_anc" "$merge_source_is_anc"
    done > "$HMAC_FILE.concat"
    HMAC_INPUT="${HMAC_INPUT}$(cat "$HMAC_FILE.concat")"
    rm -f "$HMAC_FILE.concat"
fi
MERGE_AUTH_LEN=${#BUZZ_MERGE_AUTHORIZATION}
HMAC_INPUT="${HMAC_INPUT}|${MERGE_AUTH_LEN}:${BUZZ_MERGE_AUTHORIZATION}|${TIMESTAMP}"

SIGNATURE=$(printf '%s' "$HMAC_INPUT" | openssl dgst -sha256 -hmac "$BUZZ_HOOK_SECRET" -hex 2>/dev/null | sed 's/.*= //')
if [ -z "$SIGNATURE" ]; then
    echo "error: failed to compute HMAC signature" >&2
    exit 1
fi

# Phase 3: POST to policy endpoint — FAIL-CLOSED.
# repo_id is free-form (user-chosen d-tag) — must be escaped for JSON safety.
# repo_owner, community_id, and pusher_pubkey are validated fixed-shape strings — no escaping needed.
SAFE_REPO_ID=$(printf '%s' "$BUZZ_REPO_ID" | sed 's/\\/\\\\/g; s/"/\\"/g')
BODY="{\"repo_id\":\"${SAFE_REPO_ID}\",\"repo_owner\":\"${BUZZ_REPO_OWNER}\",\"community_id\":\"${BUZZ_COMMUNITY_ID}\",\"pusher_pubkey\":\"${BUZZ_PUSHER_PUBKEY}\",\"ref_updates\":[${REFS}],\"merge_authorization\":\"${BUZZ_MERGE_AUTHORIZATION}\",\"timestamp\":${TIMESTAMP},\"signature\":\"${SIGNATURE}\"}"

HTTP_CODE=$(curl --silent --max-time 10 \
    -o "$RESP_FILE" \
    -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    "$BUZZ_HOOK_URL" 2>/dev/null) || {
    echo "error: push authorization failed (network error reaching policy service)" >&2
    exit 1
}

if [ "$HTTP_CODE" != "200" ]; then
    echo "error: push denied by policy (HTTP $HTTP_CODE)" >&2
    cat "$RESP_FILE" >&2 2>/dev/null
    exit 1
fi

exit 0
"#;

/// Install the pre-receive hook into a bare repository.
///
/// Creates a `hooks/` directory and writes the hook script with execute permission.
/// Called during repo creation (kind:30617 handling) and can be called to
/// retrofit existing repos.
pub async fn install_hook(repo_path: &Path) -> anyhow::Result<()> {
    let hooks_dir = repo_path.join("hooks");
    fs::create_dir_all(&hooks_dir).await.map_err(|e| {
        error!(path = %hooks_dir.display(), error = %e, "failed to create hooks dir");
        anyhow::anyhow!("failed to create hooks directory: {e}")
    })?;

    let hook_path = hooks_dir.join("pre-receive");
    fs::write(&hook_path, PRE_RECEIVE_HOOK).await.map_err(|e| {
        error!(path = %hook_path.display(), error = %e, "failed to write hook");
        anyhow::anyhow!("failed to write pre-receive hook: {e}")
    })?;

    // Make executable (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&hook_path, perms).map_err(|e| {
            error!(path = %hook_path.display(), error = %e, "failed to chmod hook");
            anyhow::anyhow!("failed to set hook permissions: {e}")
        })?;
    }

    info!(repo = %repo_path.display(), "pre-receive hook installed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PRE_RECEIVE_HOOK;
    use std::path::Path;
    use std::process::{Command, Output};

    fn git(repo: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should run")
    }

    fn git_success(repo: &Path, args: &[&str]) -> String {
        let output = git(repo, args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output should be UTF-8")
            .trim()
            .to_string()
    }

    #[test]
    fn merge_proof_source_ancestry_is_checked_and_authenticated() {
        assert_eq!(
            PRE_RECEIVE_HOOK
                .matches("GIT_NO_REPLACE_OBJECTS=1 git merge-base --is-ancestor")
                .count(),
            2,
            "both fast-forward and PR-source ancestry must use the real object graph"
        );
        for fragment in [
            "git merge-base --is-ancestor \"$BUZZ_MERGE_SOURCE_COMMIT\" \"$new_oid\"",
            "\\\"merge_source_is_ancestor\\\":${MERGE_SOURCE_IS_ANCESTOR}",
            "${ref_name} ${old_oid} ${new_oid} ${IS_ANCESTOR_HMAC} ${MERGE_SOURCE_IS_ANCESTOR_HMAC}",
            "printf '%s%s%s:%s%s%s'",
        ] {
            assert!(
                PRE_RECEIVE_HOOK.contains(fragment),
                "hook must preserve merge-source ancestry contract fragment: {fragment}"
            );
        }
    }

    #[test]
    fn security_ancestry_ignores_replacement_objects() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let repo = temp.path();
        git_success(repo, &["init"]);
        git_success(repo, &["config", "user.name", "Buzz Test"]);
        git_success(repo, &["config", "user.email", "buzz-test@example.invalid"]);
        git_success(repo, &["commit", "--allow-empty", "-m", "old tip"]);
        let old_oid = git_success(repo, &["rev-parse", "HEAD"]);

        git_success(repo, &["switch", "-c", "reviewed-pr"]);
        git_success(repo, &["commit", "--allow-empty", "-m", "reviewed head"]);
        let source_oid = git_success(repo, &["rev-parse", "HEAD"]);

        git_success(repo, &["switch", "-c", "target", &old_oid]);
        git_success(repo, &["commit", "--allow-empty", "-m", "actual result"]);
        let result_oid = git_success(repo, &["rev-parse", "HEAD"]);
        let result_tree = git_success(repo, &["show", "-s", "--format=%T", &result_oid]);
        let replacement_oid = git_success(
            repo,
            &[
                "commit-tree",
                &result_tree,
                "-p",
                &old_oid,
                "-p",
                &source_oid,
                "-m",
                "synthetic replacement",
            ],
        );
        git_success(repo, &["replace", &result_oid, &replacement_oid]);

        assert!(
            git(
                repo,
                &["merge-base", "--is-ancestor", &source_oid, &result_oid]
            )
            .status
            .success(),
            "the fixture must prove that replacement refs can falsify ancestry"
        );

        let hardened = Command::new("git")
            .args(["merge-base", "--is-ancestor", &source_oid, &result_oid])
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .current_dir(repo)
            .output()
            .expect("hardened git command should run");
        assert_eq!(
            hardened.status.code(),
            Some(1),
            "security ancestry must use the actual result graph"
        );
    }

    #[test]
    fn runtime_image_installs_pre_receive_hook_tools() {
        let dockerfile = include_str!("../../../../../Dockerfile");
        let runtime_stage = dockerfile
            .split("FROM debian:${DEBIAN_VERSION}-slim AS runtime")
            .nth(1)
            .expect("Dockerfile should have a runtime stage");
        let runtime_setup = runtime_stage
            .split("COPY --from=builder")
            .next()
            .expect("runtime stage should copy built artifacts after package setup");

        for tool in ["curl", "openssl"] {
            assert!(
                PRE_RECEIVE_HOOK.contains(tool),
                "test setup expected the pre-receive hook to invoke {tool}"
            );
            assert!(
                runtime_setup.contains(&format!("\n        {tool} \\")),
                "relay runtime image must install {tool}; the git pre-receive hook uses it and fails closed without it"
            );
        }
    }
}
