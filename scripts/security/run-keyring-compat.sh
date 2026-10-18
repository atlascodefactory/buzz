#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
manifest="$repo/scripts/security/keyring-compat/Cargo.toml"
# Build before isolating HOME so Cargo uses its normal dependency cache.
cargo build --locked --manifest-path "$manifest"
binary="$repo/scripts/security/keyring-compat/target/debug/buzz-keyring-compat"
test_home=$(mktemp -d)
trap 'rm -rf "$test_home"' EXIT
mkdir -p "$test_home/runtime"
chmod 700 "$test_home" "$test_home/runtime"
HOME="$test_home" XDG_CONFIG_HOME="$test_home/config" XDG_DATA_HOME="$test_home/data" XDG_RUNTIME_DIR="$test_home/runtime" BUZZ_ISOLATED_KEYRING_TEST=1 \
  dbus-run-session -- bash -eu -c '
    printf "%s" "isolated-test-password" | gnome-keyring-daemon --unlock --components=secrets
    timeout 90 "$1"
  ' _ "$binary"
HOME="$test_home" XDG_CONFIG_HOME="$test_home/config" XDG_DATA_HOME="$test_home/data" XDG_RUNTIME_DIR="$test_home/runtime" BUZZ_ISOLATED_KEYRING_TEST=1 \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$test_home/no-such-bus" timeout 20 "$binary" --no-bus
for failure in locked denied disconnect approved; do
  HOME="$test_home" XDG_RUNTIME_DIR="$test_home/runtime" BUZZ_ISOLATED_KEYRING_TEST=1 \
    dbus-run-session --config-file="$repo/scripts/security/keyring-compat/test-bus.conf" -- bash -eu -c '
      ready="$1/ready-$4"
      writes="$1/writes-$4"
      /usr/bin/python3 "$2" "$4" "$ready" "$writes" &
      provider=$!
      trap "kill $provider 2>/dev/null || true" EXIT
      for attempt in $(seq 1 100); do
        test -f "$ready" && break
        sleep 0.05
      done
      test -f "$ready"
      timeout 20 "$3" "--fault-$4"
      test ! -e "$writes"
      grep -qx OpenSession "$writes.events"
      grep -qx Unlock "$writes.events"
      if test "$4" != approved; then grep -qx SearchItems "$writes.events"; fi
      if test "$4" != locked; then grep -qx Prompt "$writes.events"; fi
      if test "$4" = disconnect; then
        grep -qx exit "$writes.events"
      elif test "$4" != locked; then
        grep -qx Completed "$writes.events"
      fi
    ' _ "$test_home" "$repo/scripts/security/keyring-compat/fault_service.py" "$binary" "$failure"
done
# These injected failures are test-only; production has no override path.
cargo test --locked --manifest-path "$repo/third_party/dbus-secret-service/Cargo.toml" --features crypto-rust,vendored session::crypto::
