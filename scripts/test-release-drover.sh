#!/usr/bin/env bash
set -euo pipefail
script=$(cd "$(dirname "$0")" && pwd)/release-drover.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin" "$work/source"
printf '[package]\nversion = "0.9.3"\n' > "$work/source/Cargo.toml"
cat > "$work/bin/zig" <<'MOCK'
#!/bin/sh
echo "${TEST_ZIG_VERSION:-0.16.0}"
MOCK
cat > "$work/bin/rustup" <<'MOCK'
#!/bin/sh
set -eu
[ "$*" = 'run 1.96.1 cargo build --release --locked' ]
[ "$HERDR_BUILD_COMMIT" = abc1234 ]
mkdir -p "$CARGO_TARGET_DIR/release"
printf binary > "$CARGO_TARGET_DIR/release/herdr"
MOCK
cat > "$work/bin/ah" <<'MOCK'
#!/bin/sh
exit 99
MOCK
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH"
if env -u ZIG bash "$script" --dry-run > "$work/error" 2>&1; then exit 1; fi
grep -q 'Set ZIG' "$work/error"
export ZIG="$work/bin/zig"
if TEST_ZIG_VERSION=0.17.0 bash "$script" --dry-run > "$work/error" 2>&1; then exit 1; fi
grep -q 'must be version 0.16' "$work/error"
if bash "$script" --dry-run --source-dir "$work/source" > "$work/error" 2>&1; then exit 1; fi
grep -q 'requires --version' "$work/error"
bash "$script" --dry-run --source-dir "$work/source" --version 0.9.3-drover.abc1234 > "$work/output"
grep -q 'ah release publish herdr-drover 0.9.3-drover.abc1234' "$work/output"
grep -Eq '(darwin|linux)-(arm64|amd64)=.*/herdr-drover' "$work/output"
echo 'PASS: missing/wrong Zig, explicit source/version, pinned build, platform, dry-run without publishing'
