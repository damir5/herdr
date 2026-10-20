#!/usr/bin/env bash
set -euo pipefail
source_dir=
version=
dry_run=${DRY_RUN:-0}
while (($#)); do
    case "$1" in
        --source-dir|--version)
            if (($# < 2)); then echo "Missing value for $1" >&2; exit 1; fi
            if [[ $1 == --source-dir ]]; then source_dir=$2; else version=$2; fi
            shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        *) echo 'Usage: release-drover.sh [--dry-run] [--source-dir ARCHIVE_DIRECTORY --version VERSION]' >&2; exit 1 ;;
    esac
done
if [[ -z ${ZIG:-} ]]; then
    echo 'Set ZIG to a Zig 0.16 executable (Mac: /private/tmp/zig-aarch64-macos-0.16.0/zig; damir-tp: /snap/zig/16117/zig).' >&2
    exit 1
fi
zig_version=$("$ZIG" version)
case "$zig_version" in
    0.16.*) ;;
    *) echo "ZIG must be version 0.16; found $zig_version at $ZIG." >&2; exit 1 ;;
esac
export ZIG
# rustup's installer adds ~/.cargo/bin to PATH only in login shells; plain `ssh host cmd` misses it.
command -v rustup >/dev/null || PATH=$HOME/.cargo/bin:$PATH
case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) echo 'Only Darwin and Linux are supported.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=amd64 ;;
    *) echo 'Only arm64 and amd64 are supported.' >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [[ -n $source_dir ]]; then
    if [[ -z $version ]]; then echo '--source-dir requires --version for an exported source tree.' >&2; exit 1; fi
    cd "$source_dir"
else
    cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
    commit=$(git rev-parse --short HEAD)
    git archive --format=tar HEAD > "$work/source.tar"
    mkdir "$work/src"
    tar -xf "$work/source.tar" -C "$work/src"
    cd "$work/src"
    package_version=$(sed -n '/^\[package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml)
    version=${version:-$package_version-drover.$commit}
fi
case "$version" in
    *[!a-zA-Z0-9._-]*|'') echo 'Invalid version: use letters, digits, dots, underscores or hyphens.' >&2; exit 1 ;;
esac
# Isolate output even when the caller has CARGO_TARGET_DIR set.
export CARGO_TARGET_DIR="$work/target"
export HERDR_BUILD_COMMIT="${version##*.}"
rustup run 1.96.1 cargo build --release --locked
cp "$CARGO_TARGET_DIR/release/herdr" "$work/herdr-drover"
command=(ah release publish herdr-drover "$version" "$os-$arch=$work/herdr-drover" --host "${AGENT_HUB_RELEASE_HOST:-raspberrypi}")
if [[ $dry_run == 1 ]]; then
    printf '%q ' "${command[@]}"
    printf '\n'
else
    "${command[@]}"
fi
