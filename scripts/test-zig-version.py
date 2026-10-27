"""Check the build-script toolchain guard without invoking Cargo or Zig builds."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="herdr-zig-check-") as directory:
    temp = Path(directory)
    binary = temp / "build-script"
    subprocess.run(["rustc", "--edition=2024", str(root / "crates/ghostty-vt/build.rs"), "-o", str(binary)], check=True)
    zig = temp / "zig"
    zig.write_text('#!/bin/sh\nif [ "$1" = version ]; then echo "$TEST_ZIG_VERSION"; else printf "%s\\n" "$@" > "$TEST_ZIG_ARGS"; echo unexpected-build >&2; exit 42; fi\n')
    zig.chmod(0o755)
    for version, accepted in [("0.17.0", False), ("0.15.2", False), ("0.16.0", True)]:
        env = dict(os.environ, ZIG=str(zig), TEST_ZIG_VERSION=version, TEST_ZIG_ARGS=str(temp / "args"),
                   CARGO_MANIFEST_DIR=str(root / "crates/ghostty-vt"),
                   TARGET="aarch64-apple-darwin", OUT_DIR=str(temp))
        result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
        assert ("unexpected-build" in result.stderr) == accepted, (version, result.stderr)
        if not accepted:
            assert "requires Zig 0.16" in result.stderr, result.stderr
    if sys.platform == "darwin":
        xcrun = temp / "xcrun"
        xcrun.write_text('#!/bin/sh\necho /test/macos-sdk\n')
        xcrun.chmod(0o755)
        env.update(PATH=str(temp) + os.pathsep + env["PATH"], TARGET="x86_64-pc-windows-msvc",
                   LIBGHOSTTY_VT_WINDOWS_LIBC="/test/windows-libc.txt")
        result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
        args = (temp / "args").read_text().splitlines()
        assert "unexpected-build" in result.stderr, result.stderr
        assert args[args.index("--libc") + 1] == "/test/windows-libc.txt", args
        assert "--sysroot" in args, "Windows cross-build must preserve the macOS SDK for native helpers"
        assert args[args.index("--sysroot") + 1] == "/test/macos-sdk", args
print("PASS rejects incompatible Zig before build; accepts 0.16")
