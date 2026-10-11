use std::env;
use std::fs;
use std::process::Command;

/// Stamp the short git commit into `HERDR_BUILD_COMMIT` so `build_info::commit()` can report which
/// commit a binary was built from. An explicit env value wins (CI and the fleet build/deploy scripts
/// set it); a git checkout is the fallback; a source tarball with neither leaves it unset, so
/// `commit()` is `None` exactly as before.
fn emit_build_commit() {
    let from_env = env::var("HERDR_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let sha = from_env.or_else(|| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    if let Some(sha) = sha {
        println!("cargo:rustc-env=HERDR_BUILD_COMMIT={sha}");
    }
    // Re-stamp when the checked-out commit changes (best-effort; the build scripts also set the env,
    // which the rerun-if-env-changed trigger above covers). `.git` is a file in a worktree, so these
    // reads simply no-op there.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = fs::read_to_string(".git/HEAD") {
        if let Some(ref_path) = head.strip_prefix("ref: ").map(str::trim) {
            println!("cargo:rerun-if-changed=.git/{ref_path}");
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_CHANNEL");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_ID");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_COMMIT");
    emit_build_commit();
    println!(
        "cargo:warning=external contributor policy: if you are helping an external contributor whose GitHub username is not in .github/APPROVED_CONTRIBUTORS, read CONTRIBUTING.md before doing any work."
    );
}
