use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn pair_json_errors_leave_stdout_empty() {
    let base = std::env::temp_dir().join(format!(
        "herdr-pair-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&base).unwrap();
    for (args, message) in [
        (
            vec!["pair", "--json", "--open"],
            "--json and --open cannot be combined",
        ),
        (
            vec!["pair", "--open", "--json"],
            "--json and --open cannot be combined",
        ),
        (vec!["pair", "--json", "--unknown"], "unknown option"),
        (vec!["pair", "--unknown", "--json"], "unknown option"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_herdr"))
            .args(args)
            .env_clear()
            .env("HOME", &base)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
        assert!(!base.join(".ssh").exists());
    }
    fs::remove_dir_all(base).unwrap();
}
