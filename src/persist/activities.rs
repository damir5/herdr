//! Registered Live Activity push-token store.
//!
//! Persists the set of iOS Live Activity push tokens registered for background
//! updates at `~/.config/herdr/activities.json`, guarded by an `.activities.lock`
//! sidecar. Mirrors the atomic-write / lenient-load / strict-under-lock pattern of
//! [`crate::persist::devices`].
//!
//! A Live Activity token is PER-ACTIVITY (one running Live Activity), distinct from
//! the single device push token in [`crate::persist::devices`] — a device may hold
//! several at once. The daemon pushes its session's aggregate agent status to every
//! registered token, so no per-session key is needed: this daemon IS the session.
//! Like the device store, the file is owner-only (0600) on Unix because it holds
//! relay capabilities.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;

const ACTIVITIES_LOCK_FILE: &str = ".activities.lock";

/// An iOS Live Activity registered to receive background push updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredActivity {
    /// Opaque APNs Live Activity push token (hex string). Not a secret; per activity.
    pub activity_push_token: String,
    /// Registration time in Unix milliseconds.
    pub registered_unix_ms: u64,
    /// Opaque sealed capability from the HerdrUp push relay (`hpr1.…`). Sent back
    /// verbatim to the relay; never parsed or logged. Absent on legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_capability: Option<String>,
}

fn registry_path() -> PathBuf {
    crate::config::config_dir().join("activities.json")
}

fn registry_lock_path() -> PathBuf {
    crate::config::config_dir().join(ACTIVITIES_LOCK_FILE)
}

fn with_registry_lock<T>(operation: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    let lock_path = registry_lock_path();
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock.lock()?;
    operation()
}

fn save_to_path(path: &Path, activities: &[RegisteredActivity]) -> std::io::Result<()> {
    super::devices::save_owner_only_json(path, activities)
}

fn load_from_path_strict(path: &Path) -> std::io::Result<Vec<RegisteredActivity>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    super::devices::restrict_to_owner(path);
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str::<Vec<RegisteredActivity>>(&content)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// Read-modify-write the registry under the lock, returning the mutation's result
/// and the persisted activity list.
pub fn update<T>(
    mutation: impl FnOnce(&mut Vec<RegisteredActivity>) -> T,
) -> std::io::Result<(T, Vec<RegisteredActivity>)> {
    with_registry_lock(|| {
        let mut activities = load_from_path_strict(&registry_path())?;
        let result = mutation(&mut activities);
        activities.sort_by(|left, right| left.activity_push_token.cmp(&right.activity_push_token));
        save_to_path(&registry_path(), &activities)?;
        Ok((result, activities))
    })
}

/// Insert or replace an activity by its token. Returns the persisted activity list.
pub fn upsert(activity: RegisteredActivity) -> std::io::Result<Vec<RegisteredActivity>> {
    let (_, activities) = update(move |activities| {
        activities.retain(|existing| existing.activity_push_token != activity.activity_push_token);
        activities.push(activity);
    })?;
    Ok(activities)
}

/// Remove an activity by its token (the activity ended, or APNs reported it invalid).
/// Returns true when one was removed.
pub fn remove_token(token: &str) -> std::io::Result<bool> {
    let (removed, _) = update(|activities| {
        let before = activities.len();
        activities.retain(|activity| activity.activity_push_token != token);
        before != activities.len()
    })?;
    Ok(removed)
}

pub fn try_load() -> std::io::Result<Vec<RegisteredActivity>> {
    with_registry_lock(|| load_from_path_strict(&registry_path()))
}

/// Load the activity registry. Returns an empty vec on failure so a corrupt or missing
/// file never blocks delivery; mutations still use strict reads.
pub fn load() -> Vec<RegisteredActivity> {
    match try_load() {
        Ok(activities) => activities,
        Err(err) => {
            warn!(path = %registry_path().display(), err = %err, "failed to load activity registry");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "herdr-activities-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn save_and_load_roundtrip_with_and_without_capability() {
        let path = temp_path("roundtrip");
        let activities = [
            RegisteredActivity {
                activity_push_token: "aaaa".to_string(),
                registered_unix_ms: 1,
                relay_capability: None,
            },
            RegisteredActivity {
                activity_push_token: "bbbb".to_string(),
                registered_unix_ms: 2,
                relay_capability: Some("hpr1.c2VhbGVk".to_string()),
            },
        ];
        save_to_path(&path, &activities).unwrap();
        assert_eq!(load_from_path_strict(&path).unwrap(), activities);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn legacy_file_without_capability_still_loads() {
        let path = temp_path("legacy");
        std::fs::write(
            &path,
            r#"[{"activity_push_token":"abcd","registered_unix_ms":1700000000000}]"#,
        )
        .unwrap();
        let loaded = load_from_path_strict(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].activity_push_token, "abcd");
        assert_eq!(loaded[0].relay_capability, None);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn registry_is_owner_only_after_save_and_repaired_on_load() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = temp_path("mode");
        let tmp = path.with_extension("json.tmp");
        // A stale world-readable temp file must not leak its mode into the save.
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_to_path(&path, &[]).unwrap();
        assert_eq!(mode(&path), 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_from_path_strict(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
