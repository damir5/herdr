use tokio::sync::mpsc;

use crate::{events::AppEvent, layout::PaneId};

use super::osc::OscStreamCollector;

pub(super) const FISH_INIT_COMMAND: &str = r"if status is-interactive
    function __herdr_command_start --on-event fish_preexec
        builtin printf '\e]133;C;herdr=%s\a' $fish_pid
    end
    function __herdr_command_end --on-event fish_postexec
        set -l command_status $status
        builtin printf '\e]133;D;%s;herdr=%s\a' $command_status $fish_pid
    end
end";

/// Only the pane's root shell can report activity, never an agent's child shell.
#[derive(Default)]
pub(super) struct ShellActivityTracker {
    collector: OscStreamCollector,
    running: bool,
}

impl ShellActivityTracker {
    pub(super) fn observe(&mut self, bytes: &[u8], root_pid: u32, mut receive: impl FnMut(bool)) {
        let running = &mut self.running;
        self.collector.observe(bytes, |body| {
            let Ok(body) = std::str::from_utf8(body) else {
                return;
            };
            let mut fields = body.split(';');
            if fields.next() != Some("133") {
                return;
            }
            let working = match fields.next() {
                Some("C") => true,
                Some("D") => {
                    if fields
                        .next()
                        .and_then(|value| value.parse::<i32>().ok())
                        .is_none()
                    {
                        return;
                    }
                    false
                }
                _ => return,
            };
            let pid = fields
                .next()
                .and_then(|value| value.strip_prefix("herdr="))
                .and_then(|value| value.parse::<u32>().ok());
            if root_pid == 0 || pid != Some(root_pid) || fields.next().is_some() {
                return;
            }
            if *running != working || !working {
                *running = working;
                receive(working);
            }
        });
    }
}

pub(super) fn shell_activity_channel(
    pane_id: PaneId,
    runtime_epoch: u64,
    events: mpsc::Sender<AppEvent>,
) -> mpsc::UnboundedSender<(bool, std::time::Instant)> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    // Preserve short, silent commands even when the app queue is full, without blocking PTY I/O.
    tokio::spawn(async move {
        while let Some((working, observed_at)) = rx.recv().await {
            if events
                .send(AppEvent::ShellCommandStateChanged {
                    pane_id,
                    runtime_epoch: Some(runtime_epoch),
                    working,
                    observed_at,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fish_shell_activity_keeps_fast_commands_and_excludes_child_shells() {
        let mut tracker = ShellActivityTracker::default();
        let mut changes = Vec::new();
        // An end can follow reader handoff; untagged integration and child shells are ignored.
        tracker.observe(
            b"\x1b]133;D;0;herdr=42\x07\x1b]133;C\x07\x1b]133;C;herdr=99\x07",
            42,
            |state| changes.push(state),
        );
        let commands = b"\x1b]133;C;herdr=42\x07\x1b]133;D;0;herdr=42\x07\x1b]133;C;herdr=42\x1b\\\x1b]133;D;1;herdr=42\x1b\\";
        for byte in commands {
            tracker.observe(&[*byte], 42, |state| changes.push(state));
        }
        assert_eq!(changes, [false, true, false, true, false]);
    }

    #[tokio::test]
    async fn fish_shell_activity_waits_for_queue_space_in_order() {
        let (events, mut rx) = mpsc::channel(1);
        events
            .send(AppEvent::UpdateReady {
                version: "test".into(),
                install_command: "test".into(),
            })
            .await
            .unwrap();
        let tx = shell_activity_channel(PaneId::from_raw(42), 7, events);
        tx.send((true, std::time::Instant::now())).unwrap();
        tx.send((false, std::time::Instant::now())).unwrap();
        assert!(matches!(
            rx.recv().await,
            Some(AppEvent::UpdateReady { .. })
        ));
        for expected in [true, false] {
            let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(event, AppEvent::ShellCommandStateChanged { working, runtime_epoch: Some(7), .. } if working == expected)
            );
        }
        drop(tx);
        assert!(rx.recv().await.is_none());
    }
}
