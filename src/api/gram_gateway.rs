//! Supervision of the coordinator's Gram reverse gateway to one saved peer.
//!
//! A gateway attempt ([`crate::api::reverse::ReverseGateway`]) is a remote
//! socket preflight, one `ssh -R` child, and a private local listener. The
//! supervisor owns at most one attempt at a time, retries a failed or exited
//! attempt with bounded exponential backoff, and publishes its state for
//! `machine.status`. It runs independently of the peer's federation bridge and
//! stops when its owner drops it (peer retired, consent withdrawn, shutdown).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::api::federation_manager::PeerRoute;
use crate::api::schema::GramGatewayState;
use crate::config::FederationPeer;

const BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// An attempt that stayed up at least this long restarts the backoff schedule.
const STABLE_AFTER: Duration = BACKOFF_CAP;
const EXIT_POLL: Duration = Duration::from_millis(100);
const MAX_ERROR_CHARS: usize = 240;

/// Delay after `failures` consecutive failed attempts: 2 s doubling to 60 s.
pub(crate) fn gateway_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(16);
    BACKOFF_BASE.saturating_mul(1 << exponent).min(BACKOFF_CAP)
}

/// Everything one gateway attempt needs for a pinned saved peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GramGatewaySpec {
    pub(crate) alias: String,
    pub(crate) profile_id: String,
    pub(crate) endpoint: String,
    pub(crate) session: String,
    pub(crate) remote_machine_id: String,
}

impl GramGatewaySpec {
    /// Only a saved peer with a profile, remote session, and pinned install
    /// identity can carry a gateway.
    pub(crate) fn for_peer(peer: &FederationPeer) -> Option<Self> {
        Some(Self {
            alias: peer.alias.clone(),
            profile_id: peer.profile_id.clone()?,
            endpoint: peer.endpoint.clone()?,
            session: peer.remote_session.clone()?,
            remote_machine_id: peer.expected_node_id.clone()?,
        })
    }
}

/// One started gateway attempt. Dropping it stops the SSH forward and removes
/// the local gateway socket.
pub(crate) trait GramGatewaySession: Send {
    /// Why the gateway stopped serving, once it has.
    fn exited(&self) -> Option<String>;
}

/// Starts one gateway attempt, blocking through the remote preflight and the
/// SSH setup window. Returns early with an error once `cancel` is set.
pub(crate) trait GramGatewaySpawner: Send + Sync {
    fn start(
        &self,
        spec: &GramGatewaySpec,
        route: &PeerRoute,
        cancel: &Arc<AtomicBool>,
    ) -> io::Result<Box<dyn GramGatewaySession>>;
}

/// Time source for retry scheduling, injectable so tests drive backoff.
pub(crate) trait GatewayClock: Send + Sync {
    fn now(&self) -> Instant;
    /// Wait for `delay`, returning early once `stop` reports true.
    fn sleep(&self, delay: Duration, stop: &dyn Fn() -> bool);
    /// Spread retries of peers that failed together. Default: none.
    fn jitter(&self, delay: Duration) -> Duration {
        delay
    }
}

pub(crate) struct SystemClock;

impl GatewayClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, delay: Duration, stop: &dyn Fn() -> bool) {
        let deadline = Instant::now() + delay;
        while !stop() {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(50)));
        }
    }

    fn jitter(&self, delay: Duration) -> Duration {
        crate::api::server::failure_backoff(delay)
    }
}

/// Live consent check for one alias, re-evaluated before every attempt.
pub(crate) type GramConsent = Arc<dyn Fn(&str) -> bool + Send + Sync>;

enum Phase {
    Off,
    Starting,
    Up,
    Retrying {
        attempt: u32,
        next_at: Instant,
        last_error: String,
    },
}

/// Owns one peer's gateway attempts on a background thread.
pub(crate) struct GramRelaySupervisor {
    stop: Arc<AtomicBool>,
    phase: Arc<Mutex<Phase>>,
    clock: Arc<dyn GatewayClock>,
    join: Option<JoinHandle<()>>,
}

impl GramRelaySupervisor {
    pub(crate) fn start(
        spec: GramGatewaySpec,
        route: PeerRoute,
        spawner: Arc<dyn GramGatewaySpawner>,
        clock: Arc<dyn GatewayClock>,
        running: Arc<AtomicBool>,
        consent: GramConsent,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let phase = Arc::new(Mutex::new(Phase::Starting));
        let worker = Worker {
            spec,
            route,
            spawner,
            clock: Arc::clone(&clock),
            running,
            consent,
            stop: Arc::clone(&stop),
            phase: Arc::clone(&phase),
        };
        let join = std::thread::spawn(move || worker.run());
        Self {
            stop,
            phase,
            clock,
            join: Some(join),
        }
    }

    pub(crate) fn state(&self) -> GramGatewayState {
        match &*self
            .phase
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            Phase::Off => GramGatewayState::Off,
            Phase::Starting => GramGatewayState::Starting,
            Phase::Up => GramGatewayState::Up,
            Phase::Retrying {
                attempt,
                next_at,
                last_error,
            } => {
                let remaining = next_at.saturating_duration_since(self.clock.now());
                GramGatewayState::Retrying {
                    attempt: *attempt,
                    next_in_secs: remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0),
                    last_error: last_error.clone(),
                }
            }
        }
    }
}

impl Drop for GramRelaySupervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct Worker {
    spec: GramGatewaySpec,
    route: PeerRoute,
    spawner: Arc<dyn GramGatewaySpawner>,
    clock: Arc<dyn GatewayClock>,
    running: Arc<AtomicBool>,
    consent: GramConsent,
    stop: Arc<AtomicBool>,
    phase: Arc<Mutex<Phase>>,
}

impl Worker {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire) || !self.running.load(Ordering::Acquire)
    }

    fn set(&self, phase: Phase) {
        *self
            .phase
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = phase;
    }

    fn run(self) {
        let alias = self.spec.alias.as_str();
        let mut failures: u32 = 0;
        while !self.stopping() {
            if !(self.consent)(alias) {
                info!(alias = %alias, "Gram reverse gateway consent withdrawn; not retrying");
                break;
            }
            self.set(Phase::Starting);
            let failure = match self.spawner.start(&self.spec, &self.route, &self.stop) {
                Ok(session) => {
                    if self.stopping() {
                        break;
                    }
                    if failures == 0 {
                        info!(alias = %alias, "Gram reverse gateway up");
                    } else {
                        info!(alias = %alias, failed_attempts = failures, "Gram reverse gateway recovered");
                    }
                    self.set(Phase::Up);
                    let up_at = self.clock.now();
                    let exited = loop {
                        if self.stopping() {
                            break None;
                        }
                        if let Some(reason) = session.exited() {
                            break Some(reason);
                        }
                        std::thread::sleep(EXIT_POLL);
                    };
                    // Tear the attempt down before any retry: one ssh -R per peer.
                    drop(session);
                    let Some(reason) = exited else {
                        break;
                    };
                    if self.clock.now().saturating_duration_since(up_at) >= STABLE_AFTER {
                        failures = 0;
                    }
                    reason
                }
                Err(error) => {
                    if self.stopping() {
                        break;
                    }
                    error.to_string()
                }
            };
            failures = failures.saturating_add(1);
            let last_error = bounded_error(&failure);
            let delay = self.clock.jitter(gateway_backoff(failures));
            warn!(
                alias = %alias,
                attempt = failures,
                retry_in_secs = delay.as_secs(),
                error = %last_error,
                "Gram reverse gateway down; retrying"
            );
            self.set(Phase::Retrying {
                attempt: failures,
                next_at: self.clock.now() + delay,
                last_error,
            });
            self.clock.sleep(delay, &|| self.stopping());
        }
        self.set(Phase::Off);
    }
}

/// One line, at most [`MAX_ERROR_CHARS`] characters, for logs and status.
fn bounded_error(error: &str) -> String {
    let mut bounded: String = error
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_ERROR_CHARS)
        .collect();
    if error.chars().count() > MAX_ERROR_CHARS {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Condvar;

    /// Virtual time: `sleep` blocks until the test advances past its deadline.
    pub(crate) struct ManualClock {
        now: Mutex<Instant>,
        ticked: Condvar,
    }

    impl ManualClock {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
                ticked: Condvar::new(),
            })
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.now.lock().unwrap() += by;
            self.ticked.notify_all();
        }
    }

    impl GatewayClock for ManualClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }

        fn sleep(&self, delay: Duration, stop: &dyn Fn() -> bool) {
            let mut now = self.now.lock().unwrap();
            let deadline = *now + delay;
            while *now < deadline && !stop() {
                now = self
                    .ticked
                    .wait_timeout(now, Duration::from_millis(5))
                    .unwrap()
                    .0;
            }
        }
    }

    pub(crate) struct FakeSession {
        exited: Arc<Mutex<Option<String>>>,
        live: Arc<AtomicUsize>,
    }

    impl GramGatewaySession for FakeSession {
        fn exited(&self) -> Option<String> {
            self.exited.lock().unwrap().clone()
        }
    }

    impl Drop for FakeSession {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Scripted spawner: each call pops the next outcome (`Err` text or success);
    /// an empty script succeeds. Counts calls and concurrently live sessions.
    #[derive(Default)]
    pub(crate) struct FakeSpawner {
        script: Mutex<VecDeque<Result<(), String>>>,
        pub(crate) calls: AtomicUsize,
        pub(crate) live: Arc<AtomicUsize>,
        pub(crate) max_live: AtomicUsize,
        sessions: Mutex<Vec<Arc<Mutex<Option<String>>>>>,
        pub(crate) always_fail: AtomicBool,
    }

    impl FakeSpawner {
        pub(crate) fn scripted(script: impl IntoIterator<Item = Result<(), String>>) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(script.into_iter().collect()),
                ..Self::default()
            })
        }

        pub(crate) fn failing() -> Arc<Self> {
            let spawner = Self::default();
            spawner.always_fail.store(true, Ordering::Release);
            Arc::new(spawner)
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }

        pub(crate) fn live(&self) -> usize {
            self.live.load(Ordering::Acquire)
        }

        /// Make the most recent session report that its SSH forward exited.
        pub(crate) fn exit_latest(&self, reason: &str) {
            let sessions = self.sessions.lock().unwrap();
            *sessions.last().expect("a started session").lock().unwrap() = Some(reason.into());
        }
    }

    impl GramGatewaySpawner for FakeSpawner {
        fn start(
            &self,
            _spec: &GramGatewaySpec,
            _route: &PeerRoute,
            _cancel: &Arc<AtomicBool>,
        ) -> io::Result<Box<dyn GramGatewaySession>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let outcome = if self.always_fail.load(Ordering::Acquire) {
                Err("remote Gram reverse socket preflight failed: exit status: 255".into())
            } else {
                self.script.lock().unwrap().pop_front().unwrap_or(Ok(()))
            };
            outcome.map_err(io::Error::other)?;
            let live = self.live.fetch_add(1, Ordering::AcqRel) + 1;
            self.max_live.fetch_max(live, Ordering::AcqRel);
            let exited = Arc::new(Mutex::new(None));
            self.sessions.lock().unwrap().push(Arc::clone(&exited));
            Ok(Box::new(FakeSession {
                exited,
                live: Arc::clone(&self.live),
            }))
        }
    }

    /// Poll `condition` in real time for up to five seconds.
    pub(crate) fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::api::client::ConnectionTarget;

    fn spec() -> GramGatewaySpec {
        GramGatewaySpec {
            alias: "8195b6326f748f4da1945364a4e205b9".into(),
            profile_id: "8195b6326f748f4da1945364a4e205b9".into(),
            endpoint: "ssh://mac.example".into(),
            session: "main".into(),
            remote_machine_id: "machine_cf86dc42c063eac7b83162361990ae59".into(),
        }
    }

    fn route() -> PeerRoute {
        PeerRoute::new(
            ConnectionTarget::SocketPath("/nonexistent/herdr-test.sock".into()),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            true,
        )
    }

    fn supervise(
        spawner: &Arc<FakeSpawner>,
        clock: &Arc<ManualClock>,
        consent: GramConsent,
    ) -> GramRelaySupervisor {
        GramRelaySupervisor::start(
            spec(),
            route(),
            Arc::clone(spawner) as Arc<dyn GramGatewaySpawner>,
            Arc::clone(clock) as Arc<dyn GatewayClock>,
            Arc::new(AtomicBool::new(true)),
            consent,
        )
    }

    fn retrying(attempt: u32) -> impl Fn(&GramGatewayState) -> bool {
        move |state| matches!(state, GramGatewayState::Retrying { attempt: seen, .. } if *seen == attempt)
    }

    #[test]
    fn backoff_doubles_from_two_seconds_to_a_sixty_second_cap() {
        let schedule: Vec<u64> = (1..=8).map(|n| gateway_backoff(n).as_secs()).collect();
        assert_eq!(schedule, [2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(gateway_backoff(u32::MAX), Duration::from_secs(60));
    }

    #[test]
    fn exited_gateway_is_torn_down_before_exactly_one_replacement_starts() {
        let spawner = FakeSpawner::scripted([]);
        let clock = ManualClock::new();
        let supervisor = supervise(&spawner, &clock, Arc::new(|_| true));
        wait_until("gateway up", || supervisor.state() == GramGatewayState::Up);

        spawner.exit_latest("Gram relay SSH forward exited: exit status: 255");
        wait_until("retry scheduled", || retrying(1)(&supervisor.state()));
        assert_eq!(
            spawner.live(),
            0,
            "the exited attempt is dropped before backoff"
        );
        assert_eq!(
            supervisor.state(),
            GramGatewayState::Retrying {
                attempt: 1,
                next_in_secs: 2,
                last_error: "Gram relay SSH forward exited: exit status: 255".into(),
            }
        );

        clock.advance(Duration::from_secs(2));
        wait_until("gateway recovered", || {
            supervisor.state() == GramGatewayState::Up
        });
        assert_eq!(spawner.calls(), 2);
        assert_eq!(spawner.live(), 1);
        assert_eq!(spawner.max_live.load(Ordering::Acquire), 1);
        drop(supervisor);
        assert_eq!(spawner.live(), 0);
    }

    #[test]
    fn repeated_failures_back_off_and_withdrawn_consent_stops_retries() {
        let spawner = FakeSpawner::failing();
        let clock = ManualClock::new();
        let consent = Arc::new(AtomicBool::new(true));
        let allowed = Arc::clone(&consent);
        let supervisor = supervise(
            &spawner,
            &clock,
            Arc::new(move |_| allowed.load(Ordering::Acquire)),
        );
        wait_until("first retry", || retrying(1)(&supervisor.state()));
        clock.advance(Duration::from_secs(2));
        wait_until("second retry", || retrying(2)(&supervisor.state()));
        assert!(matches!(
            supervisor.state(),
            GramGatewayState::Retrying {
                next_in_secs: 4,
                ..
            }
        ));

        consent.store(false, Ordering::Release);
        clock.advance(Duration::from_secs(4));
        wait_until("supervisor off", || {
            supervisor.state() == GramGatewayState::Off
        });
        clock.advance(Duration::from_secs(600));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(spawner.calls(), 2);
    }

    #[test]
    fn bounded_error_is_one_line_and_truncated() {
        assert_eq!(bounded_error("ssh: exit\n255"), "ssh: exit 255");
        let long = bounded_error(&"x".repeat(1000));
        assert_eq!(long.chars().count(), MAX_ERROR_CHARS + 1);
        assert!(long.ends_with('…'));
    }
}
