//! In-memory cache of remote federation peers' agents and workspaces.
//!
//! The outbound federation client (see `crate::api::server`) polls each
//! configured peer's `agent.list` on a timer and writes the result here. The
//! local `agent.list` handler reads it back through [`FederationStore::merged_agents`],
//! which stamps every remote agent with an honest reachability status so a stale
//! `idle`/`done` is never presented as current once a peer stops answering.
//!
//! The store is shared behind an `Arc<Mutex<_>>`: the poll threads are writers,
//! the app loop is the reader. When no peer has an `endpoint` no poll thread is
//! ever spawned, so the store stays empty and the merge is a no-op — the local
//! `agent.list` path is byte-identical to a build without federation.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::api::schema::{
    AgentInfo, AgentStatus, FederationPollErrorClass, PaneAgentStatusChangedEvent,
    ServerCapabilities, WorkspaceInfo,
};

/// Reachability of a federation peer, derived from consecutive poll outcomes.
///
/// Serialized onto remote [`AgentInfo`]s so a client can tell a live peer from
/// one that has gone quiet. A C-like enum, so it derives `Eq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// The last poll succeeded.
    Reachable,
    /// One or two consecutive polls have failed; last-known agents are retained.
    Degraded,
    /// At least [`UNREACHABLE_MISS_THRESHOLD`] consecutive polls have failed; the
    /// peer is treated as offline and its agents are stamped `unknown`.
    Unreachable,
}

/// Consecutive poll misses at which a peer flips from `Degraded` to
/// `Unreachable`.
pub const UNREACHABLE_MISS_THRESHOLD: u32 = 3;

/// Map a running count of consecutive poll misses to a [`Reachability`].
///
/// `0` misses is [`Reachability::Reachable`]; `1..=2` is
/// [`Reachability::Degraded`] (last-known agents are kept); `>= 3` is
/// [`Reachability::Unreachable`].
pub fn reachability_for_misses(consecutive_misses: u32) -> Reachability {
    match consecutive_misses {
        0 => Reachability::Reachable,
        n if n < UNREACHABLE_MISS_THRESHOLD => Reachability::Degraded,
        _ => Reachability::Unreachable,
    }
}

/// Tracks consecutive poll misses for a single peer and maps them to a
/// [`Reachability`]. Held in a poll thread's local state, not in the store.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReachabilityTracker {
    consecutive_misses: u32,
}

impl ReachabilityTracker {
    /// Record a successful poll: resets the miss counter and reports
    /// [`Reachability::Reachable`].
    pub fn record_success(&mut self) -> Reachability {
        self.consecutive_misses = 0;
        Reachability::Reachable
    }

    /// Record a failed poll: increments the miss counter and reports the
    /// resulting degraded/unreachable status.
    pub fn record_miss(&mut self) -> Reachability {
        self.consecutive_misses = self.consecutive_misses.saturating_add(1);
        reachability_for_misses(self.consecutive_misses)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerObservation {
    pub validated_machine_id: Option<String>,
    pub remote_boot_id: Option<String>,
    pub remote_version: Option<String>,
    pub remote_protocol: Option<u32>,
    pub remote_capabilities: Option<ServerCapabilities>,
}

/// The last status the event relay published to local subscribers for one
/// remote pane (ids alias-qualified), and when it did.
///
/// This is both the relay's de-duplication baseline and the ordering fence
/// against the 5 s poll: a poll that started before `at` carries an older view
/// of the pane, so its status fields yield to this one.
#[derive(Debug, Clone)]
pub struct RelayedStatus {
    pub event: PaneAgentStatusChangedEvent,
    pub at: Instant,
}

/// How a relay resynchronization compares a fresh `agent.list` with what it
/// already published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayResync {
    /// First stream of this relay: record the current state silently.
    Seed,
    /// Reconnect or lag: publish each pane whose state differs from the last
    /// one published, including panes that appeared meanwhile.
    Diff,
    /// The peer restarted: pane ids from the old boot mean nothing, so publish
    /// every current pane.
    Reset,
}

/// One federation peer's cached agents plus its current reachability.
///
/// `agents` are stored already alias-prefixed (see the poll thread); the honest
/// reachability stamping is applied on read in [`FederationStore::merged_agents`].
#[derive(Debug, Clone)]
pub struct PeerCacheEntry {
    /// Current reachability of the peer.
    pub reachability: Reachability,
    /// Last-known agents from this peer, alias-prefixed at write time.
    pub agents: Vec<AgentInfo>,
    /// Last-known workspaces from this peer, alias-qualified at write time and
    /// in the peer's own order. Refreshed on a slower cadence than `agents`
    /// (see [`FederationStore::set_peer_workspaces`]) and kept across agent
    /// polls and misses.
    pub workspaces: Vec<WorkspaceInfo>,
    /// When the last successful poll landed, if any. Recorded now for a later
    /// staleness surface (e.g. a `last_seen` age in `agent.list`); not yet read
    /// on the merge path, so it reads as unused in a non-test build.
    #[allow(dead_code)]
    pub last_seen: Option<Instant>,
    pub last_success_unix_ms: Option<u64>,
    pub last_error_class: Option<FederationPollErrorClass>,
    pub observation: PeerObservation,
    /// Per remote pane (qualified id), the last status the event relay
    /// published. Empty for peers without an event stream.
    pub relayed: HashMap<String, RelayedStatus>,
}

impl PeerCacheEntry {
    #[cfg(test)]
    /// A fresh entry from a successful poll.
    pub fn reachable(agents: Vec<AgentInfo>, last_seen: Instant) -> Self {
        Self::reachable_observed(agents, last_seen, PeerObservation::default())
    }

    pub fn reachable_observed(
        agents: Vec<AgentInfo>,
        last_seen: Instant,
        observation: PeerObservation,
    ) -> Self {
        Self {
            reachability: Reachability::Reachable,
            agents,
            workspaces: Vec::new(),
            last_seen: Some(last_seen),
            last_success_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|duration| u64::try_from(duration.as_millis()).ok()),
            last_error_class: None,
            observation,
            relayed: HashMap::new(),
        }
    }
}

/// Cache of every configured federation peer's agents, keyed by peer alias.
#[derive(Debug, Default)]
pub struct FederationStore {
    peers: HashMap<String, PeerCacheEntry>,
}

impl FederationStore {
    /// Replace a peer's cached agent snapshot outside the poll path (tests),
    /// as a poll that started now.
    #[cfg(test)]
    pub fn set_peer(&mut self, alias: impl Into<String>, entry: PeerCacheEntry) {
        self.set_polled_peer(alias, entry, Instant::now());
    }

    /// Replace a peer's cached agent snapshot with a poll that started at
    /// `poll_started`. The peer's cached workspaces are carried over: they
    /// refresh on their own cadence through [`Self::set_peer_workspaces`], so
    /// an agent poll never blanks them.
    ///
    /// Ordering against the event relay: a pane whose status the relay
    /// published after `poll_started` keeps that status (and its turn), since
    /// this poll's answer may predate it. The relay's baselines are kept,
    /// except for panes the peer no longer lists that nothing relayed since the
    /// poll started.
    pub fn set_polled_peer(
        &mut self,
        alias: impl Into<String>,
        mut entry: PeerCacheEntry,
        poll_started: Instant,
    ) {
        let alias = alias.into();
        if let Some(previous) = self.peers.get_mut(&alias) {
            entry.workspaces = std::mem::take(&mut previous.workspaces);
            entry.relayed = std::mem::take(&mut previous.relayed);
        }
        for agent in &mut entry.agents {
            if let Some(relayed) = entry.relayed.get(&agent.pane_id) {
                if relayed.at > poll_started {
                    apply_status_event(agent, &relayed.event);
                }
            }
        }
        let agents = &entry.agents;
        entry.relayed.retain(|pane_id, relayed| {
            relayed.at > poll_started || agents.iter().any(|agent| agent.pane_id == *pane_id)
        });
        self.peers.insert(alias, entry);
    }

    /// Record one status event the relay received from `alias` (ids already
    /// qualified) and patch the cached agent. Returns whether it should be
    /// published: `false` when it repeats the last status published for the
    /// pane (a transition a resync already reported) or the alias is not
    /// cached.
    pub fn relay_status(
        &mut self,
        alias: &str,
        event: &PaneAgentStatusChangedEvent,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.peers.get_mut(alias) else {
            return false;
        };
        if entry
            .relayed
            .get(&event.pane_id)
            .is_some_and(|last| last.event == *event)
        {
            return false;
        }
        entry.record_relayed(event.clone(), now);
        true
    }

    /// Record a relayed `pane.turn_completed`: the pane's turn and epoch move
    /// forward (never back) in the cache and in the relay baseline, so an older
    /// poll cannot rewind them.
    pub fn relay_turn(
        &mut self,
        alias: &str,
        pane_id: &str,
        turn: u64,
        turn_epoch: u64,
        now: Instant,
    ) {
        let Some(entry) = self.peers.get_mut(alias) else {
            return;
        };
        let current = entry
            .relayed
            .get(pane_id)
            .map(|relayed| relayed.event.clone())
            .or_else(|| {
                entry
                    .agents
                    .iter()
                    .find(|agent| agent.pane_id == pane_id)
                    .map(agent_status_event)
            });
        let Some(mut event) = current else {
            return;
        };
        if (event.turn_epoch, event.turn) >= (Some(turn_epoch), Some(turn)) {
            return;
        }
        event.turn = Some(turn);
        event.turn_epoch = Some(turn_epoch);
        entry.record_relayed(event, now);
    }

    /// Forget a closed remote pane's relay baseline.
    pub fn relay_pane_closed(&mut self, alias: &str, pane_id: &str) {
        if let Some(entry) = self.peers.get_mut(alias) {
            entry.relayed.remove(pane_id);
        }
    }

    /// Compare a fresh `agent.list` from `alias` (as status events, ids
    /// qualified) with what the relay published, record it as the new
    /// baseline, and return the events to publish so each missed change is
    /// reported exactly once. Panes the peer no longer lists lose their
    /// baseline.
    pub fn relay_resync(
        &mut self,
        alias: &str,
        current: Vec<PaneAgentStatusChangedEvent>,
        mode: RelayResync,
        now: Instant,
    ) -> Vec<PaneAgentStatusChangedEvent> {
        let Some(entry) = self.peers.get_mut(alias) else {
            return Vec::new();
        };
        if mode == RelayResync::Reset {
            entry.relayed.clear();
        }
        let mut missed = Vec::new();
        let mut present = HashSet::with_capacity(current.len());
        for event in current {
            present.insert(event.pane_id.clone());
            let changed = entry
                .relayed
                .get(&event.pane_id)
                .is_none_or(|last| last.event != event);
            if mode != RelayResync::Seed && changed {
                missed.push(event.clone());
            }
            entry.record_relayed(event, now);
        }
        entry.relayed.retain(|pane_id, _| present.contains(pane_id));
        missed
    }

    /// Workspace ids named by `alias`'s cached agents that its cached
    /// workspaces do not contain: the poll's trigger for an early
    /// `workspace.list` refresh. Archived agents (empty workspace id) never count.
    pub fn missing_workspace_ids(&self, alias: &str) -> HashSet<String> {
        let Some(entry) = self.peers.get(alias) else {
            return HashSet::new();
        };
        entry
            .agents
            .iter()
            .map(|agent| agent.workspace_id.as_str())
            .filter(|id| {
                !id.is_empty()
                    && !entry
                        .workspaces
                        .iter()
                        .any(|workspace| workspace.workspace_id == *id)
            })
            .map(str::to_owned)
            .collect()
    }

    /// Replace a peer's cached workspaces (already alias-qualified). A no-op
    /// for an alias with no entry: the agent poll creates the entry first, and
    /// an evicted alias must not reappear.
    pub fn set_peer_workspaces(&mut self, alias: &str, workspaces: Vec<WorkspaceInfo>) {
        if let Some(entry) = self.peers.get_mut(alias) {
            entry.workspaces = workspaces;
        }
    }

    /// The cached entry for `alias`, if any. The event relay reads a peer's
    /// observed capabilities here; the merge path reads through
    /// [`Self::merged_agents`] instead.
    pub fn peer(&self, alias: &str) -> Option<&PeerCacheEntry> {
        self.peers.get(alias)
    }

    /// Update mutable saved-profile presentation on cached agents without
    /// disturbing transport generation, reachability, status, or last-seen time.
    pub fn update_peer_presentation(&mut self, alias: &str, profile_id: Option<&str>, label: &str) {
        let Some(entry) = self.peers.get_mut(alias) else {
            return;
        };
        for agent in &mut entry.agents {
            agent.machine_profile_id = profile_id.map(str::to_owned);
            agent.machine_label = Some(label.to_owned());
        }
        for workspace in &mut entry.workspaces {
            workspace.machine_profile_id = profile_id.map(str::to_owned);
            workspace.machine_label = Some(label.to_owned());
        }
    }

    /// Mark a peer's reachability without disturbing its last-known agents.
    ///
    /// Used on a poll miss: the agents from the last success are retained, only
    /// the reachability changes. A miss for a peer that never succeeded records
    /// an empty entry so its offline status is still observable.
    pub fn degrade_peer(&mut self, alias: &str, reachability: Reachability) {
        match self.peers.get_mut(alias) {
            Some(entry) => entry.reachability = reachability,
            None => {
                self.peers.insert(
                    alias.to_string(),
                    PeerCacheEntry {
                        reachability,
                        agents: Vec::new(),
                        workspaces: Vec::new(),
                        last_seen: None,
                        last_success_unix_ms: None,
                        last_error_class: None,
                        observation: PeerObservation::default(),
                        relayed: HashMap::new(),
                    },
                );
            }
        }
    }

    pub fn record_poll_error(&mut self, alias: &str, class: FederationPollErrorClass) {
        if let Some(entry) = self.peers.get_mut(alias) {
            entry.last_error_class = Some(class);
        }
    }

    /// Evict a peer's cache entry so its agents stop being merged into
    /// `agent.list` immediately on removal/change. Called by the federation peer
    /// manager's `reconcile` when a peer is dropped or re-pointed, so a removed
    /// peer's last-known agents never linger past the reload.
    pub fn remove_peer(&mut self, alias: &str) {
        self.peers.remove(alias);
    }

    /// Whether any peer is cached. Empty means federation contributed nothing.
    /// Exercised by the no-federation regression tests; the merge path does not
    /// need it (extending by an empty set is a no-op), so it reads as unused in a
    /// non-test build.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Every cached peer's agents, honest-reachability stamped for merge into the
    /// local `agent.list`.
    ///
    /// - `Reachable`: the agent is returned as-is with its `reachability` set.
    /// - `Degraded`/`Unreachable`: the visible `agent_status` is replaced with
    ///   [`AgentStatus::Unknown`] and the last-known status is preserved in
    ///   `last_known_status`, so a stale `idle`/`done` is never shown as current
    ///   the moment a peer stops answering. `reachability` still distinguishes a
    ///   briefly-degraded peer from a fully offline one.
    pub fn merged_agents(&self) -> Vec<AgentInfo> {
        self.peers
            .values()
            .flat_map(|entry| {
                entry
                    .agents
                    .iter()
                    .map(|agent| stamp_agent(agent, entry.reachability))
            })
            .collect()
    }

    /// Every cached peer's workspaces for merge into the local
    /// `workspace.list`, grouped by peer alias (sorted, so the order is stable)
    /// and in each peer's own order, so `number` and position reproduce that
    /// machine's sidebar. Stamped like [`Self::merged_agents`]: a peer that is
    /// not `Reachable` keeps its last-known workspaces, surfaces `agent_status`
    /// as `unknown`, and preserves the real value in `last_known_status`.
    pub fn merged_workspaces(&self) -> Vec<WorkspaceInfo> {
        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_unstable_by_key(|(alias, _)| *alias);
        peers
            .into_iter()
            .flat_map(|(_, entry)| {
                entry.workspaces.iter().map(|workspace| {
                    let mut stamped = workspace.clone();
                    stamped.reachability = Some(entry.reachability);
                    if entry.reachability != Reachability::Reachable {
                        stamped.last_known_status = Some(workspace.agent_status);
                        stamped.agent_status = AgentStatus::Unknown;
                    }
                    stamped
                })
            })
            .collect()
    }
}

impl PeerCacheEntry {
    /// Make `event` the pane's relay baseline and patch its cached agent.
    fn record_relayed(&mut self, event: PaneAgentStatusChangedEvent, now: Instant) {
        if let Some(agent) = self
            .agents
            .iter_mut()
            .find(|agent| agent.pane_id == event.pane_id)
        {
            apply_status_event(agent, &event);
        }
        self.relayed
            .insert(event.pane_id.clone(), RelayedStatus { event, at: now });
    }
}

/// The `pane.agent_status_changed` payload describing `agent`'s current state.
pub fn agent_status_event(agent: &AgentInfo) -> PaneAgentStatusChangedEvent {
    PaneAgentStatusChangedEvent {
        pane_id: agent.pane_id.clone(),
        workspace_id: agent.workspace_id.clone(),
        agent_status: agent.agent_status,
        input_pending: agent.input_pending,
        input_prompt_kind: agent.input_prompt_kind,
        agent: agent.agent.clone(),
        title: agent.title.clone(),
        display_agent: agent.display_agent.clone(),
        state_labels: agent.state_labels.clone(),
        turn: agent.turn,
        turn_epoch: agent.turn_epoch,
    }
}

/// Overwrite `agent`'s status fields with a status event for its pane.
fn apply_status_event(agent: &mut AgentInfo, event: &PaneAgentStatusChangedEvent) {
    agent.agent_status = event.agent_status;
    agent.input_pending = event.input_pending;
    agent.input_prompt_kind = event.input_prompt_kind;
    agent.agent.clone_from(&event.agent);
    agent.title.clone_from(&event.title);
    agent.display_agent.clone_from(&event.display_agent);
    agent.state_labels.clone_from(&event.state_labels);
    agent.turn = event.turn;
    agent.turn_epoch = event.turn_epoch;
}

/// Apply the honest-offline reachability stamp to one stored (already-prefixed)
/// remote agent.
fn stamp_agent(agent: &AgentInfo, reachability: Reachability) -> AgentInfo {
    let mut stamped = agent.clone();
    stamped.reachability = Some(reachability);
    // Only a `Reachable` peer surfaces its real live status. The moment a peer
    // stops answering — `Degraded` (1-2 misses) OR `Unreachable` (>= 3) — its
    // last poll's `idle`/`done` is no longer known to be current, so it must not
    // be presented as the live `agent_status`: surface `unknown` and keep the
    // real last-known status separately in `last_known_status`. A consumer that
    // reads `agent_status` alone is then never misled by a stale idle/done; the
    // `reachability` field still tells a briefly-degraded peer from a fully
    // offline one.
    if reachability != Reachability::Reachable {
        stamped.last_known_status = Some(agent.agent_status);
        stamped.agent_status = AgentStatus::Unknown;
    }
    stamped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(status: AgentStatus, name: &str) -> AgentInfo {
        let value = serde_json::json!({
            "terminal_id": "t",
            "name": name,
            "agent_status": status,
            "workspace_id": "ws",
            "tab_id": "tab",
            "pane_id": "pane",
            "focused": false,
            "revision": 1,
        });
        serde_json::from_value(value).expect("agent info deserializes")
    }

    #[test]
    fn miss_state_machine_degrades_then_goes_unreachable_then_recovers() {
        let mut tracker = ReachabilityTracker::default();
        // First and second miss: Degraded, last-known kept.
        assert_eq!(tracker.record_miss(), Reachability::Degraded);
        assert_eq!(tracker.record_miss(), Reachability::Degraded);
        // Third miss: Unreachable.
        assert_eq!(tracker.record_miss(), Reachability::Unreachable);
        // Still unreachable while misses accumulate.
        assert_eq!(tracker.record_miss(), Reachability::Unreachable);
        // A success resets and recovers immediately.
        assert_eq!(tracker.record_success(), Reachability::Reachable);
        // And the counter is back to zero, so the next miss is Degraded again.
        assert_eq!(tracker.record_miss(), Reachability::Degraded);
    }

    #[test]
    fn reachability_for_misses_boundaries() {
        assert_eq!(reachability_for_misses(0), Reachability::Reachable);
        assert_eq!(reachability_for_misses(1), Reachability::Degraded);
        assert_eq!(reachability_for_misses(2), Reachability::Degraded);
        assert_eq!(reachability_for_misses(3), Reachability::Unreachable);
        assert_eq!(reachability_for_misses(9), Reachability::Unreachable);
    }

    #[test]
    fn empty_store_merges_to_nothing() {
        let store = FederationStore::default();
        assert!(store.is_empty());
        assert!(store.merged_agents().is_empty());
    }

    #[test]
    fn reachable_peer_stamps_reachable_and_keeps_status() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![agent(AgentStatus::Working, "home/builder")],
                Instant::now(),
            ),
        );
        let merged = store.merged_agents();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].agent_status, AgentStatus::Working);
        assert_eq!(merged[0].reachability, Some(Reachability::Reachable));
        assert_eq!(merged[0].last_known_status, None);
    }

    #[test]
    fn degraded_peer_stamps_unknown_and_preserves_last_known() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry {
                reachability: Reachability::Degraded,
                agents: vec![agent(AgentStatus::Blocked, "home/reviewer")],
                workspaces: Vec::new(),
                last_seen: Some(Instant::now()),
                last_success_unix_ms: None,
                last_error_class: None,
                observation: PeerObservation::default(),
                relayed: HashMap::new(),
            },
        );
        let merged = store.merged_agents();
        // A Degraded peer has stopped answering (1-2 misses): it must NOT surface
        // its last poll's status as current. It is stamped `Unknown` exactly like
        // Unreachable, distinguished only by the `reachability` field.
        assert_eq!(
            merged[0].agent_status,
            AgentStatus::Unknown,
            "a degraded peer must not surface a stale idle/done as current"
        );
        assert_eq!(merged[0].last_known_status, Some(AgentStatus::Blocked));
        assert_eq!(merged[0].reachability, Some(Reachability::Degraded));
    }

    #[test]
    fn unreachable_peer_stamps_unknown_and_preserves_last_known() {
        let mut store = FederationStore::default();
        // A peer last seen idle, then gone offline: must NOT surface `idle`.
        store.set_peer(
            "home",
            PeerCacheEntry {
                reachability: Reachability::Unreachable,
                agents: vec![agent(AgentStatus::Idle, "home/idler")],
                workspaces: Vec::new(),
                last_seen: Some(Instant::now()),
                last_success_unix_ms: None,
                last_error_class: None,
                observation: PeerObservation::default(),
                relayed: HashMap::new(),
            },
        );
        let merged = store.merged_agents();
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].agent_status,
            AgentStatus::Unknown,
            "an offline peer must never present a stale idle/done as current"
        );
        assert_eq!(merged[0].last_known_status, Some(AgentStatus::Idle));
        assert_eq!(merged[0].reachability, Some(Reachability::Unreachable));
    }

    #[test]
    fn degrade_peer_retains_agents_but_updates_reachability() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![agent(AgentStatus::Done, "home/done")], Instant::now()),
        );
        store.degrade_peer("home", Reachability::Unreachable);
        let entry = store.peer("home").expect("peer retained");
        assert_eq!(entry.reachability, Reachability::Unreachable);
        assert_eq!(
            entry.agents.len(),
            1,
            "last-known agents retained on a miss"
        );
        // And a miss for an unknown peer records an observable offline entry.
        store.degrade_peer("ghost", Reachability::Unreachable);
        assert_eq!(
            store.peer("ghost").expect("ghost recorded").reachability,
            Reachability::Unreachable
        );
        assert!(store
            .peer("ghost")
            .expect("ghost recorded")
            .agents
            .is_empty());
    }

    #[test]
    fn remove_peer_evicts_entry_and_clears_merge() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![agent(AgentStatus::Working, "home/builder")],
                Instant::now(),
            ),
        );
        assert!(store.peer("home").is_some());
        assert_eq!(store.merged_agents().len(), 1);

        store.remove_peer("home");
        assert!(
            store.peer("home").is_none(),
            "removed peer must leave no cache entry"
        );
        assert!(
            store.merged_agents().is_empty(),
            "a removed peer contributes no merged agents"
        );
        assert!(store.is_empty());

        // Removing an absent alias is a no-op, not a panic.
        store.remove_peer("home");
        assert!(store.is_empty());
    }

    fn workspace(workspace_id: &str, number: usize, status: AgentStatus) -> WorkspaceInfo {
        serde_json::from_value(serde_json::json!({
            "workspace_id": workspace_id,
            "number": number,
            "label": format!("label-{number}"),
            "focused": false,
            "pane_count": 1,
            "tab_count": 1,
            "active_tab_id": format!("{workspace_id}:t1"),
            "agent_status": status,
        }))
        .expect("workspace info deserializes")
    }

    #[test]
    fn cached_workspaces_survive_agent_polls_and_go_stale_with_the_peer() {
        let mut store = FederationStore::default();
        store.set_peer_workspaces("home", vec![workspace("home/w0", 1, AgentStatus::Idle)]);
        assert!(
            store.merged_workspaces().is_empty(),
            "an alias without an agent-poll entry must not gain workspaces"
        );

        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![agent(AgentStatus::Working, "a")], Instant::now()),
        );
        store.set_peer_workspaces(
            "home",
            vec![
                workspace("home/w2", 1, AgentStatus::Working),
                workspace("home/w1", 2, AgentStatus::Done),
            ],
        );
        store.set_peer(
            "alpha",
            PeerCacheEntry::reachable(Vec::new(), Instant::now()),
        );
        store.set_peer_workspaces("alpha", vec![workspace("alpha/w1", 1, AgentStatus::Idle)]);
        // The next 5 s agent poll replaces the entry; workspaces are kept.
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![agent(AgentStatus::Working, "a")], Instant::now()),
        );

        let merged = store.merged_workspaces();
        let ids: Vec<_> = merged.iter().map(|ws| ws.workspace_id.as_str()).collect();
        assert_eq!(
            ids,
            ["alpha/w1", "home/w2", "home/w1"],
            "peers sorted by alias, each in its own order"
        );
        assert!(merged
            .iter()
            .all(|ws| ws.reachability == Some(Reachability::Reachable)));
        assert_eq!(merged[1].agent_status, AgentStatus::Working);
        assert_eq!(merged[1].last_known_status, None);

        store.degrade_peer("home", Reachability::Unreachable);
        let merged = store.merged_workspaces();
        let home: Vec<_> = merged
            .iter()
            .filter(|ws| ws.workspace_id.starts_with("home/"))
            .collect();
        assert_eq!(
            home.len(),
            2,
            "an unreachable peer keeps its last-known workspaces"
        );
        assert!(home.iter().all(|ws| {
            ws.reachability == Some(Reachability::Unreachable)
                && ws.agent_status == AgentStatus::Unknown
        }));
        assert_eq!(home[0].last_known_status, Some(AgentStatus::Working));
        assert_eq!(home[1].last_known_status, Some(AgentStatus::Done));

        store.remove_peer("home");
        assert_eq!(store.merged_workspaces().len(), 1);
    }

    #[test]
    fn missing_workspace_ids_names_only_uncached_live_workspaces() {
        let mut store = FederationStore::default();
        let mut archived = agent(AgentStatus::Idle, "archived");
        archived.workspace_id = String::new();
        let mut known = agent(AgentStatus::Idle, "known");
        known.workspace_id = "home/w1".into();
        let mut new = agent(AgentStatus::Idle, "new");
        new.workspace_id = "home/w2".into();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![archived, known, new], Instant::now()),
        );
        store.set_peer_workspaces("home", vec![workspace("home/w1", 1, AgentStatus::Idle)]);

        assert_eq!(
            store.missing_workspace_ids("home"),
            HashSet::from(["home/w2".to_string()])
        );
        assert!(store.missing_workspace_ids("absent").is_empty());
    }

    fn pane_agent(pane_id: &str, status: AgentStatus) -> AgentInfo {
        let mut agent = agent(status, pane_id);
        agent.pane_id = pane_id.into();
        agent
    }

    fn status(pane_id: &str, status: AgentStatus) -> PaneAgentStatusChangedEvent {
        agent_status_event(&pane_agent(pane_id, status))
    }

    fn cached_status(store: &FederationStore, pane_id: &str) -> AgentStatus {
        store
            .peer("home")
            .expect("home cached")
            .agents
            .iter()
            .find(|agent| agent.pane_id == pane_id)
            .expect("pane cached")
            .agent_status
    }

    #[test]
    fn a_poll_older_than_a_relayed_event_keeps_the_event_status() {
        use std::time::Duration;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], t0),
            t0,
        );

        // The poll request goes out, then the stream reports `blocked`, then the
        // poll's (older) `working` answer lands.
        let poll_started = Instant::now();
        let mut blocked = status("home/p1", AgentStatus::Blocked);
        blocked.turn = Some(4);
        blocked.turn_epoch = Some(2);
        assert!(store.relay_status("home", &blocked, poll_started + Duration::from_millis(1)));
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Blocked);
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], t0),
            poll_started,
        );
        assert_eq!(
            cached_status(&store, "home/p1"),
            AgentStatus::Blocked,
            "an older poll must not overwrite a newer relayed status"
        );
        assert_eq!(store.peer("home").unwrap().agents[0].turn, Some(4));

        // A poll that started after the event is authoritative again.
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Idle)], t0),
            Instant::now() + Duration::from_millis(5),
        );
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Idle);
    }

    #[test]
    fn relay_resync_reports_each_missed_change_once() {
        let mut store = FederationStore::default();
        let now = Instant::now();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![
                    pane_agent("home/p1", AgentStatus::Working),
                    pane_agent("home/p2", AgentStatus::Idle),
                ],
                now,
            ),
        );
        let seeded = store.relay_resync(
            "home",
            vec![
                status("home/p1", AgentStatus::Working),
                status("home/p2", AgentStatus::Idle),
            ],
            RelayResync::Seed,
            now,
        );
        assert!(seeded.is_empty(), "the first stream seeds silently");

        // While disconnected p1 blocked and p3 appeared; p2 did not change.
        let missed = store.relay_resync(
            "home",
            vec![
                status("home/p1", AgentStatus::Blocked),
                status("home/p2", AgentStatus::Idle),
                status("home/p3", AgentStatus::Working),
            ],
            RelayResync::Diff,
            now,
        );
        assert_eq!(
            missed
                .iter()
                .map(|event| (event.pane_id.as_str(), event.agent_status))
                .collect::<Vec<_>>(),
            vec![
                ("home/p1", AgentStatus::Blocked),
                ("home/p3", AgentStatus::Working)
            ]
        );
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Blocked);
        // The stream then delivers the same transition: it is not repeated,
        // while a genuinely new one is.
        assert!(!store.relay_status("home", &status("home/p1", AgentStatus::Blocked), now));
        assert!(store.relay_status("home", &status("home/p1", AgentStatus::Working), now));
        // A second resync with nothing new reports nothing.
        assert!(store
            .relay_resync(
                "home",
                vec![
                    status("home/p1", AgentStatus::Working),
                    status("home/p2", AgentStatus::Idle),
                    status("home/p3", AgentStatus::Working),
                ],
                RelayResync::Diff,
                now,
            )
            .is_empty());
        // After a peer restart every current pane is reported.
        assert_eq!(
            store
                .relay_resync(
                    "home",
                    vec![status("home/p1", AgentStatus::Working)],
                    RelayResync::Reset,
                    now,
                )
                .len(),
            1
        );
    }
}
