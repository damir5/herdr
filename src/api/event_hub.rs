use std::collections::VecDeque;

use crate::api::schema::EventEnvelope;

#[derive(Clone, Default)]
pub struct EventHub {
    inner: std::sync::Arc<std::sync::Mutex<EventHubState>>,
}

#[derive(Default)]
struct EventHubState {
    /// Sequence number of the newest event pushed.
    next_sequence: u64,
    /// Sequence number of the newest event evicted from the ring.
    evicted_through: u64,
    /// Sequence number of the newest non-relayed event evicted from the ring:
    /// all a `local_only` reader can have missed.
    local_evicted_through: u64,
    events: VecDeque<HubEvent>,
}

struct HubEvent {
    sequence: u64,
    envelope: EventEnvelope,
    /// Pushed by the federation event relay from a peer rather than raised by
    /// this server. Local subscribers see it like any other event; a
    /// `local_only` subscription (a coordinator relaying this server) does not,
    /// so relayed events are never re-exported to another coordinator.
    relayed: bool,
}

/// Events retained after a cursor, read under one lock.
#[derive(Debug)]
pub struct EventBatch {
    /// Hub sequence at the time of the read: the reader's next cursor.
    pub head: u64,
    /// Set when events after the cursor were evicted before this read.
    pub missed: Option<MissedEvents>,
    pub events: Vec<(u64, EventEnvelope)>,
}

/// Sequence range a reader could no longer see because the ring evicted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissedEvents {
    pub first: u64,
    pub last: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EventHistoryError {
    Lost,
    Unavailable,
}

impl EventHub {
    /// Retained events shared by every subscriber. Subscription streams drain
    /// everything new every 100 ms, so only a reader that stops reading (a
    /// stalled socket write to a suspended phone, for example) falls behind.
    /// At the ~50 events/s a coordinator relaying several busy machines can
    /// sustain, 4096 events keep more than a minute of history, longer than the
    /// 40 s federation idle timeout, while typical envelopes keep the ring to a
    /// few MiB.
    pub(crate) const MAX_EVENTS: usize = 4096;

    pub fn push(&self, event: EventEnvelope) {
        self.push_marked(event, false);
    }

    /// Push an event the federation relay received from a peer; see
    /// [`HubEvent::relayed`].
    pub fn push_relayed(&self, event: EventEnvelope) {
        self.push_marked(event, true);
    }

    fn push_marked(&self, envelope: EventEnvelope, relayed: bool) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        state.next_sequence += 1;
        let sequence = state.next_sequence;
        state.events.push_back(HubEvent {
            sequence,
            envelope,
            relayed,
        });
        while state.events.len() > Self::MAX_EVENTS {
            if let Some(evicted) = state.events.pop_front() {
                state.evicted_through = evicted.sequence;
                if !evicted.relayed {
                    state.local_evicted_through = evicted.sequence;
                }
            }
        }
    }

    pub fn events_after(&self, sequence: u64) -> Vec<(u64, EventEnvelope)> {
        let Ok(state) = self.inner.lock() else {
            return Vec::new();
        };
        state.events_after(sequence)
    }

    /// Events after `cursor` together with the head to resume from and whether
    /// the ring dropped anything the reader had not seen yet.
    pub fn read_after(&self, cursor: u64) -> EventBatch {
        self.read_batch(cursor, true)
    }

    fn read_batch(&self, cursor: u64, include_relayed: bool) -> EventBatch {
        self.read_checked(cursor, include_relayed)
            .unwrap_or_else(|_| EventBatch {
                head: cursor,
                missed: None,
                events: Vec::new(),
            })
    }

    /// [`Self::read_after`] (or, without `include_relayed`, only the events
    /// this server produced itself) that reports a poisoned history as
    /// [`EventHistoryError::Unavailable`] instead of an empty batch. A batch
    /// whose `missed` is set is what [`EventHistoryError::Lost`] describes; the
    /// subscription stream decides whether that ends the stream.
    pub(super) fn read_checked(
        &self,
        cursor: u64,
        include_relayed: bool,
    ) -> Result<EventBatch, EventHistoryError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| EventHistoryError::Unavailable)?;
        Ok(state.batch_after(cursor, include_relayed))
    }

    pub fn current_sequence(&self) -> u64 {
        let Ok(state) = self.inner.lock() else {
            return 0;
        };
        state.next_sequence
    }
}

impl EventHubState {
    fn retained_after(&self, sequence: u64) -> impl Iterator<Item = &HubEvent> {
        let start = self
            .events
            .partition_point(|event| event.sequence <= sequence);
        self.events.range(start..)
    }

    fn events_after(&self, sequence: u64) -> Vec<(u64, EventEnvelope)> {
        self.retained_after(sequence)
            .map(|event| (event.sequence, event.envelope.clone()))
            .collect()
    }

    fn batch_after(&self, cursor: u64, include_relayed: bool) -> EventBatch {
        // A local reader never sees relayed events, so losing only those is no
        // gap for it.
        let evicted_through = if include_relayed {
            self.evicted_through
        } else {
            self.local_evicted_through
        };
        EventBatch {
            head: self.next_sequence,
            missed: (evicted_through > cursor).then_some(MissedEvents {
                first: cursor + 1,
                last: evicted_through,
            }),
            events: self
                .retained_after(cursor)
                .filter(|event| include_relayed || !event.relayed)
                .map(|event| (event.sequence, event.envelope.clone()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::{EventData, EventKind};

    fn focused(workspace_id: &str) -> EventEnvelope {
        EventEnvelope {
            event: EventKind::WorkspaceFocused,
            data: EventData::WorkspaceFocused {
                workspace_id: workspace_id.into(),
            },
        }
    }

    #[test]
    fn read_after_reports_evicted_range_only_when_reader_missed_it() {
        let hub = EventHub::default();
        for index in 0..EventHub::MAX_EVENTS + 3 {
            hub.push(focused(&index.to_string()));
        }

        let behind = hub.read_after(1);
        assert_eq!(behind.missed, Some(MissedEvents { first: 2, last: 3 }));
        assert_eq!(
            behind.events.first().map(|(sequence, _)| *sequence),
            Some(4)
        );
        assert_eq!(behind.events.len(), EventHub::MAX_EVENTS);

        let current = hub.read_after(3);
        assert_eq!(current.missed, None);
        assert_eq!(current.events.len(), EventHub::MAX_EVENTS);
        assert_eq!(current.head, (EventHub::MAX_EVENTS + 3) as u64);
    }

    #[test]
    fn local_reads_skip_relayed_events_but_keep_the_shared_sequence() {
        let hub = EventHub::default();
        hub.push(focused("local-1"));
        hub.push_relayed(focused("peer/w1"));
        hub.push(focused("local-2"));

        let local = hub.read_checked(0, false).unwrap();
        assert_eq!(local.head, 3);
        assert_eq!(
            local
                .events
                .iter()
                .map(|(sequence, _)| *sequence)
                .collect::<Vec<_>>(),
            vec![1, 3],
            "a relayed event must never be served to a relaying coordinator"
        );
        assert_eq!(hub.read_after(0).events.len(), 3);
    }

    #[test]
    fn local_reads_lag_only_when_a_local_event_was_evicted() {
        let hub = EventHub::default();
        hub.push(focused("local-1"));
        for index in 0..EventHub::MAX_EVENTS + 2 {
            hub.push_relayed(focused(&format!("peer/w{index}")));
        }

        // Seen through the local event; only relayed events were lost since.
        assert_eq!(hub.read_checked(1, false).unwrap().missed, None);
        assert_eq!(
            hub.read_after(1).missed,
            Some(MissedEvents { first: 2, last: 3 })
        );
        // A local reader that had not seen the local event did miss it.
        assert_eq!(
            hub.read_checked(0, false).unwrap().missed,
            Some(MissedEvents { first: 1, last: 1 })
        );
    }

    #[test]
    fn checked_history_distinguishes_retained_boundary_from_lost_events() {
        let hub = EventHub::default();
        let empty = hub.read_checked(0, true).unwrap();
        assert!(empty.events.is_empty() && empty.missed.is_none());
        for index in 0..EventHub::MAX_EVENTS {
            hub.push(focused(&index.to_string()));
        }
        let full = hub.read_checked(0, true).unwrap();
        assert_eq!(full.missed, None);
        assert_eq!(full.events.len(), EventHub::MAX_EVENTS);
        hub.push(focused("overflow"));
        assert_eq!(
            hub.read_checked(0, true).unwrap().missed,
            Some(MissedEvents { first: 1, last: 1 })
        );
        let retained = hub.read_checked(1, true).unwrap();
        assert_eq!(retained.missed, None);
        assert_eq!(retained.events.len(), EventHub::MAX_EVENTS);
        assert_eq!(retained.events.first().unwrap().0, 2);
        assert_eq!(retained.events.last().unwrap().0, hub.current_sequence());
        assert!(hub
            .read_checked(hub.current_sequence(), true)
            .unwrap()
            .events
            .is_empty());
    }

    #[test]
    fn checked_history_reports_unavailable_instead_of_empty_after_poison() {
        let hub = EventHub::default();
        assert!(std::panic::catch_unwind(|| {
            let _guard = hub.inner.lock().unwrap();
            panic!("poison the test event history");
        })
        .is_err());
        assert!(matches!(
            hub.read_checked(0, true),
            Err(EventHistoryError::Unavailable)
        ));
    }
}
