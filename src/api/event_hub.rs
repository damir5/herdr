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
    events: VecDeque<(u64, EventEnvelope)>,
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
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        state.next_sequence += 1;
        let sequence = state.next_sequence;
        state.events.push_back((sequence, event));
        while state.events.len() > Self::MAX_EVENTS {
            if let Some((evicted, _)) = state.events.pop_front() {
                state.evicted_through = evicted;
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
        let Ok(state) = self.inner.lock() else {
            return EventBatch {
                head: cursor,
                missed: None,
                events: Vec::new(),
            };
        };
        state.batch_after(cursor)
    }

    pub fn current_sequence(&self) -> u64 {
        let Ok(state) = self.inner.lock() else {
            return 0;
        };
        state.next_sequence
    }
}

impl EventHubState {
    fn events_after(&self, sequence: u64) -> Vec<(u64, EventEnvelope)> {
        let start = self
            .events
            .partition_point(|(event_sequence, _)| *event_sequence <= sequence);
        self.events.range(start..).cloned().collect()
    }

    fn batch_after(&self, cursor: u64) -> EventBatch {
        EventBatch {
            head: self.next_sequence,
            missed: (self.evicted_through > cursor).then_some(MissedEvents {
                first: cursor + 1,
                last: self.evicted_through,
            }),
            events: self.events_after(cursor),
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
}
