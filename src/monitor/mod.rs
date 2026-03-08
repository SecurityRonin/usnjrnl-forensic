//! Real-time USN Journal monitoring via FSCTL_READ_USN_JOURNAL.
//!
//! Provides a cross-platform abstraction layer for monitoring new journal entries.
//! The actual Windows FSCTL implementation lives behind a `cfg(target_os = "windows")` gate.

use std::time::Duration;

use anyhow::Result;

use crate::usn::{parse_usn_journal, UsnRecord};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Configuration for the journal monitor.
pub struct MonitorConfig {
    /// How often to poll for new journal entries.
    pub poll_interval: Duration,
    /// Size of the read buffer in bytes.
    pub buffer_size: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            buffer_size: 64 * 1024, // 64 KB
        }
    }
}

// ─── Events ─────────────────────────────────────────────────────────────────

/// Events emitted by the journal monitor.
#[derive(Debug)]
pub enum MonitorEvent {
    /// A new USN record was parsed from the journal.
    NewRecord(UsnRecord),
    /// The journal has wrapped: USN went backward, indicating the journal
    /// was recycled or truncated.
    JournalWrap { old_usn: i64, new_usn: i64 },
    /// An error occurred while reading or parsing journal data.
    Error(String),
}

// ─── Journal data source trait ──────────────────────────────────────────────

/// Trait abstracting the journal data source. Allows mocking in tests
/// and swapping between live Windows FSCTL and offline replay.
pub trait JournalSource {
    /// Read journal data starting from `start_usn` into `buffer`.
    /// Returns the number of bytes read.
    fn read_from_usn(&mut self, start_usn: i64, buffer: &mut [u8]) -> Result<usize>;

    /// Return the current journal ID (to detect journal deletion/recreation).
    fn current_journal_id(&self) -> Result<u64>;
}

// ─── Monitor ────────────────────────────────────────────────────────────────

/// Monitors a USN journal for new entries by polling a `JournalSource`.
pub struct JournalMonitor<S: JournalSource> {
    config: MonitorConfig,
    source: S,
    last_usn: i64,
    _journal_id: u64,
}

impl<S: JournalSource> JournalMonitor<S> {
    /// Create a new monitor with the given source and config.
    pub fn new(source: S, config: MonitorConfig) -> Result<Self> {
        let journal_id = source.current_journal_id()?;
        Ok(Self {
            config,
            source,
            last_usn: 0,
            _journal_id: journal_id,
        })
    }

    /// Return the last USN that was processed.
    pub fn last_usn(&self) -> i64 {
        self.last_usn
    }

    /// Return a reference to the config.
    pub fn config(&self) -> &MonitorConfig {
        &self.config
    }

    /// Poll once for new journal entries. Reads from the source starting at
    /// `last_usn`, parses any USN records found, and returns events.
    pub fn poll_once(&mut self) -> Vec<MonitorEvent> {
        let mut events = Vec::new();
        let mut buffer = vec![0u8; self.config.buffer_size];

        let bytes_read = match self.source.read_from_usn(self.last_usn, &mut buffer) {
            Ok(n) => n,
            Err(e) => {
                events.push(MonitorEvent::Error(e.to_string()));
                return events;
            }
        };

        if bytes_read == 0 {
            return events;
        }

        let data = &buffer[..bytes_read];
        let records = match parse_usn_journal(data) {
            Ok(r) => r,
            Err(e) => {
                events.push(MonitorEvent::Error(e.to_string()));
                return events;
            }
        };

        for record in records {
            // Detect journal wrap: if a record's USN is less than our last_usn,
            // the journal has wrapped around.
            if record.usn < self.last_usn {
                events.push(MonitorEvent::JournalWrap {
                    old_usn: self.last_usn,
                    new_usn: record.usn,
                });
            }

            // Update last_usn to the highest USN seen
            if record.usn > self.last_usn {
                self.last_usn = record.usn;
            }

            events.push(MonitorEvent::NewRecord(record));
        }

        events
    }
}

// ─── Windows implementation stub ────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows;

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock journal source ─────────────────────────────────────────────

    /// A mock journal source that returns pre-built USN record bytes.
    struct MockJournalSource {
        /// Data to return on the next read_from_usn call.
        data: Vec<u8>,
        journal_id: u64,
    }

    impl MockJournalSource {
        fn new(data: Vec<u8>, journal_id: u64) -> Self {
            Self { data, journal_id }
        }

        fn empty() -> Self {
            Self::new(Vec::new(), 1)
        }
    }

    impl JournalSource for MockJournalSource {
        fn read_from_usn(&mut self, _start_usn: i64, buffer: &mut [u8]) -> Result<usize> {
            let n = self.data.len().min(buffer.len());
            buffer[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }

        fn current_journal_id(&self) -> Result<u64> {
            Ok(self.journal_id)
        }
    }

    // ── Helper: build a V2 record with a specific USN value ─────────────

    fn build_v2_record_with_usn(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        usn: i64,
        reason: u32,
        filename: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        // Record length
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        // Major version = 2
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Minor version = 0
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // File reference
        let file_ref = entry | ((seq as u64) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        // Parent reference
        let parent_ref = parent_entry | ((parent_seq as u64) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        // USN
        buf[0x18..0x20].copy_from_slice(&usn.to_le_bytes());
        // Timestamp: 2024-01-15 12:00:00 UTC
        let ts: i64 = 133500480000000000;
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        // Reason
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        // Source info
        buf[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
        // Security ID
        buf[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        // File attributes (ARCHIVE)
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        // Filename length
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // Filename offset
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        // Filename UTF-16LE
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        buf
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_monitor_config_defaults() {
        let config = MonitorConfig::default();
        assert_eq!(config.poll_interval, Duration::from_millis(100));
        assert_eq!(config.buffer_size, 64 * 1024);
    }

    #[test]
    fn test_monitor_config_custom() {
        let config = MonitorConfig {
            poll_interval: Duration::from_millis(500),
            buffer_size: 128 * 1024,
        };
        assert_eq!(config.poll_interval, Duration::from_millis(500));
        assert_eq!(config.buffer_size, 128 * 1024);
    }

    #[test]
    fn test_monitor_event_callback() {
        // Verify MonitorEvent enum has all three variants and they can be constructed.
        let record_data = build_v2_record_with_usn(100, 1, 5, 5, 1000, 0x100, "test.txt");
        let records = parse_usn_journal(&record_data).unwrap();
        assert_eq!(records.len(), 1);

        let new_record = MonitorEvent::NewRecord(records.into_iter().next().unwrap());
        assert!(matches!(new_record, MonitorEvent::NewRecord(_)));

        let wrap = MonitorEvent::JournalWrap {
            old_usn: 5000,
            new_usn: 100,
        };
        assert!(matches!(
            wrap,
            MonitorEvent::JournalWrap {
                old_usn: 5000,
                new_usn: 100
            }
        ));

        let error = MonitorEvent::Error("test error".to_string());
        assert!(matches!(error, MonitorEvent::Error(_)));
    }

    #[test]
    fn test_monitor_processes_new_data() {
        // Given a mock data source with two records, monitor should parse them.
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_with_usn(
            100,
            1,
            5,
            5,
            1000,
            0x100,
            "file1.txt",
        ));
        data.extend_from_slice(&build_v2_record_with_usn(
            200,
            1,
            5,
            5,
            2000,
            0x200,
            "file2.txt",
        ));

        let source = MockJournalSource::new(data, 1);
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        let events = monitor.poll_once();
        let new_records: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MonitorEvent::NewRecord(_)))
            .collect();
        assert_eq!(new_records.len(), 2);

        // Verify filenames
        if let MonitorEvent::NewRecord(ref r) = new_records[0] {
            assert_eq!(r.filename, "file1.txt");
        }
        if let MonitorEvent::NewRecord(ref r) = new_records[1] {
            assert_eq!(r.filename, "file2.txt");
        }
    }

    #[test]
    fn test_monitor_tracks_last_usn() {
        // After processing records, last_usn should be updated to the highest USN seen.
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_with_usn(
            100, 1, 5, 5, 1000, 0x100, "a.txt",
        ));
        data.extend_from_slice(&build_v2_record_with_usn(
            200, 1, 5, 5, 5000, 0x200, "b.txt",
        ));

        let source = MockJournalSource::new(data, 1);
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        assert_eq!(monitor.last_usn(), 0);
        monitor.poll_once();
        assert_eq!(monitor.last_usn(), 5000);
    }

    #[test]
    fn test_monitor_detects_journal_wrap() {
        // When a record has a USN lower than last_usn, it indicates journal wrap.
        // First, set up a monitor that has already processed some records.
        let first_data = build_v2_record_with_usn(100, 1, 5, 5, 5000, 0x100, "before.txt");
        let source = MockJournalSource::new(first_data, 1);
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();
        monitor.poll_once();
        assert_eq!(monitor.last_usn(), 5000);

        // Now feed data with a lower USN (journal wrapped).
        let wrap_data = build_v2_record_with_usn(300, 1, 5, 5, 100, 0x100, "wrapped.txt");
        monitor.source = MockJournalSource::new(wrap_data, 1);
        let events = monitor.poll_once();

        let wraps: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MonitorEvent::JournalWrap { .. }))
            .collect();
        assert_eq!(wraps.len(), 1);

        if let MonitorEvent::JournalWrap { old_usn, new_usn } = wraps[0] {
            assert_eq!(*old_usn, 5000);
            assert_eq!(*new_usn, 100);
        } else {
            panic!("Expected JournalWrap event");
        }
    }

    #[test]
    fn test_monitor_handles_empty_read() {
        // No new data means no events.
        let source = MockJournalSource::empty();
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        let events = monitor.poll_once();
        assert!(events.is_empty());
    }

    #[test]
    fn test_monitor_config_accessor() {
        let config = MonitorConfig {
            poll_interval: Duration::from_millis(250),
            buffer_size: 32 * 1024,
        };
        let source = MockJournalSource::empty();
        let monitor = JournalMonitor::new(source, config).unwrap();
        assert_eq!(monitor.config().poll_interval, Duration::from_millis(250));
        assert_eq!(monitor.config().buffer_size, 32 * 1024);
    }

    /// A mock journal source that returns an error.
    struct ErrorJournalSource;

    impl JournalSource for ErrorJournalSource {
        fn read_from_usn(&mut self, _start_usn: i64, _buffer: &mut [u8]) -> Result<usize> {
            anyhow::bail!("Mock read error")
        }

        fn current_journal_id(&self) -> Result<u64> {
            Ok(42)
        }
    }

    #[test]
    fn test_monitor_handles_read_error() {
        let source = ErrorJournalSource;
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        let events = monitor.poll_once();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], MonitorEvent::Error(_)));
    }

    /// A mock source that returns corrupt data (non-parseable).
    struct CorruptJournalSource;

    impl JournalSource for CorruptJournalSource {
        fn read_from_usn(&mut self, _start_usn: i64, buffer: &mut [u8]) -> Result<usize> {
            // Fill with garbage that looks like a record but isn't
            let n = 64.min(buffer.len());
            for item in buffer.iter_mut().take(n) {
                *item = 0xDE;
            }
            // Make it look like a valid record header but with corrupt data
            buffer[0..4].copy_from_slice(&(0x40u32).to_le_bytes()); // record_len
            buffer[4..6].copy_from_slice(&2u16.to_le_bytes()); // version 2
            buffer[6..8].copy_from_slice(&0u16.to_le_bytes()); // minor version
            Ok(n)
        }

        fn current_journal_id(&self) -> Result<u64> {
            Ok(42)
        }
    }

    #[test]
    fn test_monitor_handles_corrupt_data() {
        let source = CorruptJournalSource;
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        let events = monitor.poll_once();
        // Corrupt data may produce empty events or error events, either is fine
        // Just make sure it doesn't panic
        let _ = events;
    }

    /// A mock source that returns data that will cause parse_usn_journal
    /// to return an error. Since parse_usn_journal basically never returns Err
    /// (it returns Ok with empty vec for corrupt data), we need to trick it.
    /// Actually, parse_usn_journal always returns Ok. Lines 111-113 are
    /// unreachable in practice because parse_usn_journal never returns Err.
    /// Let me still add a test that exercises as close to that path as possible.
    struct AlmostCorruptJournalSource;

    impl JournalSource for AlmostCorruptJournalSource {
        fn read_from_usn(&mut self, _start_usn: i64, buffer: &mut [u8]) -> Result<usize> {
            // Return data that parse_usn_journal handles gracefully (no error)
            // but produces no records
            let n = 64.min(buffer.len());
            for item in buffer.iter_mut().take(n) {
                *item = 0xFF;
            }
            Ok(n)
        }

        fn current_journal_id(&self) -> Result<u64> {
            Ok(42)
        }
    }

    #[test]
    fn test_monitor_handles_all_garbage_data() {
        // Tests that poll_once handles data that produces no records
        let source = AlmostCorruptJournalSource;
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        let events = monitor.poll_once();
        // No records parsed from garbage, so no NewRecord events
        let new_records: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MonitorEvent::NewRecord(_)))
            .collect();
        assert_eq!(new_records.len(), 0);
    }

    /// A mock source that returns data which causes parse_usn_journal to fail.
    /// parse_usn_journal currently always returns Ok, so this exercises the
    /// parse path as closely as possible. To actually trigger lines 111-113,
    /// we need parse_usn_journal to return Err. Let's use a source that returns
    /// data that will produce an error if we can find a way.
    ///
    /// Actually, looking at parse_usn_journal, it always returns Ok(records).
    /// Lines 111-113 are defensive code for future-proofing. The test below
    /// still exercises the closest possible path.
    struct ParseFailSource {
        data: Vec<u8>,
    }

    impl JournalSource for ParseFailSource {
        fn read_from_usn(&mut self, _start_usn: i64, buffer: &mut [u8]) -> Result<usize> {
            let n = self.data.len().min(buffer.len());
            buffer[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }

        fn current_journal_id(&self) -> Result<u64> {
            Ok(42)
        }
    }

    #[test]
    fn test_monitor_parse_returns_no_records_from_garbage() {
        // Exercises the parse path with data that produces no records.
        // Lines 111-113 are unreachable since parse_usn_journal never returns Err,
        // but this confirms that garbage data produces no NewRecord events.
        let mut garbage = vec![0xFFu8; 128];
        // Make it look non-zero so bytes_read > 0
        garbage[0..4].copy_from_slice(&(0x40u32).to_le_bytes());
        garbage[4..6].copy_from_slice(&99u16.to_le_bytes()); // unknown version

        let source = ParseFailSource { data: garbage };
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();

        let events = monitor.poll_once();
        let new_records: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MonitorEvent::NewRecord(_)))
            .collect();
        assert_eq!(
            new_records.len(),
            0,
            "Garbage data should produce no records"
        );
    }

    #[test]
    fn test_monitor_last_usn_not_updated_on_wrap() {
        // When journal wraps, the new USN is lower than last_usn
        // last_usn should NOT decrease (it tracks highest seen)
        let first_data = build_v2_record_with_usn(100, 1, 5, 5, 5000, 0x100, "before.txt");
        let source = MockJournalSource::new(first_data, 1);
        let mut monitor = JournalMonitor::new(source, MonitorConfig::default()).unwrap();
        monitor.poll_once();
        assert_eq!(monitor.last_usn(), 5000);

        // Feed wrapped data with USN=100
        let wrap_data = build_v2_record_with_usn(300, 1, 5, 5, 100, 0x100, "wrapped.txt");
        monitor.source = MockJournalSource::new(wrap_data, 1);
        monitor.poll_once();
        // last_usn should remain at 5000 since 100 < 5000
        assert_eq!(monitor.last_usn(), 5000);
    }
}
