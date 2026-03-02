//! TriForce correlation engine: MFT + $LogFile + $UsnJrnl.
//!
//! Cross-correlates three NTFS artifacts to produce a unified timeline
//! and detect evidence of anti-forensic activity (journal clearing,
//! timestomping, phantom file operations).

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

use crate::usn::{UsnRecord, UsnReason};
use crate::logfile::usn_extractor::LogFileUsnRecord;
use crate::mft::MftEntry;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Where a correlated event originated from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventSource {
    /// Found only in $UsnJrnl.
    UsnJournal,
    /// Found only in $LogFile.
    LogFile,
    /// Found in both $UsnJrnl and $LogFile.
    Both,
}

/// A single event in the unified timeline.
#[derive(Debug, Clone)]
pub struct CorrelatedEvent {
    /// The USN record for this event.
    pub record: UsnRecord,
    /// Where this event was found.
    pub source: EventSource,
    /// LSN from $LogFile (if available).
    pub lsn: Option<u64>,
}

/// A USN record found in $LogFile but absent from $UsnJrnl.
#[derive(Debug, Clone)]
pub struct GhostRecord {
    /// The recovered USN record.
    pub record: UsnRecord,
    /// LSN where it was found.
    pub lsn: u64,
}

/// Coverage analysis comparing $UsnJrnl and $LogFile time ranges.
#[derive(Debug, Clone)]
pub struct CoverageAnalysis {
    pub usn_earliest_ts: DateTime<Utc>,
    pub usn_latest_ts: DateTime<Utc>,
    pub usn_record_count: usize,
    pub logfile_earliest_ts: Option<DateTime<Utc>>,
    pub logfile_latest_ts: Option<DateTime<Utc>>,
    pub logfile_record_count: usize,
    /// True if $LogFile contains records older than the oldest $UsnJrnl record.
    pub logfile_extends_before_usn: bool,
}

/// Type of timestamp conflict between MFT and USN Journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampConflictType {
    /// $STANDARD_INFORMATION created timestamp predates USN FILE_CREATE.
    SiPredatesUsnCreate,
}

/// A detected timestamp conflict for a specific MFT entry.
#[derive(Debug, Clone)]
pub struct TimestampConflict {
    pub mft_entry: u64,
    pub filename: String,
    pub conflict_type: TimestampConflictType,
    pub si_timestamp: DateTime<Utc>,
    pub usn_timestamp: DateTime<Utc>,
}

/// Detected MFT entry reuse (same entry number, different sequence).
#[derive(Debug, Clone)]
pub struct EntryReuse {
    pub mft_entry: u64,
    pub old_sequence: u16,
    pub new_sequence: u16,
    pub old_filename: String,
    pub new_filename: String,
    pub reuse_timestamp: DateTime<Utc>,
}

/// High-level TriForce correlation report.
#[derive(Debug, Clone)]
pub struct TriForceReport {
    pub timeline_event_count: usize,
    pub ghost_record_count: usize,
    pub journal_clearing_suspected: bool,
    pub timestamp_conflict_count: usize,
    pub entry_reuse_count: usize,
    pub coverage: CoverageAnalysis,
}

/// Summary of all activity for a single file (MFT entry).
#[derive(Debug, Clone)]
pub struct FileActivitySummary {
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub filename: String,
    pub event_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Union of all reason flags seen for this file.
    pub reasons: UsnReason,
}

// ─── Engine ─────────────────────────────────────────────────────────────────

/// The TriForce correlation engine.
pub struct CorrelationEngine;

impl CorrelationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Build a unified, deduplicated, time-sorted timeline from all sources.
    pub fn build_timeline(
        &self,
        usn_records: &[UsnRecord],
        logfile_records: &[LogFileUsnRecord],
        _mft_entries: &[MftEntry],
    ) -> Vec<CorrelatedEvent> {
        // Index LogFile records by dedup key: (mft_entry, usn_offset, timestamp_secs)
        let mut logfile_by_key: HashMap<(u64, i64, i64), u64> = HashMap::new();
        for lr in logfile_records {
            let key = (lr.record.mft_entry, lr.record.usn, lr.record.timestamp.timestamp());
            logfile_by_key.insert(key, lr.lsn);
        }

        let mut events = Vec::new();
        let mut seen_keys: HashSet<(u64, i64, i64)> = HashSet::new();

        // Add USN journal records, marking duplicates as Both
        for r in usn_records {
            let key = (r.mft_entry, r.usn, r.timestamp.timestamp());
            let (source, lsn) = if let Some(&lsn) = logfile_by_key.get(&key) {
                (EventSource::Both, Some(lsn))
            } else {
                (EventSource::UsnJournal, None)
            };
            seen_keys.insert(key);
            events.push(CorrelatedEvent {
                record: r.clone(),
                source,
                lsn,
            });
        }

        // Add LogFile-only records
        for lr in logfile_records {
            let key = (lr.record.mft_entry, lr.record.usn, lr.record.timestamp.timestamp());
            if !seen_keys.contains(&key) {
                events.push(CorrelatedEvent {
                    record: lr.record.clone(),
                    source: EventSource::LogFile,
                    lsn: Some(lr.lsn),
                });
            }
        }

        // Sort by timestamp
        events.sort_by_key(|e| e.record.timestamp);
        events
    }

    /// Find "ghost" records: USN records in $LogFile but absent from $UsnJrnl.
    pub fn find_ghost_records(
        &self,
        usn_records: &[UsnRecord],
        logfile_records: &[LogFileUsnRecord],
    ) -> Vec<GhostRecord> {
        let usn_keys: HashSet<(u64, i64, i64)> = usn_records
            .iter()
            .map(|r| (r.mft_entry, r.usn, r.timestamp.timestamp()))
            .collect();

        logfile_records
            .iter()
            .filter(|lr| {
                let key = (lr.record.mft_entry, lr.record.usn, lr.record.timestamp.timestamp());
                !usn_keys.contains(&key)
            })
            .map(|lr| GhostRecord {
                record: lr.record.clone(),
                lsn: lr.lsn,
            })
            .collect()
    }

    /// Analyze temporal coverage of $UsnJrnl vs $LogFile USN records.
    pub fn analyze_coverage(
        &self,
        usn_records: &[UsnRecord],
        logfile_records: &[LogFileUsnRecord],
    ) -> CoverageAnalysis {
        let usn_record_count = usn_records.len();
        let logfile_record_count = logfile_records.len();

        let usn_earliest = usn_records.iter().map(|r| r.timestamp).min();
        let usn_latest = usn_records.iter().map(|r| r.timestamp).max();

        let lf_earliest = logfile_records.iter().map(|r| r.record.timestamp).min();
        let lf_latest = logfile_records.iter().map(|r| r.record.timestamp).max();

        let epoch = DateTime::from_timestamp(0, 0).unwrap();

        let logfile_extends_before_usn = match (usn_earliest, lf_earliest) {
            (Some(usn_e), Some(lf_e)) => lf_e < usn_e,
            _ => false,
        };

        CoverageAnalysis {
            usn_earliest_ts: usn_earliest.unwrap_or(epoch),
            usn_latest_ts: usn_latest.unwrap_or(epoch),
            usn_record_count,
            logfile_earliest_ts: lf_earliest,
            logfile_latest_ts: lf_latest,
            logfile_record_count,
            logfile_extends_before_usn,
        }
    }

    /// Find timestamp conflicts between MFT $SI timestamps and USN FILE_CREATE events.
    pub fn find_timestamp_conflicts(
        &self,
        usn_records: &[UsnRecord],
        mft_entries: &[MftEntry],
    ) -> Vec<TimestampConflict> {
        // Index: for each MFT entry, find the earliest USN FILE_CREATE timestamp
        let mut create_ts: HashMap<u64, DateTime<Utc>> = HashMap::new();
        for r in usn_records {
            if r.reason.contains(UsnReason::FILE_CREATE) {
                create_ts
                    .entry(r.mft_entry)
                    .and_modify(|existing| {
                        if r.timestamp < *existing {
                            *existing = r.timestamp;
                        }
                    })
                    .or_insert(r.timestamp);
            }
        }

        let mut conflicts = Vec::new();
        for entry in mft_entries {
            if let Some(&usn_create_ts) = create_ts.get(&entry.entry_number) {
                if let Some(si_created) = entry.si_created {
                    // SI_Created significantly before USN FILE_CREATE = timestomped
                    if si_created < usn_create_ts
                        && (usn_create_ts - si_created).num_seconds() > 2
                    {
                        conflicts.push(TimestampConflict {
                            mft_entry: entry.entry_number,
                            filename: entry.filename.clone(),
                            conflict_type: TimestampConflictType::SiPredatesUsnCreate,
                            si_timestamp: si_created,
                            usn_timestamp: usn_create_ts,
                        });
                    }
                }
            }
        }
        conflicts
    }

    /// Detect MFT entry reuse: same entry number with different sequence numbers.
    pub fn detect_entry_reuse(&self, usn_records: &[UsnRecord]) -> Vec<EntryReuse> {
        // Track last-seen sequence for each entry, sorted by timestamp
        let mut sorted: Vec<&UsnRecord> = usn_records.iter().collect();
        sorted.sort_by_key(|r| r.timestamp);

        let mut last_seen: HashMap<u64, (u16, String)> = HashMap::new();
        let mut reuses = Vec::new();

        for r in sorted {
            if let Some((prev_seq, prev_name)) = last_seen.get(&r.mft_entry) {
                if *prev_seq != r.mft_sequence {
                    reuses.push(EntryReuse {
                        mft_entry: r.mft_entry,
                        old_sequence: *prev_seq,
                        new_sequence: r.mft_sequence,
                        old_filename: prev_name.clone(),
                        new_filename: r.filename.clone(),
                        reuse_timestamp: r.timestamp,
                    });
                }
            }
            last_seen.insert(r.mft_entry, (r.mft_sequence, r.filename.clone()));
        }

        reuses
    }

    /// Generate a high-level TriForce correlation report.
    pub fn generate_report(
        &self,
        usn_records: &[UsnRecord],
        logfile_records: &[LogFileUsnRecord],
        mft_entries: &[MftEntry],
    ) -> TriForceReport {
        let timeline = self.build_timeline(usn_records, logfile_records, mft_entries);
        let ghosts = self.find_ghost_records(usn_records, logfile_records);
        let coverage = self.analyze_coverage(usn_records, logfile_records);
        let conflicts = self.find_timestamp_conflicts(usn_records, mft_entries);
        let reuses = self.detect_entry_reuse(usn_records);

        TriForceReport {
            timeline_event_count: timeline.len(),
            ghost_record_count: ghosts.len(),
            journal_clearing_suspected: coverage.logfile_extends_before_usn || !ghosts.is_empty(),
            timestamp_conflict_count: conflicts.len(),
            entry_reuse_count: reuses.len(),
            coverage,
        }
    }

    /// Summarize all USN activity grouped by MFT entry number.
    pub fn summarize_file_activity(
        &self,
        usn_records: &[UsnRecord],
    ) -> Vec<FileActivitySummary> {
        let mut map: HashMap<(u64, u16), FileActivitySummary> = HashMap::new();

        for r in usn_records {
            let key = (r.mft_entry, r.mft_sequence);
            map.entry(key)
                .and_modify(|s| {
                    s.event_count += 1;
                    if r.timestamp < s.first_seen {
                        s.first_seen = r.timestamp;
                    }
                    if r.timestamp > s.last_seen {
                        s.last_seen = r.timestamp;
                    }
                    s.reasons |= r.reason;
                    // Use latest filename (handles renames)
                    s.filename = r.filename.clone();
                })
                .or_insert(FileActivitySummary {
                    mft_entry: r.mft_entry,
                    mft_sequence: r.mft_sequence,
                    filename: r.filename.clone(),
                    event_count: 1,
                    first_seen: r.timestamp,
                    last_seen: r.timestamp,
                    reasons: r.reason,
                });
        }

        let mut result: Vec<_> = map.into_values().collect();
        result.sort_by_key(|s| s.first_seen);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{UsnRecord, UsnReason, FileAttributes};
    use crate::logfile::usn_extractor::{LogFileUsnRecord, LogFileRecordSource};
    use crate::mft::MftEntry;
    use chrono::DateTime;

    /// Helper: build a minimal UsnRecord for testing.
    fn usn(entry: u64, seq: u16, parent: u64, usn_offset: i64, ts_secs: i64, name: &str, reason: UsnReason) -> UsnRecord {
        UsnRecord {
            mft_entry: entry,
            mft_sequence: seq,
            parent_mft_entry: parent,
            parent_mft_sequence: 1,
            usn: usn_offset,
            timestamp: DateTime::from_timestamp(ts_secs, 0).unwrap(),
            reason,
            filename: name.into(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    /// Helper: wrap a UsnRecord into a LogFileUsnRecord.
    fn logfile_usn(record: UsnRecord, lsn: u64) -> LogFileUsnRecord {
        LogFileUsnRecord {
            lsn,
            page_offset: 0,
            source: LogFileRecordSource::RedoData,
            record,
        }
    }

    /// Helper: build a minimal MftEntry for testing.
    fn mft_entry(entry: u64, seq: u16, parent: u64, name: &str, is_dir: bool) -> MftEntry {
        MftEntry {
            entry_number: entry,
            sequence_number: seq,
            filename: name.into(),
            parent_entry: parent,
            parent_sequence: 1,
            is_directory: is_dir,
            is_in_use: true,
            si_created: None,
            si_modified: None,
            si_mft_modified: None,
            si_accessed: None,
            fn_created: None,
            fn_modified: None,
            fn_mft_modified: None,
            fn_accessed: None,
            full_path: format!(".\\{}", name),
            file_size: 0,
            has_ads: false,
        }
    }

    // ─── Test 1: Create engine and build unified timeline ────────────────

    #[test]
    fn test_unified_timeline_from_usn_only() {
        let records = vec![
            usn(100, 1, 50, 1000, 1700000000, "file1.txt", UsnReason::FILE_CREATE),
            usn(101, 1, 50, 2000, 1700000100, "file2.txt", UsnReason::FILE_CREATE),
        ];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&records, &[], &[]);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].source, EventSource::UsnJournal);
        assert_eq!(timeline[1].source, EventSource::UsnJournal);
        // Timeline is sorted by timestamp
        assert!(timeline[0].record.timestamp <= timeline[1].record.timestamp);
    }

    // ─── Test 2: Merge LogFile USN records into timeline ─────────────────

    #[test]
    fn test_unified_timeline_merges_logfile_records() {
        let usn_records = vec![
            usn(100, 1, 50, 2000, 1700000200, "file1.txt", UsnReason::DATA_EXTEND),
        ];
        let logfile_records = vec![
            logfile_usn(
                usn(100, 1, 50, 1000, 1700000100, "file1.txt", UsnReason::FILE_CREATE),
                500,
            ),
        ];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&usn_records, &logfile_records, &[]);

        assert_eq!(timeline.len(), 2);
        // LogFile record came first chronologically
        assert_eq!(timeline[0].source, EventSource::LogFile);
        assert_eq!(timeline[1].source, EventSource::UsnJournal);
    }

    // ─── Test 3: Deduplicate records present in both sources ─────────────

    #[test]
    fn test_deduplication_when_record_in_both_sources() {
        // Same USN offset + same entry + same timestamp = duplicate
        let record = usn(100, 1, 50, 1000, 1700000100, "file1.txt", UsnReason::FILE_CREATE);
        let usn_records = vec![record.clone()];
        let logfile_records = vec![logfile_usn(record.clone(), 500)];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&usn_records, &logfile_records, &[]);

        // Should deduplicate into a single event marked as Both
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].source, EventSource::Both);
    }

    // ─── Test 4: Ghost records (in LogFile but not UsnJrnl) ──────────────

    #[test]
    fn test_ghost_records_detected() {
        // UsnJrnl starts at USN 5000 (journal was cleared/wrapped)
        let usn_records = vec![
            usn(200, 1, 50, 5000, 1700001000, "after.txt", UsnReason::FILE_CREATE),
        ];
        // LogFile has older records with USN < 5000
        let logfile_records = vec![
            logfile_usn(
                usn(100, 1, 50, 1000, 1700000100, "deleted_evidence.txt", UsnReason::FILE_CREATE),
                300,
            ),
            logfile_usn(
                usn(101, 1, 50, 2000, 1700000200, "wiped.exe", UsnReason::FILE_DELETE | UsnReason::CLOSE),
                400,
            ),
        ];

        let engine = CorrelationEngine::new();
        let ghosts = engine.find_ghost_records(&usn_records, &logfile_records);

        assert_eq!(ghosts.len(), 2);
        assert_eq!(ghosts[0].record.filename, "deleted_evidence.txt");
        assert_eq!(ghosts[1].record.filename, "wiped.exe");
    }

    // ─── Test 5: No ghosts when all LogFile records also in UsnJrnl ──────

    #[test]
    fn test_no_ghosts_when_fully_covered() {
        let record = usn(100, 1, 50, 1000, 1700000100, "file1.txt", UsnReason::FILE_CREATE);
        let usn_records = vec![record.clone()];
        let logfile_records = vec![logfile_usn(record, 500)];

        let engine = CorrelationEngine::new();
        let ghosts = engine.find_ghost_records(&usn_records, &logfile_records);

        assert_eq!(ghosts.len(), 0);
    }

    // ─── Test 6: Coverage analysis ───────────────────────────────────────

    #[test]
    fn test_coverage_analysis() {
        let usn_records = vec![
            usn(100, 1, 50, 1000, 1700000100, "a.txt", UsnReason::FILE_CREATE),
            usn(101, 1, 50, 5000, 1700000500, "b.txt", UsnReason::FILE_CREATE),
        ];
        let logfile_records = vec![
            logfile_usn(
                usn(99, 1, 50, 500, 1700000050, "early.txt", UsnReason::FILE_CREATE),
                100,
            ),
        ];

        let engine = CorrelationEngine::new();
        let coverage = engine.analyze_coverage(&usn_records, &logfile_records);

        // UsnJrnl range
        assert_eq!(coverage.usn_earliest_ts.timestamp(), 1700000100);
        assert_eq!(coverage.usn_latest_ts.timestamp(), 1700000500);
        assert_eq!(coverage.usn_record_count, 2);

        // LogFile range
        assert_eq!(coverage.logfile_earliest_ts.unwrap().timestamp(), 1700000050);
        assert_eq!(coverage.logfile_record_count, 1);

        // LogFile extends before UsnJrnl = evidence of clearing
        assert!(coverage.logfile_extends_before_usn);
    }

    // ─── Test 7: MFT cross-validation (timestomping detection) ──────────

    #[test]
    fn test_mft_usn_timestamp_conflicts() {
        // MFT says file was created at ts=1700000100
        let mut entry = mft_entry(100, 1, 50, "suspicious.exe", false);
        entry.si_created = Some(DateTime::from_timestamp(1700000100, 0).unwrap());
        entry.fn_created = Some(DateTime::from_timestamp(1700000500, 0).unwrap());

        // USN Journal says file was created at ts=1700000500
        let usn_records = vec![
            usn(100, 1, 50, 1000, 1700000500, "suspicious.exe", UsnReason::FILE_CREATE),
        ];

        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[entry]);

        // SI_Created (1700000100) predates the USN FILE_CREATE (1700000500) = timestomped
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].mft_entry, 100);
        assert_eq!(conflicts[0].conflict_type, TimestampConflictType::SiPredatesUsnCreate);
    }

    // ─── Test 8: No conflict when timestamps are consistent ──────────────

    #[test]
    fn test_no_conflict_when_timestamps_consistent() {
        let mut entry = mft_entry(100, 1, 50, "normal.txt", false);
        let ts = DateTime::from_timestamp(1700000500, 0).unwrap();
        entry.si_created = Some(ts);
        entry.fn_created = Some(ts);

        let usn_records = vec![
            usn(100, 1, 50, 1000, 1700000500, "normal.txt", UsnReason::FILE_CREATE),
        ];

        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[entry]);

        assert_eq!(conflicts.len(), 0);
    }

    // ─── Test 9: File activity summary per MFT entry ─────────────────────

    #[test]
    fn test_file_activity_summary() {
        let usn_records = vec![
            usn(100, 1, 50, 1000, 1700000100, "report.docx", UsnReason::FILE_CREATE),
            usn(100, 1, 50, 2000, 1700000200, "report.docx", UsnReason::DATA_EXTEND),
            usn(100, 1, 50, 3000, 1700000300, "report.docx", UsnReason::CLOSE),
            usn(100, 1, 50, 4000, 1700000400, "report.docx", UsnReason::DATA_EXTEND),
            usn(100, 1, 50, 5000, 1700000500, "report.docx", UsnReason::CLOSE),
        ];

        let engine = CorrelationEngine::new();
        let summaries = engine.summarize_file_activity(&usn_records);

        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.mft_entry, 100);
        assert_eq!(summary.filename, "report.docx");
        assert_eq!(summary.event_count, 5);
        assert_eq!(summary.first_seen.timestamp(), 1700000100);
        assert_eq!(summary.last_seen.timestamp(), 1700000500);
        assert!(summary.reasons.contains(UsnReason::FILE_CREATE));
        assert!(summary.reasons.contains(UsnReason::DATA_EXTEND));
        assert!(summary.reasons.contains(UsnReason::CLOSE));
    }

    // ─── Test 10: Empty inputs produce empty results ─────────────────────

    #[test]
    fn test_empty_inputs() {
        let engine = CorrelationEngine::new();

        let timeline = engine.build_timeline(&[], &[], &[]);
        assert!(timeline.is_empty());

        let ghosts = engine.find_ghost_records(&[], &[]);
        assert!(ghosts.is_empty());

        let coverage = engine.analyze_coverage(&[], &[]);
        assert_eq!(coverage.usn_record_count, 0);
        assert_eq!(coverage.logfile_record_count, 0);
        assert!(!coverage.logfile_extends_before_usn);
    }

    // ─── Test 11: Detect MFT entry reuse across USN records ─────────────

    #[test]
    fn test_detect_entry_reuse() {
        // Same MFT entry 100, but different sequence numbers = reused
        let usn_records = vec![
            usn(100, 3, 50, 1000, 1700000100, "old_file.txt", UsnReason::FILE_DELETE | UsnReason::CLOSE),
            usn(100, 4, 60, 2000, 1700000200, "new_file.exe", UsnReason::FILE_CREATE),
        ];

        let engine = CorrelationEngine::new();
        let reuses = engine.detect_entry_reuse(&usn_records);

        assert_eq!(reuses.len(), 1);
        assert_eq!(reuses[0].mft_entry, 100);
        assert_eq!(reuses[0].old_sequence, 3);
        assert_eq!(reuses[0].new_sequence, 4);
        assert_eq!(reuses[0].old_filename, "old_file.txt");
        assert_eq!(reuses[0].new_filename, "new_file.exe");
    }

    // ─── Test 12: No reuse when sequence stays the same ──────────────────

    #[test]
    fn test_no_reuse_same_sequence() {
        let usn_records = vec![
            usn(100, 3, 50, 1000, 1700000100, "file.txt", UsnReason::FILE_CREATE),
            usn(100, 3, 50, 2000, 1700000200, "file.txt", UsnReason::DATA_EXTEND),
        ];

        let engine = CorrelationEngine::new();
        let reuses = engine.detect_entry_reuse(&usn_records);
        assert!(reuses.is_empty());
    }

    // ─── Test 13: Full TriForce report ───────────────────────────────────

    #[test]
    fn test_triforce_report() {
        let usn_records = vec![
            usn(100, 1, 50, 5000, 1700001000, "current.txt", UsnReason::FILE_CREATE),
        ];
        let logfile_records = vec![
            logfile_usn(
                usn(99, 1, 50, 1000, 1700000100, "ghost.exe", UsnReason::FILE_CREATE),
                200,
            ),
        ];
        let mut entry = mft_entry(100, 1, 50, "current.txt", false);
        entry.si_created = Some(DateTime::from_timestamp(1700000500, 0).unwrap());

        let engine = CorrelationEngine::new();
        let report = engine.generate_report(&usn_records, &logfile_records, &[entry]);

        assert_eq!(report.timeline_event_count, 2);
        assert_eq!(report.ghost_record_count, 1);
        assert!(report.journal_clearing_suspected);
        assert_eq!(report.timestamp_conflict_count, 1);
    }

    // ─── Test 14: Multiple files activity summary is separated ───────────

    #[test]
    fn test_activity_summary_multiple_files() {
        let usn_records = vec![
            usn(100, 1, 50, 1000, 1700000100, "a.txt", UsnReason::FILE_CREATE),
            usn(101, 1, 50, 2000, 1700000200, "b.txt", UsnReason::FILE_CREATE),
            usn(100, 1, 50, 3000, 1700000300, "a.txt", UsnReason::CLOSE),
        ];

        let engine = CorrelationEngine::new();
        let summaries = engine.summarize_file_activity(&usn_records);

        assert_eq!(summaries.len(), 2);
        // Sorted by first_seen
        assert_eq!(summaries[0].mft_entry, 100);
        assert_eq!(summaries[0].event_count, 2);
        assert_eq!(summaries[1].mft_entry, 101);
        assert_eq!(summaries[1].event_count, 1);
    }

    // ─── Test 15: Timeline preserves LSN for LogFile records ─────────────

    #[test]
    fn test_timeline_preserves_lsn() {
        let logfile_records = vec![
            logfile_usn(
                usn(100, 1, 50, 1000, 1700000100, "file.txt", UsnReason::FILE_CREATE),
                42_000,
            ),
        ];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&[], &logfile_records, &[]);

        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].lsn, Some(42_000));
    }
}
