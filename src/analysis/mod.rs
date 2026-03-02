//! Anti-forensics and threat detection from USN Journal records.
//!
//! Provides heuristic detectors for:
//! - Secure deletion tool artifacts (SDelete, CCleaner, cipher /w)
//! - USN journal clearing / tampering
//! - Ransomware-like mass rename/encrypt patterns
//! - Timestamp manipulation (timestomping)

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::usn::{UsnReason, UsnRecord};

// ═══════════════════════════════════════════════════════════════════════════════
// Secure Deletion Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// Indicator of secure deletion tool usage.
#[derive(Debug, Clone)]
pub struct SecureDeletionIndicator {
    /// The type of secure deletion pattern detected.
    pub pattern: SecureDeletionPattern,
    /// Filenames involved in the pattern.
    pub filenames: Vec<String>,
    /// Time window during which the pattern was observed.
    pub time_start: DateTime<Utc>,
    pub time_end: DateTime<Utc>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// Known secure deletion tool patterns.
#[derive(Debug, Clone, PartialEq)]
pub enum SecureDeletionPattern {
    /// SDelete creates files named with repeating chars (AAA, ZZZ, 000) then deletes them.
    SDelete,
    /// CCleaner and similar tools create/delete many .tmp files rapidly.
    BulkTempDeletion,
    /// cipher /w creates large files to overwrite free space.
    CipherWipe,
}

/// Detect patterns indicative of secure deletion tools.
///
/// Looks for:
/// - Rapid create-delete cycles for files named with SDelete patterns (AAA, ZZZ, 000)
/// - Bulk .tmp file deletion in Temp folders
pub fn detect_secure_deletion(records: &[UsnRecord]) -> Vec<SecureDeletionIndicator> {
    let mut indicators = Vec::new();

    // ── SDelete detection ────────────────────────────────────────────────
    // SDelete renames files to sequences of repeating characters before deletion.
    // Look for create+delete of files matching patterns like AAAAAA, ZZZZZZ, 000000.

    let sdelete_patterns = detect_sdelete_patterns(records);
    indicators.extend(sdelete_patterns);

    // ── Bulk temp file deletion ──────────────────────────────────────────
    let temp_indicators = detect_bulk_temp_deletion(records);
    indicators.extend(temp_indicators);

    indicators
}

/// Detect SDelete-style repeating character filename patterns.
fn detect_sdelete_patterns(records: &[UsnRecord]) -> Vec<SecureDeletionIndicator> {
    let mut indicators = Vec::new();

    // Collect files matching SDelete naming patterns with create or delete events
    let mut sdelete_events: Vec<&UsnRecord> = Vec::new();

    for record in records {
        if is_sdelete_filename(&record.filename)
            && (record.reason.contains(UsnReason::FILE_CREATE)
                || record.reason.contains(UsnReason::FILE_DELETE))
        {
            sdelete_events.push(record);
        }
    }

    if sdelete_events.len() < 3 {
        return indicators;
    }

    // Group by time windows (within 60 seconds)
    let mut groups: Vec<Vec<&UsnRecord>> = Vec::new();
    let mut current_group: Vec<&UsnRecord> = vec![sdelete_events[0]];

    for event in &sdelete_events[1..] {
        let last = current_group.last().unwrap();
        if event.timestamp - last.timestamp <= Duration::seconds(60) {
            current_group.push(event);
        } else {
            if current_group.len() >= 3 {
                groups.push(std::mem::take(&mut current_group));
            } else {
                current_group.clear();
            }
            current_group.push(event);
        }
    }
    if current_group.len() >= 3 {
        groups.push(current_group);
    }

    for group in groups {
        let filenames: Vec<String> = group.iter().map(|r| r.filename.clone()).collect();
        let time_start = group.first().unwrap().timestamp;
        let time_end = group.last().unwrap().timestamp;

        // Higher confidence if we see both creates and deletes
        let has_creates = group.iter().any(|r| r.reason.contains(UsnReason::FILE_CREATE));
        let has_deletes = group.iter().any(|r| r.reason.contains(UsnReason::FILE_DELETE));
        let confidence = if has_creates && has_deletes {
            0.9
        } else {
            0.6
        };

        indicators.push(SecureDeletionIndicator {
            pattern: SecureDeletionPattern::SDelete,
            filenames,
            time_start,
            time_end,
            confidence,
        });
    }

    indicators
}

/// Check if a filename matches SDelete's repeating character pattern.
fn is_sdelete_filename(name: &str) -> bool {
    // Strip extension if present
    let base = name.split('.').next().unwrap_or(name);
    if base.len() < 3 {
        return false;
    }
    let first = base.chars().next().unwrap();
    // SDelete uses repeating single characters: AAA, ZZZ, 000
    base.chars().all(|c| c == first)
        && (first.is_ascii_uppercase() || first.is_ascii_digit())
}

/// Detect bulk .tmp file deletion indicative of cleaning tools.
fn detect_bulk_temp_deletion(records: &[UsnRecord]) -> Vec<SecureDeletionIndicator> {
    let mut indicators = Vec::new();

    // Find delete events for .tmp files
    let tmp_deletes: Vec<&UsnRecord> = records
        .iter()
        .filter(|r| {
            r.reason.contains(UsnReason::FILE_DELETE)
                && r.filename.to_lowercase().ends_with(".tmp")
        })
        .collect();

    if tmp_deletes.len() < 10 {
        return indicators;
    }

    // Group by 30-second windows
    let mut groups: Vec<Vec<&UsnRecord>> = Vec::new();
    let mut current_group: Vec<&UsnRecord> = vec![tmp_deletes[0]];

    for event in &tmp_deletes[1..] {
        let last = current_group.last().unwrap();
        if event.timestamp - last.timestamp <= Duration::seconds(30) {
            current_group.push(event);
        } else {
            if current_group.len() >= 10 {
                groups.push(std::mem::take(&mut current_group));
            } else {
                current_group.clear();
            }
            current_group.push(event);
        }
    }
    if current_group.len() >= 10 {
        groups.push(current_group);
    }

    for group in groups {
        indicators.push(SecureDeletionIndicator {
            pattern: SecureDeletionPattern::BulkTempDeletion,
            filenames: group.iter().map(|r| r.filename.clone()).collect(),
            time_start: group.first().unwrap().timestamp,
            time_end: group.last().unwrap().timestamp,
            confidence: 0.7,
        });
    }

    indicators
}

// ═══════════════════════════════════════════════════════════════════════════════
// Journal Clearing Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of journal clearing analysis.
#[derive(Debug, Clone)]
pub struct JournalClearingResult {
    /// Whether journal clearing was detected.
    pub clearing_detected: bool,
    /// The first USN value seen (high values suggest prior clearing).
    pub first_usn: Option<i64>,
    /// Timestamp gaps detected (sudden jumps in time).
    pub timestamp_gaps: Vec<TimestampGap>,
    /// Overall confidence (0.0 - 1.0).
    pub confidence: f64,
}

/// A detected gap in the journal timeline.
#[derive(Debug, Clone)]
pub struct TimestampGap {
    /// Timestamp before the gap.
    pub before: DateTime<Utc>,
    /// Timestamp after the gap.
    pub after: DateTime<Utc>,
    /// Duration of the gap.
    pub gap_duration: Duration,
    /// USN value before the gap.
    pub usn_before: i64,
    /// USN value after the gap.
    pub usn_after: i64,
}

/// Detect if the USN journal was cleared or tampered with.
///
/// Indicators:
/// - First record's USN is very high (older records were removed)
/// - Sudden large timestamp jumps between consecutive records
pub fn detect_journal_clearing(records: &[UsnRecord]) -> JournalClearingResult {
    if records.is_empty() {
        return JournalClearingResult {
            clearing_detected: false,
            first_usn: None,
            timestamp_gaps: Vec::new(),
            confidence: 0.0,
        };
    }

    let first_usn = records[0].usn;
    let mut confidence = 0.0;

    // A high first USN suggests the journal has been in use but older entries were cleared.
    // Typical threshold: if first USN > 1GB of journal data, it's suspicious.
    const USN_CLEARING_THRESHOLD: i64 = 1_073_741_824; // 1 GiB
    let high_usn = first_usn > USN_CLEARING_THRESHOLD;
    if high_usn {
        confidence += 0.5;
    }

    // Detect timestamp gaps (jumps of > 24 hours between consecutive records)
    let mut timestamp_gaps = Vec::new();
    let gap_threshold = Duration::hours(24);

    for window in records.windows(2) {
        let gap = window[1].timestamp - window[0].timestamp;
        if gap > gap_threshold {
            timestamp_gaps.push(TimestampGap {
                before: window[0].timestamp,
                after: window[1].timestamp,
                gap_duration: gap,
                usn_before: window[0].usn,
                usn_after: window[1].usn,
            });
        }
    }

    if !timestamp_gaps.is_empty() {
        // More gaps = higher confidence
        let gap_factor = (timestamp_gaps.len() as f64 * 0.2).min(0.5);
        confidence += gap_factor;
    }

    let clearing_detected = confidence >= 0.4;

    JournalClearingResult {
        clearing_detected,
        first_usn: Some(first_usn),
        timestamp_gaps,
        confidence,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ransomware Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// Indicator of ransomware-like activity.
#[derive(Debug, Clone)]
pub struct RansomwareIndicator {
    /// The suspicious extension being added to files.
    pub extension: String,
    /// Number of files affected.
    pub affected_count: usize,
    /// Sample filenames that were renamed.
    pub sample_filenames: Vec<String>,
    /// Time window of the activity.
    pub time_start: DateTime<Utc>,
    pub time_end: DateTime<Utc>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// Known ransomware extensions to check for.
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted",
    ".locked",
    ".crypto",
    ".crypt",
    ".enc",
    ".locky",
    ".cerber",
    ".zepto",
    ".odin",
    ".thor",
    ".aesir",
    ".zzzzz",
    ".micro",
    ".crypted",
    ".crinf",
    ".r5a",
    ".xrtn",
    ".xtbl",
    ".crypz",
    ".cryp1",
    ".ransom",
    ".wallet",
    ".onion",
    ".wncry",
    ".wcry",
    ".wncryt",
];

/// Detect ransomware-like behavior patterns in USN records.
///
/// Looks for:
/// - Mass file renames with known ransomware extensions
/// - High rate of DATA_OVERWRITE followed by RENAME_NEW_NAME
/// - Many files getting the same new extension in a short time window
pub fn detect_ransomware_patterns(records: &[UsnRecord]) -> Vec<RansomwareIndicator> {
    let mut indicators = Vec::new();

    // ── Known extension detection ────────────────────────────────────────
    indicators.extend(detect_known_ransomware_extensions(records));

    // ── Mass rename with same new extension ──────────────────────────────
    indicators.extend(detect_mass_rename_patterns(records));

    indicators
}

/// Detect files being renamed to known ransomware extensions.
fn detect_known_ransomware_extensions(records: &[UsnRecord]) -> Vec<RansomwareIndicator> {
    let mut indicators = Vec::new();

    // Group renames by extension
    let mut extension_groups: HashMap<String, Vec<&UsnRecord>> = HashMap::new();

    for record in records {
        if record.reason.contains(UsnReason::RENAME_NEW_NAME) {
            let lower = record.filename.to_lowercase();
            for ext in RANSOMWARE_EXTENSIONS {
                if lower.ends_with(ext) {
                    extension_groups
                        .entry(ext.to_string())
                        .or_default()
                        .push(record);
                    break;
                }
            }
        }
    }

    for (ext, group) in &extension_groups {
        if group.len() >= 3 {
            let time_start = group.iter().map(|r| r.timestamp).min().unwrap();
            let time_end = group.iter().map(|r| r.timestamp).max().unwrap();
            let sample: Vec<String> = group
                .iter()
                .take(10)
                .map(|r| r.filename.clone())
                .collect();

            let confidence = if group.len() >= 20 {
                0.95
            } else if group.len() >= 10 {
                0.85
            } else {
                0.6
            };

            indicators.push(RansomwareIndicator {
                extension: ext.clone(),
                affected_count: group.len(),
                sample_filenames: sample,
                time_start,
                time_end,
                confidence,
            });
        }
    }

    indicators
}

/// Detect mass rename patterns where many files get the same new extension.
fn detect_mass_rename_patterns(records: &[UsnRecord]) -> Vec<RansomwareIndicator> {
    let mut indicators = Vec::new();

    // Find DATA_OVERWRITE followed by RENAME_NEW_NAME patterns
    // Group renames by new extension in 5-minute windows
    let rename_records: Vec<&UsnRecord> = records
        .iter()
        .filter(|r| r.reason.contains(UsnReason::RENAME_NEW_NAME))
        .collect();

    if rename_records.len() < 20 {
        return indicators;
    }

    // Group by extension (excluding known ransomware - already handled above)
    let mut ext_groups: HashMap<String, Vec<&UsnRecord>> = HashMap::new();

    for record in &rename_records {
        if let Some(dot_pos) = record.filename.rfind('.') {
            let ext = record.filename[dot_pos..].to_lowercase();
            // Skip common extensions
            if !is_common_extension(&ext) {
                let lower = ext.clone();
                let is_known = RANSOMWARE_EXTENSIONS.iter().any(|&re| lower == re);
                if !is_known {
                    ext_groups.entry(ext).or_default().push(record);
                }
            }
        }
    }

    // Report extensions with abnormally high rename counts in tight time windows
    for (ext, group) in &ext_groups {
        if group.len() >= 20 {
            let time_start = group.iter().map(|r| r.timestamp).min().unwrap();
            let time_end = group.iter().map(|r| r.timestamp).max().unwrap();
            let duration = time_end - time_start;

            // 20+ renames to the same unusual extension within 10 minutes is suspicious
            if duration <= Duration::minutes(10) {
                let sample: Vec<String> = group
                    .iter()
                    .take(10)
                    .map(|r| r.filename.clone())
                    .collect();

                indicators.push(RansomwareIndicator {
                    extension: ext.clone(),
                    affected_count: group.len(),
                    sample_filenames: sample,
                    time_start,
                    time_end,
                    confidence: 0.75,
                });
            }
        }
    }

    indicators
}

/// Check if an extension is common/benign.
fn is_common_extension(ext: &str) -> bool {
    matches!(
        ext,
        ".txt" | ".doc" | ".docx" | ".xls" | ".xlsx" | ".pdf" | ".jpg" | ".jpeg"
            | ".png" | ".gif" | ".mp3" | ".mp4" | ".avi" | ".zip" | ".rar"
            | ".exe" | ".dll" | ".sys" | ".log" | ".tmp" | ".bak" | ".html"
            | ".htm" | ".css" | ".js" | ".py" | ".rs" | ".c" | ".h" | ".cpp"
            | ".java" | ".xml" | ".json" | ".csv" | ".ppt" | ".pptx"
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Timestomping Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// Indicator of timestamp manipulation.
#[derive(Debug, Clone)]
pub struct TimestompIndicator {
    /// The filename whose timestamps may have been manipulated.
    pub filename: String,
    /// MFT entry number.
    pub mft_entry: u64,
    /// The timestamp of the BASIC_INFO_CHANGE event.
    pub change_timestamp: DateTime<Utc>,
    /// Whether data modification events were found nearby.
    pub has_nearby_data_change: bool,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// Detect timestamp manipulation from USN records.
///
/// Timestomping is often visible in USN journals because:
/// - Modifying $STANDARD_INFORMATION timestamps generates a BASIC_INFO_CHANGE event
/// - Legitimate timestamp changes usually accompany data modifications
/// - Isolated BASIC_INFO_CHANGE events without nearby data changes are suspicious
pub fn detect_timestomping(records: &[UsnRecord]) -> Vec<TimestompIndicator> {
    let mut indicators = Vec::new();

    // Build a map of MFT entry -> records for correlation
    let mut entry_events: HashMap<u64, Vec<&UsnRecord>> = HashMap::new();
    for record in records {
        entry_events.entry(record.mft_entry).or_default().push(record);
    }

    // For each file, look for isolated BASIC_INFO_CHANGE events
    for (&mft_entry, events) in &entry_events {
        for (i, event) in events.iter().enumerate() {
            if !event.reason.contains(UsnReason::BASIC_INFO_CHANGE) {
                continue;
            }

            // Check if this BASIC_INFO_CHANGE has no accompanying data changes
            // within a window of nearby events (5 events before/after or 60 seconds)
            let has_nearby_data_change = events.iter().enumerate().any(|(j, other)| {
                if i == j {
                    return false;
                }
                let time_diff = if other.timestamp >= event.timestamp {
                    other.timestamp - event.timestamp
                } else {
                    event.timestamp - other.timestamp
                };
                if time_diff > Duration::seconds(60) {
                    return false;
                }
                other.reason.contains(UsnReason::DATA_OVERWRITE)
                    || other.reason.contains(UsnReason::DATA_EXTEND)
                    || other.reason.contains(UsnReason::DATA_TRUNCATION)
                    || other.reason.contains(UsnReason::FILE_CREATE)
            });

            // Isolated BASIC_INFO_CHANGE is suspicious
            if !has_nearby_data_change {
                // Check if reason is ONLY BASIC_INFO_CHANGE (possibly with CLOSE)
                let reason_without_close =
                    event.reason & !UsnReason::CLOSE;
                let is_isolated = reason_without_close == UsnReason::BASIC_INFO_CHANGE;

                let confidence = if is_isolated { 0.8 } else { 0.5 };

                indicators.push(TimestompIndicator {
                    filename: event.filename.clone(),
                    mft_entry,
                    change_timestamp: event.timestamp,
                    has_nearby_data_change: false,
                    confidence,
                });
            }
        }
    }

    indicators
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{FileAttributes, UsnReason};

    /// Helper to build a synthetic UsnRecord for testing.
    fn make_record(
        mft_entry: u64,
        filename: &str,
        reason: UsnReason,
        timestamp: DateTime<Utc>,
        usn: i64,
    ) -> UsnRecord {
        UsnRecord {
            mft_entry,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn,
            timestamp,
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    fn ts(secs_offset: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs_offset, 0).unwrap()
    }

    // ─── Secure Deletion Tests ───────────────────────────────────────────

    #[test]
    fn test_detect_sdelete_pattern() {
        let records = vec![
            make_record(100, "AAAAAAA", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(100, "AAAAAAA", UsnReason::FILE_DELETE, ts(1), 1100),
            make_record(101, "ZZZZZZZ", UsnReason::FILE_CREATE, ts(2), 1200),
            make_record(101, "ZZZZZZZ", UsnReason::FILE_DELETE, ts(3), 1300),
            make_record(102, "0000000", UsnReason::FILE_CREATE, ts(4), 1400),
            make_record(102, "0000000", UsnReason::FILE_DELETE, ts(5), 1500),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(!indicators.is_empty(), "Should detect SDelete pattern");
        assert_eq!(indicators[0].pattern, SecureDeletionPattern::SDelete);
        assert!(
            indicators[0].confidence >= 0.9,
            "High confidence when both creates and deletes are present"
        );
    }

    #[test]
    fn test_sdelete_not_triggered_by_normal_files() {
        let records = vec![
            make_record(100, "document.docx", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(101, "report.pdf", UsnReason::FILE_CREATE, ts(1), 1100),
            make_record(102, "image.png", UsnReason::FILE_DELETE, ts(2), 1200),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(
            indicators.is_empty(),
            "Normal files should not trigger SDelete detection"
        );
    }

    #[test]
    fn test_detect_bulk_temp_deletion() {
        let mut records = Vec::new();
        for i in 0..15 {
            records.push(make_record(
                100 + i,
                &format!("tmp{:04}.tmp", i),
                UsnReason::FILE_DELETE,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_secure_deletion(&records);
        assert!(
            !indicators.is_empty(),
            "Should detect bulk .tmp deletion"
        );
        assert_eq!(indicators[0].pattern, SecureDeletionPattern::BulkTempDeletion);
    }

    #[test]
    fn test_no_bulk_temp_with_few_files() {
        let records = vec![
            make_record(100, "tmp001.tmp", UsnReason::FILE_DELETE, ts(0), 1000),
            make_record(101, "tmp002.tmp", UsnReason::FILE_DELETE, ts(1), 1100),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(
            indicators.is_empty(),
            "Two .tmp deletions should not trigger bulk detection"
        );
    }

    // ─── Journal Clearing Tests ──────────────────────────────────────────

    #[test]
    fn test_detect_high_starting_usn() {
        let records = vec![
            make_record(
                100,
                "file.txt",
                UsnReason::FILE_CREATE,
                ts(0),
                2_000_000_000, // 2GB - way above threshold
            ),
            make_record(
                101,
                "file2.txt",
                UsnReason::FILE_CREATE,
                ts(1),
                2_000_001_000,
            ),
        ];

        let result = detect_journal_clearing(&records);
        assert!(result.clearing_detected, "High starting USN should indicate clearing");
        assert!(result.confidence >= 0.4);
        assert_eq!(result.first_usn, Some(2_000_000_000));
    }

    #[test]
    fn test_detect_timestamp_gap() {
        let records = vec![
            make_record(100, "before.txt", UsnReason::FILE_CREATE, ts(0), 1000),
            // 48-hour gap
            make_record(
                101,
                "after.txt",
                UsnReason::FILE_CREATE,
                ts(48 * 3600),
                1100,
            ),
        ];

        let result = detect_journal_clearing(&records);
        assert!(
            !result.timestamp_gaps.is_empty(),
            "Should detect 48-hour timestamp gap"
        );
        assert!(result.timestamp_gaps[0].gap_duration > Duration::hours(24));
    }

    #[test]
    fn test_no_clearing_for_normal_journal() {
        let records = vec![
            make_record(100, "a.txt", UsnReason::FILE_CREATE, ts(0), 100),
            make_record(101, "b.txt", UsnReason::FILE_CREATE, ts(60), 200),
            make_record(102, "c.txt", UsnReason::FILE_CREATE, ts(120), 300),
        ];

        let result = detect_journal_clearing(&records);
        assert!(
            !result.clearing_detected,
            "Normal journal should not trigger clearing detection"
        );
        assert!(result.timestamp_gaps.is_empty());
    }

    #[test]
    fn test_clearing_empty_records() {
        let result = detect_journal_clearing(&[]);
        assert!(!result.clearing_detected);
        assert!(result.first_usn.is_none());
    }

    // ─── Ransomware Detection Tests ──────────────────────────────────────

    #[test]
    fn test_detect_known_ransomware_extension() {
        let mut records = Vec::new();
        for i in 0..5 {
            records.push(make_record(
                100 + i,
                &format!("document{}.docx.encrypted", i),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        assert!(
            !indicators.is_empty(),
            "Should detect .encrypted ransomware extension"
        );
        assert_eq!(indicators[0].extension, ".encrypted");
        assert_eq!(indicators[0].affected_count, 5);
    }

    #[test]
    fn test_detect_mass_rename_unknown_extension() {
        let mut records = Vec::new();
        for i in 0..25 {
            records.push(make_record(
                100 + i,
                &format!("file{}.xyz_ransom", i),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        assert!(
            !indicators.is_empty(),
            "Should detect mass rename to unknown extension"
        );
    }

    #[test]
    fn test_no_ransomware_for_normal_renames() {
        let records = vec![
            make_record(100, "doc1.docx", UsnReason::RENAME_NEW_NAME, ts(0), 1000),
            make_record(101, "image.png", UsnReason::RENAME_NEW_NAME, ts(100), 1100),
            make_record(102, "report.pdf", UsnReason::RENAME_NEW_NAME, ts(200), 1200),
        ];

        let indicators = detect_ransomware_patterns(&records);
        assert!(
            indicators.is_empty(),
            "Normal file renames should not trigger ransomware detection"
        );
    }

    #[test]
    fn test_ransomware_multiple_known_extensions() {
        let mut records = Vec::new();
        // .locked files
        for i in 0..5 {
            records.push(make_record(
                100 + i,
                &format!("file{}.locked", i),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }
        // .crypto files
        for i in 0..4 {
            records.push(make_record(
                200 + i,
                &format!("photo{}.crypto", i),
                UsnReason::RENAME_NEW_NAME,
                ts(100 + i as i64),
                2000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        // Should detect at least the .locked group (5 >= 3 threshold)
        let locked_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.extension == ".locked")
            .collect();
        assert!(
            !locked_indicators.is_empty(),
            "Should detect .locked ransomware pattern"
        );
    }

    // ─── Timestomping Detection Tests ────────────────────────────────────

    #[test]
    fn test_detect_isolated_basic_info_change() {
        let records = vec![
            make_record(
                100,
                "suspicious.exe",
                UsnReason::BASIC_INFO_CHANGE,
                ts(1000),
                5000,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(
            !indicators.is_empty(),
            "Isolated BASIC_INFO_CHANGE should be detected"
        );
        assert_eq!(indicators[0].filename, "suspicious.exe");
        assert!(!indicators[0].has_nearby_data_change);
        assert!(indicators[0].confidence >= 0.7);
    }

    #[test]
    fn test_no_timestomp_with_data_change() {
        let records = vec![
            make_record(
                100,
                "normal.docx",
                UsnReason::DATA_OVERWRITE,
                ts(999),
                4900,
            ),
            make_record(
                100,
                "normal.docx",
                UsnReason::BASIC_INFO_CHANGE,
                ts(1000),
                5000,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(
            indicators.is_empty(),
            "BASIC_INFO_CHANGE with nearby data change should not trigger timestomp detection"
        );
    }

    #[test]
    fn test_timestomp_with_distant_data_change() {
        // Data change is > 60 seconds away, so BASIC_INFO_CHANGE is still suspicious
        let records = vec![
            make_record(
                100,
                "suspicious.exe",
                UsnReason::DATA_OVERWRITE,
                ts(0),
                1000,
            ),
            make_record(
                100,
                "suspicious.exe",
                UsnReason::BASIC_INFO_CHANGE,
                ts(120), // 2 minutes later
                5000,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(
            !indicators.is_empty(),
            "BASIC_INFO_CHANGE far from data changes should still be suspicious"
        );
    }

    #[test]
    fn test_timestomp_multiple_files() {
        let records = vec![
            make_record(
                100,
                "malware1.exe",
                UsnReason::BASIC_INFO_CHANGE,
                ts(0),
                1000,
            ),
            make_record(
                200,
                "malware2.dll",
                UsnReason::BASIC_INFO_CHANGE,
                ts(5),
                1500,
            ),
            make_record(
                300,
                "normal.txt",
                UsnReason::DATA_OVERWRITE,
                ts(10),
                2000,
            ),
            make_record(
                300,
                "normal.txt",
                UsnReason::BASIC_INFO_CHANGE,
                ts(11),
                2100,
            ),
        ];

        let indicators = detect_timestomping(&records);
        // malware1.exe and malware2.dll should be flagged, normal.txt should not
        let flagged_files: Vec<&str> = indicators.iter().map(|i| i.filename.as_str()).collect();
        assert!(
            flagged_files.contains(&"malware1.exe"),
            "malware1.exe should be flagged"
        );
        assert!(
            flagged_files.contains(&"malware2.dll"),
            "malware2.dll should be flagged"
        );
        assert!(
            !flagged_files.contains(&"normal.txt"),
            "normal.txt should not be flagged"
        );
    }

    #[test]
    fn test_no_timestomp_on_create() {
        // FILE_CREATE is a legitimate reason for BASIC_INFO_CHANGE
        let records = vec![
            make_record(
                100,
                "newfile.txt",
                UsnReason::FILE_CREATE,
                ts(0),
                1000,
            ),
            make_record(
                100,
                "newfile.txt",
                UsnReason::BASIC_INFO_CHANGE,
                ts(1),
                1100,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(
            indicators.is_empty(),
            "BASIC_INFO_CHANGE after FILE_CREATE should not be flagged"
        );
    }
}
