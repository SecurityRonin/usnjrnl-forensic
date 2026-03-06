# Rapid Triage Report — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `--report triage.html` flag that generates a self-contained HTML triage report with a Story tab (question-driven forensic narrative) and an Explore tab (full timeline workbench).

**Architecture:** Rust serializes all pipeline outputs (resolved records, MFT timestamps, detections, ghost records, carving stats) into a JSON blob, runs triage queries to pre-answer forensic questions, injects the JSON into an HTML template embedded at compile time via `include_str!`, and writes a single self-contained HTML file. The HTML uses vanilla JS for interactivity.

**Tech Stack:** Rust (serde_json for serialization), vanilla HTML/CSS/JS (no framework, no build toolchain), Chart.js-style canvas sparkline.

**Design doc:** `docs/plans/2026-03-07-rapid-triage-report-design.md`

---

## Task 1: Triage Query Engine (Rust)

**Files:**
- Create: `src/triage/mod.rs`
- Create: `src/triage/queries.rs`
- Modify: `src/lib.rs` (add `pub mod triage;`)

### Step 1: Write the failing test

Add to `src/triage/mod.rs`:

```rust
//! Triage query engine for rapid forensic assessment.
//!
//! Defines generic forensic questions (e.g. "Was malware deployed?") and
//! query logic that matches against resolved USN records. Queries are
//! image-agnostic — they work on any NTFS volume.

use regex::Regex;

use crate::rewind::ResolvedRecord;
use crate::usn::UsnReason;

/// A triage question with its query logic and results.
#[derive(Debug, Clone)]
pub struct TriageQuestion {
    pub id: &'static str,
    pub category: &'static str,
    pub question: &'static str,
    pub query: TriageQuery,
}

/// Query criteria for matching resolved records.
#[derive(Debug, Clone, Default)]
pub struct TriageQuery {
    /// Regex patterns that must match the full_path (case-insensitive).
    pub path_patterns: Vec<&'static str>,
    /// File extensions to match (lowercase, without dot).
    pub extension_filter: Vec<&'static str>,
    /// Reason flags — record must contain ANY of these.
    pub reasons: Option<UsnReason>,
    /// Regex patterns to EXCLUDE from results.
    pub exclude_patterns: Vec<&'static str>,
    /// Filename substrings to match (case-insensitive).
    pub filename_filter: Vec<&'static str>,
}

/// Result of running a triage question against resolved records.
#[derive(Debug, Clone)]
pub struct TriageResult {
    pub id: &'static str,
    pub category: &'static str,
    pub question: &'static str,
    pub has_hits: bool,
    pub hit_count: usize,
    /// Indices into the resolved records array.
    pub record_indices: Vec<usize>,
}

/// Run all triage questions against resolved records.
pub fn run_triage(
    questions: &[TriageQuestion],
    records: &[ResolvedRecord],
) -> Vec<TriageResult> {
    questions
        .iter()
        .map(|q| {
            let indices: Vec<usize> = records
                .iter()
                .enumerate()
                .filter(|(_, r)| matches_query(&q.query, r))
                .map(|(i, _)| i)
                .collect();
            TriageResult {
                id: q.id,
                category: q.category,
                question: q.question,
                has_hits: !indices.is_empty(),
                hit_count: indices.len(),
                record_indices: indices,
            }
        })
        .collect()
}

fn matches_query(query: &TriageQuery, record: &ResolvedRecord) -> bool {
    let path_lower = record.full_path.to_lowercase();
    let filename_lower = record.record.filename.to_lowercase();

    // Check reason flags (if specified, record must contain at least one)
    if let Some(reasons) = query.reasons {
        if !record.record.reason.intersects(reasons) {
            return false;
        }
    }

    // Check path patterns (if specified, at least one must match)
    if !query.path_patterns.is_empty() {
        let any_match = query.path_patterns.iter().any(|p| {
            Regex::new(&format!("(?i){p}"))
                .map(|re| re.is_match(&record.full_path))
                .unwrap_or(false)
        });
        if !any_match {
            return false;
        }
    }

    // Check extension filter (if specified, must match one)
    if !query.extension_filter.is_empty() {
        let ext = filename_lower
            .rsplit('.')
            .next()
            .unwrap_or("");
        if !query.extension_filter.iter().any(|e| *e == ext) {
            return false;
        }
    }

    // Check filename filter (if specified, must match one)
    if !query.filename_filter.is_empty() {
        if !query
            .filename_filter
            .iter()
            .any(|f| filename_lower.contains(&f.to_lowercase()))
        {
            return false;
        }
    }

    // Check exclude patterns
    for pat in &query.exclude_patterns {
        if let Ok(re) = Regex::new(&format!("(?i){pat}")) {
            if re.is_match(&path_lower) {
                return false;
            }
        }
    }

    true
}

pub mod queries;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{FileAttributes, UsnReason, UsnRecord};
    use chrono::DateTime;

    fn make_resolved(filename: &str, full_path: &str, reason: UsnReason) -> ResolvedRecord {
        ResolvedRecord {
            record: UsnRecord {
                mft_entry: 100,
                mft_sequence: 1,
                parent_mft_entry: 5,
                parent_mft_sequence: 5,
                usn: 1000,
                timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
                reason,
                filename: filename.to_string(),
                file_attributes: FileAttributes::ARCHIVE,
                source_info: 0,
                security_id: 0,
                major_version: 2,
            },
            full_path: full_path.to_string(),
            parent_path: ".".to_string(),
        }
    }

    #[test]
    fn test_malware_query_matches_exe_in_system32() {
        let questions = vec![TriageQuestion {
            id: "malware",
            category: "Breach",
            question: "Was malware deployed?",
            query: TriageQuery {
                path_patterns: vec![r"\\Windows\\System32\\"],
                extension_filter: vec!["exe", "dll"],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        }];

        let records = vec![
            make_resolved(
                "coreupdate.exe",
                ".\\Windows\\System32\\coreupdate.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                "normal.txt",
                ".\\Users\\admin\\normal.txt",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(&questions, &records);
        assert_eq!(results.len(), 1);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_query_excludes_by_pattern() {
        let questions = vec![TriageQuestion {
            id: "sensitive",
            category: "Data Theft",
            question: "Were sensitive files accessed?",
            query: TriageQuery {
                extension_filter: vec!["txt", "docx"],
                reasons: Some(UsnReason::CLOSE),
                exclude_patterns: vec![r"\\Windows\\"],
                ..Default::default()
            },
        }];

        let records = vec![
            make_resolved(
                "secret.txt",
                ".\\Users\\admin\\Documents\\secret.txt",
                UsnReason::CLOSE,
            ),
            make_resolved(
                "system.txt",
                ".\\Windows\\Logs\\system.txt",
                UsnReason::CLOSE,
            ),
        ];

        let results = run_triage(&questions, &records);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_query_no_hits_returns_empty() {
        let questions = vec![TriageQuestion {
            id: "ransomware",
            category: "Threats",
            question: "Ransomware activity?",
            query: TriageQuery {
                extension_filter: vec!["encrypted", "locked"],
                reasons: Some(UsnReason::RENAME_NEW_NAME),
                ..Default::default()
            },
        }];

        let records = vec![make_resolved(
            "normal.txt",
            ".\\Users\\normal.txt",
            UsnReason::FILE_CREATE,
        )];

        let results = run_triage(&questions, &records);
        assert!(!results[0].has_hits);
        assert_eq!(results[0].hit_count, 0);
    }

    #[test]
    fn test_filename_filter_matches() {
        let questions = vec![TriageQuestion {
            id: "lateral",
            category: "Lateral Movement",
            question: "RDP artifacts?",
            query: TriageQuery {
                filename_filter: vec!["rdpclip.exe", "tstheme.exe"],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        }];

        let records = vec![
            make_resolved(
                "rdpclip.exe",
                ".\\Windows\\System32\\rdpclip.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                "notepad.exe",
                ".\\Windows\\System32\\notepad.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(&questions, &records);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test --lib triage::tests`
Expected: FAIL — module `triage` does not exist yet in lib.rs

### Step 3: Add module declaration

Add to `src/lib.rs` after the existing `pub mod` lines:

```rust
pub mod triage;
```

### Step 4: Create the queries file

Create `src/triage/queries.rs`:

```rust
//! Built-in triage questions for generic forensic assessment.

use crate::usn::UsnReason;
use super::{TriageQuery, TriageQuestion};

/// Returns the built-in set of forensic triage questions.
///
/// These are generic enough to work on any NTFS image, but specific
/// enough to surface actionable results for typical intrusion patterns.
pub fn builtin_questions() -> Vec<TriageQuestion> {
    vec![
        TriageQuestion {
            id: "malware_deployed",
            category: "Breach & Malware",
            question: "Was malware or suspicious software deployed?",
            query: TriageQuery {
                path_patterns: vec![
                    r"\\Windows\\System32\\",
                    r"\\Windows\\SysWOW64\\",
                    r"\\Windows\\Temp\\",
                    r"\\AppData\\Local\\Temp\\",
                    r"\\ProgramData\\",
                ],
                extension_filter: vec!["exe", "dll", "scr", "bat", "ps1", "cmd", "vbs", "js", "hta"],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "sensitive_files_accessed",
            category: "Data Theft",
            question: "Were sensitive files accessed or modified?",
            query: TriageQuery {
                extension_filter: vec!["docx", "xlsx", "pdf", "txt", "csv", "pst", "kdbx", "key", "pem"],
                reasons: Some(UsnReason::DATA_EXTEND | UsnReason::CLOSE | UsnReason::DATA_TRUNCATION),
                exclude_patterns: vec![r"\\Windows\\", r"\\ProgramData\\", r"\\Program Files"],
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "data_theft",
            category: "Data Theft",
            question: "Were files accessed in user document directories?",
            query: TriageQuery {
                path_patterns: vec![r"\\Documents\\", r"\\Desktop\\", r"\\Downloads\\"],
                extension_filter: vec!["docx", "xlsx", "pdf", "txt", "csv", "zip", "7z", "rar"],
                reasons: Some(UsnReason::DATA_EXTEND | UsnReason::CLOSE),
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "lateral_movement",
            category: "Lateral Movement",
            question: "Are there signs of lateral movement (RDP, remote tools)?",
            query: TriageQuery {
                filename_filter: vec![
                    "rdpclip.exe", "tstheme.exe", "mstsc.exe",
                    "psexec", "wmiexec", "smbexec", "winrs.exe",
                ],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "persistence",
            category: "Persistence",
            question: "Were persistence mechanisms established?",
            query: TriageQuery {
                path_patterns: vec![
                    r"\\Start Menu\\Programs\\Startup\\",
                    r"\\Microsoft\\Windows\\Start Menu\\",
                    r"\\Tasks\\",
                    r"\\services\\.exe",
                ],
                extension_filter: vec!["exe", "dll", "bat", "ps1", "cmd", "vbs", "lnk"],
                reasons: Some(UsnReason::FILE_CREATE | UsnReason::RENAME_NEW_NAME),
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "credential_access",
            category: "Credential Access",
            question: "Were credential stores or security databases accessed?",
            query: TriageQuery {
                filename_filter: vec![
                    "ntds.dit", "sam", "security", "system",
                    "lsass", "mimikatz", "procdump",
                    "lazagne", "rubeus", "kerberoast",
                ],
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "anti_forensics",
            category: "Anti-Forensics",
            question: "Was evidence of anti-forensics or tampering found?",
            query: TriageQuery {
                // This question is answered by detection modules, not record queries.
                // An empty query means 0 record hits; the report generator populates
                // this card from the detection results instead.
                ..Default::default()
            },
        },
        TriageQuestion {
            id: "recovered_evidence",
            category: "Recovered Evidence",
            question: "What evidence was recovered from deleted/unallocated space?",
            query: TriageQuery {
                // Populated by carving stats and ghost record counts, not record queries.
                ..Default::default()
            },
        },
    ]
}
```

### Step 5: Run tests to verify they pass

Run: `cargo test --lib triage::tests`
Expected: 4 tests PASS

### Step 6: Commit

```bash
git add src/triage/mod.rs src/triage/queries.rs src/lib.rs
git commit -m "feat: add triage query engine with built-in forensic questions"
```

---

## Task 2: Report Data Serialization (Rust)

**Files:**
- Create: `src/output/report.rs`
- Modify: `src/output/mod.rs` (add `pub mod report;`)

### Step 1: Write the failing test

Create `src/output/report.rs` with `ReportData` struct, serialization logic, and tests:

```rust
//! HTML triage report generator.
//!
//! Serializes pipeline outputs into a JSON blob, runs triage queries,
//! and injects the result into a self-contained HTML template.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::analysis::{
    JournalClearingResult, RansomwareIndicator, SecureDeletionIndicator, TimestompIndicator,
};
use crate::correlation::GhostRecord;
use crate::mft::MftData;
use crate::rewind::ResolvedRecord;
use crate::triage::{self, TriageQuestion, TriageResult};

const TEMPLATE: &str = include_str!("../../report/template.html");

// ─── Serializable report types ──────────────────────────────────────────────

#[derive(Serialize)]
pub struct ReportData {
    pub meta: ReportMeta,
    pub records: Vec<ReportRecord>,
    pub mft_timestamps: Vec<MftTimestampEntry>,
    pub detections: ReportDetections,
    pub ghost_records: Vec<ReportGhostRecord>,
    pub carving_stats: ReportCarvingStats,
    pub triage: Vec<ReportTriageResult>,
}

#[derive(Serialize)]
pub struct ReportMeta {
    pub tool_version: String,
    pub image_name: String,
    pub generated_at: String,
    pub record_count: usize,
    pub carved_usn_count: usize,
    pub carved_mft_count: usize,
    pub ghost_record_count: usize,
    pub alert_count: usize,
    pub time_range: Option<TimeRange>,
}

#[derive(Serialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
}

#[derive(Serialize)]
pub struct ReportRecord {
    pub timestamp: String,
    pub usn: i64,
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub full_path: String,
    pub parent_path: String,
    pub filename: String,
    pub extension: String,
    pub reasons: Vec<String>,
    pub file_attributes: String,
    pub source: String,
}

#[derive(Serialize)]
pub struct MftTimestampEntry {
    pub entry: u64,
    pub filename: String,
    pub si_created: String,
    pub si_modified: String,
    pub fn_created: String,
    pub fn_modified: String,
}

#[derive(Serialize)]
pub struct ReportDetections {
    pub timestomping: Vec<ReportTimestomp>,
    pub secure_deletion: Vec<ReportSecureDeletion>,
    pub ransomware: Vec<ReportRansomware>,
    pub journal_clearing: ReportJournalClearing,
}

#[derive(Serialize)]
pub struct ReportTimestomp {
    pub filename: String,
    pub mft_entry: u64,
    pub confidence: f64,
    pub detail: String,
}

#[derive(Serialize)]
pub struct ReportSecureDeletion {
    pub pattern: String,
    pub filenames: Vec<String>,
    pub time_start: String,
    pub time_end: String,
    pub confidence: f64,
}

#[derive(Serialize)]
pub struct ReportRansomware {
    pub extension: String,
    pub affected_count: usize,
    pub sample_filenames: Vec<String>,
    pub time_start: String,
    pub time_end: String,
    pub confidence: f64,
}

#[derive(Serialize)]
pub struct ReportJournalClearing {
    pub detected: bool,
    pub confidence: f64,
}

#[derive(Serialize)]
pub struct ReportGhostRecord {
    pub timestamp: String,
    pub usn: i64,
    pub filename: String,
    pub reasons: Vec<String>,
    pub lsn: u64,
}

#[derive(Serialize)]
pub struct ReportCarvingStats {
    pub bytes_scanned: u64,
    pub chunks_processed: u64,
    pub usn_carved: usize,
    pub mft_carved: usize,
    pub usn_dupes_removed: u64,
    pub mft_dupes_removed: u64,
}

#[derive(Serialize)]
pub struct ReportTriageResult {
    pub id: String,
    pub category: String,
    pub question: String,
    pub has_hits: bool,
    pub hit_count: usize,
    pub record_indices: Vec<usize>,
}

// ─── Builder ────────────────────────────────────────────────────────────────

/// Parameters for building a report.
pub struct ReportInput<'a> {
    pub image_name: &'a str,
    pub resolved: &'a [ResolvedRecord],
    pub mft_data: Option<&'a MftData>,
    pub timestomping: &'a [TimestompIndicator],
    pub secure_deletion: &'a [SecureDeletionIndicator],
    pub ransomware: &'a [RansomwareIndicator],
    pub journal_clearing: &'a JournalClearingResult,
    pub ghost_records: &'a [GhostRecord],
    pub carved_usn_count: usize,
    pub carved_mft_count: usize,
    pub carving_bytes_scanned: u64,
    pub carving_chunks: u64,
    pub carving_usn_dupes: u64,
    pub carving_mft_dupes: u64,
}

fn extract_extension(filename: &str) -> String {
    filename
        .rsplit('.')
        .next()
        .filter(|ext| ext.len() < filename.len())
        .unwrap_or("")
        .to_lowercase()
}

fn reason_flags_to_strings(reason: crate::usn::UsnReason) -> Vec<String> {
    let mut flags = Vec::new();
    let all_flags = [
        (crate::usn::UsnReason::DATA_OVERWRITE, "DATA_OVERWRITE"),
        (crate::usn::UsnReason::DATA_EXTEND, "DATA_EXTEND"),
        (crate::usn::UsnReason::DATA_TRUNCATION, "DATA_TRUNCATION"),
        (crate::usn::UsnReason::NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
        (crate::usn::UsnReason::NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND"),
        (crate::usn::UsnReason::NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION"),
        (crate::usn::UsnReason::FILE_CREATE, "FILE_CREATE"),
        (crate::usn::UsnReason::FILE_DELETE, "FILE_DELETE"),
        (crate::usn::UsnReason::EA_CHANGE, "EA_CHANGE"),
        (crate::usn::UsnReason::SECURITY_CHANGE, "SECURITY_CHANGE"),
        (crate::usn::UsnReason::RENAME_OLD_NAME, "RENAME_OLD_NAME"),
        (crate::usn::UsnReason::RENAME_NEW_NAME, "RENAME_NEW_NAME"),
        (crate::usn::UsnReason::INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
        (crate::usn::UsnReason::BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
        (crate::usn::UsnReason::HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
        (crate::usn::UsnReason::COMPRESSION_CHANGE, "COMPRESSION_CHANGE"),
        (crate::usn::UsnReason::ENCRYPTION_CHANGE, "ENCRYPTION_CHANGE"),
        (crate::usn::UsnReason::OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE"),
        (crate::usn::UsnReason::REPARSE_POINT_CHANGE, "REPARSE_POINT_CHANGE"),
        (crate::usn::UsnReason::STREAM_CHANGE, "STREAM_CHANGE"),
        (crate::usn::UsnReason::CLOSE, "CLOSE"),
    ];
    for (flag, name) in &all_flags {
        if reason.contains(*flag) {
            flags.push(name.to_string());
        }
    }
    flags
}

pub fn build_report_data(
    input: &ReportInput,
    triage_questions: &[TriageQuestion],
) -> ReportData {
    let triage_results = triage::run_triage(triage_questions, input.resolved);

    let records: Vec<ReportRecord> = input
        .resolved
        .iter()
        .map(|r| ReportRecord {
            timestamp: r.record.timestamp.to_rfc3339(),
            usn: r.record.usn,
            mft_entry: r.record.mft_entry,
            mft_sequence: r.record.mft_sequence,
            parent_entry: r.record.parent_mft_entry,
            parent_sequence: r.record.parent_mft_sequence,
            full_path: r.full_path.clone(),
            parent_path: r.parent_path.clone(),
            filename: r.record.filename.clone(),
            extension: extract_extension(&r.record.filename),
            reasons: reason_flags_to_strings(r.record.reason),
            file_attributes: format!("{}", r.record.file_attributes),
            source: "allocated".to_string(),
        })
        .collect();

    let time_range = if !records.is_empty() {
        Some(TimeRange {
            start: records.first().map(|r| r.timestamp.clone()).unwrap_or_default(),
            end: records.last().map(|r| r.timestamp.clone()).unwrap_or_default(),
        })
    } else {
        None
    };

    let alert_count = input.timestomping.len()
        + input.secure_deletion.len()
        + input.ransomware.len()
        + if input.journal_clearing.clearing_detected { 1 } else { 0 };

    let mft_timestamps = input
        .mft_data
        .map(|mft| {
            mft.entries
                .iter()
                .map(|e| MftTimestampEntry {
                    entry: e.entry_number,
                    filename: e.filename.clone(),
                    si_created: e.si_created.to_rfc3339(),
                    si_modified: e.si_modified.to_rfc3339(),
                    fn_created: e.fn_created.to_rfc3339(),
                    fn_modified: e.fn_modified.to_rfc3339(),
                })
                .collect()
        })
        .unwrap_or_default();

    ReportData {
        meta: ReportMeta {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            image_name: input.image_name.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            record_count: input.resolved.len(),
            carved_usn_count: input.carved_usn_count,
            carved_mft_count: input.carved_mft_count,
            ghost_record_count: input.ghost_records.len(),
            alert_count,
            time_range,
        },
        records,
        mft_timestamps,
        detections: ReportDetections {
            timestomping: input
                .timestomping
                .iter()
                .map(|t| ReportTimestomp {
                    filename: t.filename.clone(),
                    mft_entry: t.mft_entry,
                    confidence: t.confidence,
                    detail: if t.has_nearby_data_change {
                        "BASIC_INFO_CHANGE with nearby data modification".to_string()
                    } else {
                        "Isolated BASIC_INFO_CHANGE — no nearby data modification".to_string()
                    },
                })
                .collect(),
            secure_deletion: input
                .secure_deletion
                .iter()
                .map(|s| ReportSecureDeletion {
                    pattern: format!("{:?}", s.pattern),
                    filenames: s.filenames.clone(),
                    time_start: s.time_start.to_rfc3339(),
                    time_end: s.time_end.to_rfc3339(),
                    confidence: s.confidence,
                })
                .collect(),
            ransomware: input
                .ransomware
                .iter()
                .map(|r| ReportRansomware {
                    extension: r.extension.clone(),
                    affected_count: r.affected_count,
                    sample_filenames: r.sample_filenames.clone(),
                    time_start: r.time_start.to_rfc3339(),
                    time_end: r.time_end.to_rfc3339(),
                    confidence: r.confidence,
                })
                .collect(),
            journal_clearing: ReportJournalClearing {
                detected: input.journal_clearing.clearing_detected,
                confidence: input.journal_clearing.confidence,
            },
        },
        ghost_records: input
            .ghost_records
            .iter()
            .map(|g| ReportGhostRecord {
                timestamp: g.record.timestamp.to_rfc3339(),
                usn: g.record.usn,
                filename: g.record.filename.clone(),
                reasons: reason_flags_to_strings(g.record.reason),
                lsn: g.lsn,
            })
            .collect(),
        carving_stats: ReportCarvingStats {
            bytes_scanned: input.carving_bytes_scanned,
            chunks_processed: input.carving_chunks,
            usn_carved: input.carved_usn_count,
            mft_carved: input.carved_mft_count,
            usn_dupes_removed: input.carving_usn_dupes,
            mft_dupes_removed: input.carving_mft_dupes,
        },
        triage: triage_results
            .iter()
            .map(|t| ReportTriageResult {
                id: t.id.to_string(),
                category: t.category.to_string(),
                question: t.question.to_string(),
                has_hits: t.has_hits,
                hit_count: t.hit_count,
                record_indices: t.record_indices.clone(),
            })
            .collect(),
    }
}

/// Generate the HTML report and write it to the given writer.
pub fn export_report<W: Write>(report_data: &ReportData, writer: &mut W) -> Result<()> {
    let json = serde_json::to_string(report_data)?;
    let html = TEMPLATE.replace("{{DATA}}", &json);
    writer.write_all(html.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::JournalClearingResult;
    use crate::usn::{FileAttributes, UsnReason, UsnRecord};

    fn make_test_input() -> (Vec<ResolvedRecord>, Vec<GhostRecord>, JournalClearingResult) {
        let record = UsnRecord {
            mft_entry: 100,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 5,
            usn: 1000,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason: UsnReason::FILE_CREATE,
            filename: "test.exe".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };
        let resolved = vec![ResolvedRecord {
            record,
            full_path: ".\\Windows\\System32\\test.exe".to_string(),
            parent_path: ".\\Windows\\System32".to_string(),
        }];
        let clearing = JournalClearingResult {
            clearing_detected: false,
            first_usn: Some(1000),
            timestamp_gaps: vec![],
            confidence: 0.0,
        };
        (resolved, vec![], clearing)
    }

    #[test]
    fn test_build_report_data_basic() {
        let (resolved, ghosts, clearing) = make_test_input();
        let input = ReportInput {
            image_name: "test.E01",
            resolved: &resolved,
            mft_data: None,
            timestomping: &[],
            secure_deletion: &[],
            ransomware: &[],
            journal_clearing: &clearing,
            ghost_records: &ghosts,
            carved_usn_count: 0,
            carved_mft_count: 0,
            carving_bytes_scanned: 0,
            carving_chunks: 0,
            carving_usn_dupes: 0,
            carving_mft_dupes: 0,
        };
        let questions = crate::triage::queries::builtin_questions();
        let data = build_report_data(&input, &questions);

        assert_eq!(data.meta.record_count, 1);
        assert_eq!(data.records.len(), 1);
        assert_eq!(data.records[0].filename, "test.exe");
        assert_eq!(data.records[0].extension, "exe");
        assert!(data.records[0].reasons.contains(&"FILE_CREATE".to_string()));
    }

    #[test]
    fn test_export_report_produces_html() {
        let (resolved, ghosts, clearing) = make_test_input();
        let input = ReportInput {
            image_name: "test.E01",
            resolved: &resolved,
            mft_data: None,
            timestomping: &[],
            secure_deletion: &[],
            ransomware: &[],
            journal_clearing: &clearing,
            ghost_records: &ghosts,
            carved_usn_count: 0,
            carved_mft_count: 0,
            carving_bytes_scanned: 0,
            carving_chunks: 0,
            carving_usn_dupes: 0,
            carving_mft_dupes: 0,
        };
        let questions = crate::triage::queries::builtin_questions();
        let data = build_report_data(&input, &questions);

        let mut buf = Vec::new();
        export_report(&data, &mut buf).unwrap();
        let html = String::from_utf8(buf).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("test.exe"));
        assert!(html.contains("FILE_CREATE"));
    }

    #[test]
    fn test_extract_extension() {
        assert_eq!(extract_extension("malware.exe"), "exe");
        assert_eq!(extract_extension("archive.tar.gz"), "gz");
        assert_eq!(extract_extension("noext"), "");
    }
}
```

### Step 2: Create a minimal HTML template placeholder

Create `report/template.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>usnjrnl-forensic Triage Report</title></head>
<body>
<script>const DATA = {{DATA}};</script>
<div id="app">Loading...</div>
</body>
</html>
```

This is a minimal placeholder so `include_str!` and tests work. The full HTML is built in Task 4.

### Step 3: Add module declaration

Add to `src/output/mod.rs`:

```rust
pub mod report;
```

### Step 4: Run tests to verify they pass

Run: `cargo test --lib output::report::tests`
Expected: 3 tests PASS

### Step 5: Commit

```bash
git add src/output/report.rs src/output/mod.rs report/template.html
git commit -m "feat: add report data serialization and HTML injection"
```

---

## Task 3: Wire --report into main.rs

**Files:**
- Modify: `src/main.rs` (add CLI flag, wire into output section)

### Step 1: Add CLI flag

In the `Cli` struct (after `xml: Option<PathBuf>` at line 71), add:

```rust
    /// Output HTML triage report
    #[arg(long)]
    report: Option<PathBuf>,
```

### Step 2: Collect detection results into variables accessible to report

The detection code in main.rs currently runs inside conditional blocks. We need to hoist the results so the report generator can access them. Add default-initialized variables before the detection section, and assign into them:

```rust
// Before detection blocks (around line 200):
let mut timestomping_indicators: Vec<usnjrnl_forensic::analysis::TimestompIndicator> = Vec::new();
let mut secure_deletion_indicators: Vec<usnjrnl_forensic::analysis::SecureDeletionIndicator> = Vec::new();
let mut ransomware_indicators: Vec<usnjrnl_forensic::analysis::RansomwareIndicator> = Vec::new();
let mut journal_clearing_result = usnjrnl_forensic::analysis::JournalClearingResult {
    clearing_detected: false,
    first_usn: None,
    timestamp_gaps: vec![],
    confidence: 0.0,
};
let mut ghost_records: Vec<usnjrnl_forensic::correlation::GhostRecord> = Vec::new();
```

Then inside the existing detection blocks, assign to these variables instead of using local `let` bindings. Inside the correlation block, capture `ghosts` into `ghost_records`.

### Step 3: Add report generation to output section

After the XML output block (line ~447), before the `if !has_output` check:

```rust
    if let Some(ref report_path) = cli.report {
        eprintln!("[*] Generating triage report to {}", report_path.display());
        let image_name = cli
            .image
            .as_ref()
            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
            .unwrap_or_else(|| {
                cli.journal
                    .as_ref()
                    .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            });

        let questions = usnjrnl_forensic::triage::queries::builtin_questions();
        let report_input = usnjrnl_forensic::output::report::ReportInput {
            image_name: &image_name,
            resolved: &resolved,
            mft_data: mft_data.as_ref(),
            timestomping: &timestomping_indicators,
            secure_deletion: &secure_deletion_indicators,
            ransomware: &ransomware_indicators,
            journal_clearing: &journal_clearing_result,
            ghost_records: &ghost_records,
            carved_usn_count,
            carved_mft_count,
            carving_bytes_scanned,
            carving_chunks,
            carving_usn_dupes,
            carving_mft_dupes,
        };
        let report_data =
            usnjrnl_forensic::output::report::build_report_data(&report_input, &questions);
        let file = std::fs::File::create(report_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl_forensic::output::report::export_report(&report_data, &mut writer)?;
        eprintln!("[+] Triage report generated");
    }
```

Update `has_output` to include `cli.report.is_some()`.

Update the no-output hint message to mention `--report`.

### Step 4: Update carving section to export stats

The carving section in main.rs currently consumes `carve_results`. Add variables to capture carving stats:

```rust
let mut carved_usn_count: usize = 0;
let mut carved_mft_count: usize = 0;
let mut carving_bytes_scanned: u64 = 0;
let mut carving_chunks: u64 = 0;
let mut carving_usn_dupes: u64 = 0;
let mut carving_mft_dupes: u64 = 0;
```

Assign these inside the `if cli.carve_unallocated` block from `carve_results.stats`.

### Step 5: Run tests

Run: `cargo test`
Expected: All 433+ tests pass, plus new triage and report tests

### Step 6: Verify compilation

Run: `cargo check` and `cargo check --features image`
Expected: Clean

### Step 7: Commit

```bash
git add src/main.rs
git commit -m "feat: wire --report flag into CLI pipeline"
```

---

## Task 4: HTML Template — Full UI

**Files:**
- Modify: `report/template.html` (replace placeholder with full UI)

This is the largest task. The template is a single self-contained HTML file with inline CSS and JS.

### Step 1: Build the complete HTML template

Replace `report/template.html` with the full implementation containing:

**HTML structure:**
- Header bar with stat cards
- Tab switcher (Story / Explore)
- Story tab: category groups with expandable question cards
- Explore tab: filter sidebar + sparkline canvas + data table + detail panel

**CSS (inline `<style>`):**
- Dark theme (#0d1117 base)
- System monospace font stack
- CSS grid for Explore layout
- Card components with colored left borders
- Source pills (allocated=default, carved=purple, ghost=cyan)
- Responsive: works down to 1024px

**JS (inline `<script>`):**
- `DATA` global populated by Rust
- Tab switching
- Story card expand/collapse
- "View in Explore" cross-tab links that apply filters
- Explore: text search (debounced), reason flag checkboxes, source toggles
- Explore: table rendering with 500-row pagination
- Explore: row click → detail panel
- Sparkline: canvas rendering bucketed by minute, click to zoom time range
- All filtering done with `Array.filter()` on the `DATA.records` array

### Step 2: Test manually

Run against test data:

```bash
cargo run -- -j test_fixtures/$J -m test_fixtures/$MFT --report /tmp/test_report.html
open /tmp/test_report.html
```

Or if no fixtures available, the unit tests in report.rs already verify the JSON injection works.

### Step 3: Verify template compiles

Run: `cargo check`
Expected: Clean (include_str! picks up the updated template)

### Step 4: Commit

```bash
git add report/template.html
git commit -m "feat: add full triage report HTML template with Story and Explore tabs"
```

---

## Task 5: CLI Tests and Polish

**Files:**
- Modify: `src/main.rs` (add CLI test for --report flag)

### Step 1: Add CLI argument test

In the `#[cfg(test)] mod tests` section of main.rs, add:

```rust
#[test]
fn test_cli_accepts_report_flag() {
    let cli = Cli::try_parse_from(["usnjrnl-forensic", "-j", "$J", "--report", "triage.html"]);
    assert!(cli.is_ok());
    let cli = cli.unwrap();
    assert_eq!(
        cli.report.unwrap().to_str().unwrap(),
        "triage.html"
    );
}

#[test]
fn test_cli_report_with_image() {
    let cli = Cli::try_parse_from([
        "usnjrnl-forensic",
        "--image",
        "evidence.E01",
        "--carve-unallocated",
        "--report",
        "triage.html",
    ]);
    assert!(cli.is_ok());
}
```

### Step 2: Run all tests

Run: `cargo test`
Expected: All tests pass (435+)

### Step 3: Run clippy

Run: `cargo clippy -- -W clippy::all`
Expected: Clean

### Step 4: Run fmt

Run: `cargo fmt --check`
Expected: Clean

### Step 5: Commit

```bash
git add src/main.rs
git commit -m "test: add CLI tests for --report flag"
```

---

## Task 6: Update README and Bump Version

**Files:**
- Modify: `README.md`
- Modify: `Cargo.toml`

### Step 1: Add --report to Usage section

Under the E01 image usage section, add:

```markdown
#### Generate a triage report

```bash
usnjrnl-forensic --image evidence.E01 --carve-unallocated --report triage.html
```

Produces a self-contained HTML file with a Story tab (question-driven forensic narrative) and an Explore tab (full timeline workbench). Opens in any browser — no server needed.
```

### Step 2: Add HTML to the Output Formats table

| HTML Report | `--report` | Self-contained triage report with Story + Explore tabs |

### Step 3: Update test count badge

### Step 4: Bump version to 0.5.0

In `Cargo.toml`, change `version = "0.4.0"` to `version = "0.5.0"`.

### Step 5: Commit

```bash
git add README.md Cargo.toml Cargo.lock
git commit -m "docs: add --report to README, bump to v0.5.0"
```

---

## Task Order and Dependencies

```
Task 1 (triage engine) ──┐
                          ├──▶ Task 3 (wire into main.rs) ──▶ Task 5 (tests/polish)
Task 2 (report.rs)  ─────┘                                          │
                                                                     ▼
Task 4 (HTML template) ──────────────────────────────────▶ Task 6 (README/version)
```

Tasks 1 and 2 are independent and can be done in parallel.
Task 3 depends on both 1 and 2.
Task 4 can be done in parallel with Task 3 (the placeholder template is enough for Rust compilation).
Task 5 depends on 3 and 4.
Task 6 depends on 5.
