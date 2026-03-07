//! HTML triage report generator.
//!
//! Serializes pipeline outputs into a JSON blob, runs triage queries,
//! and injects the result into a self-contained HTML template.

use std::io::Write;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use crate::analysis::{
    JournalClearingResult, RansomwareIndicator, SecureDeletionIndicator, TimestompIndicator,
};
use crate::correlation::GhostRecord;
use crate::mft::MftData;
use crate::rewind::ResolvedRecord;
use crate::triage::{self, TriageQuestion};

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
        (
            crate::usn::UsnReason::NAMED_DATA_OVERWRITE,
            "NAMED_DATA_OVERWRITE",
        ),
        (
            crate::usn::UsnReason::NAMED_DATA_EXTEND,
            "NAMED_DATA_EXTEND",
        ),
        (
            crate::usn::UsnReason::NAMED_DATA_TRUNCATION,
            "NAMED_DATA_TRUNCATION",
        ),
        (crate::usn::UsnReason::FILE_CREATE, "FILE_CREATE"),
        (crate::usn::UsnReason::FILE_DELETE, "FILE_DELETE"),
        (crate::usn::UsnReason::EA_CHANGE, "EA_CHANGE"),
        (crate::usn::UsnReason::SECURITY_CHANGE, "SECURITY_CHANGE"),
        (crate::usn::UsnReason::RENAME_OLD_NAME, "RENAME_OLD_NAME"),
        (crate::usn::UsnReason::RENAME_NEW_NAME, "RENAME_NEW_NAME"),
        (crate::usn::UsnReason::INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
        (
            crate::usn::UsnReason::BASIC_INFO_CHANGE,
            "BASIC_INFO_CHANGE",
        ),
        (crate::usn::UsnReason::HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
        (
            crate::usn::UsnReason::COMPRESSION_CHANGE,
            "COMPRESSION_CHANGE",
        ),
        (
            crate::usn::UsnReason::ENCRYPTION_CHANGE,
            "ENCRYPTION_CHANGE",
        ),
        (crate::usn::UsnReason::OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE"),
        (
            crate::usn::UsnReason::REPARSE_POINT_CHANGE,
            "REPARSE_POINT_CHANGE",
        ),
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

pub fn build_report_data(input: &ReportInput, triage_questions: &[TriageQuestion]) -> ReportData {
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
            start: records
                .first()
                .map(|r| r.timestamp.clone())
                .unwrap_or_default(),
            end: records
                .last()
                .map(|r| r.timestamp.clone())
                .unwrap_or_default(),
        })
    } else {
        None
    };

    let alert_count = input.timestomping.len()
        + input.secure_deletion.len()
        + input.ransomware.len()
        + if input.journal_clearing.clearing_detected {
            1
        } else {
            0
        };

    let mft_timestamps = input
        .mft_data
        .map(|mft| {
            mft.entries
                .iter()
                .map(|e| MftTimestampEntry {
                    entry: e.entry_number,
                    filename: e.filename.clone(),
                    si_created: e.si_created.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    si_modified: e.si_modified.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    fn_created: e.fn_created.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    fn_modified: e.fn_modified.map(|t| t.to_rfc3339()).unwrap_or_default(),
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
    use chrono::DateTime;

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

    #[test]
    fn test_html_contains_story_tab() {
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

        // Template must contain Story/Explore tab structure
        assert!(html.contains("Story"), "missing Story tab");
        assert!(html.contains("Explore"), "missing Explore tab");
        // Template must contain stat cards
        assert!(html.contains("stat-card"), "missing stat cards");
        // Template must contain the dark theme
        assert!(html.contains("#0d1117"), "missing dark theme background");
        // Template must contain sparkline canvas
        assert!(html.contains("sparkline"), "missing sparkline");
    }

    #[test]
    fn test_html_contains_triage_questions() {
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

        // The injected JSON must contain triage question data
        assert!(
            html.contains("malware_deployed"),
            "missing malware triage question"
        );
        assert!(
            html.contains("lateral_movement"),
            "missing lateral movement question"
        );
        assert!(html.contains("What Happened"), "missing triage category");
    }
}
