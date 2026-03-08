//! Rapid triage query engine for USN journal forensic analysis.
//!
//! Provides a structured way to ask forensic questions against resolved USN
//! journal records. Each `TriageQuestion` encapsulates a query that filters
//! records by path patterns, extensions, reason flags, and filename keywords.
//! The engine returns `TriageResult` structs indicating whether evidence was
//! found and which record indices matched.

use regex::Regex;

use crate::rewind::ResolvedRecord;
use crate::usn::UsnReason;

pub mod queries;

// ─── Types ──────────────────────────────────────────────────────────────────

/// A forensic triage question with its associated query filter.
#[derive(Debug, Clone)]
pub struct TriageQuestion {
    /// Unique identifier (e.g. "malware_deployed").
    pub id: &'static str,
    /// Category grouping (e.g. "Breach & Malware").
    pub category: &'static str,
    /// Human-readable question (e.g. "Were executables dropped in suspicious locations?").
    pub question: &'static str,
    /// The query filter to evaluate against records.
    pub query: TriageQuery,
}

/// Filter criteria for a triage question.
#[derive(Debug, Clone, Default)]
pub struct TriageQuery {
    /// Regex patterns matched against the full path (case-insensitive, any match).
    pub path_patterns: Vec<&'static str>,
    /// File extension filter (without dot, e.g. "exe", "dll").
    pub extension_filter: Vec<&'static str>,
    /// Reason flags; record must have at least one flag in common (intersects).
    pub reasons: Option<UsnReason>,
    /// Regex patterns; records matching any of these are excluded.
    pub exclude_patterns: Vec<&'static str>,
    /// Substring filters matched against the filename (case-insensitive, any match).
    pub filename_filter: Vec<&'static str>,
    /// Filter by record source (e.g. "carved", "ghost"). Empty = match all sources.
    pub source_filter: Vec<&'static str>,
}

/// Result of evaluating a single triage question against the record set.
pub struct TriageResult {
    /// Matches the `TriageQuestion::id`.
    pub id: &'static str,
    /// Matches the `TriageQuestion::category`.
    pub category: &'static str,
    /// Matches the `TriageQuestion::question`.
    pub question: &'static str,
    /// Whether any records matched.
    pub has_hits: bool,
    /// Number of matching records.
    pub hit_count: usize,
    /// Indices into the input record slice for matching records.
    pub record_indices: Vec<usize>,
}

// ─── Engine ─────────────────────────────────────────────────────────────────

/// Run all triage questions against the resolved record set.
///
/// Returns one `TriageResult` per question, in the same order as the input.
pub fn run_triage(questions: &[TriageQuestion], records: &[ResolvedRecord]) -> Vec<TriageResult> {
    questions
        .iter()
        .map(|q| {
            let record_indices: Vec<usize> = records
                .iter()
                .enumerate()
                .filter(|(_, r)| matches_query(&q.query, r))
                .map(|(i, _)| i)
                .collect();
            let hit_count = record_indices.len();
            TriageResult {
                id: q.id,
                category: q.category,
                question: q.question,
                has_hits: hit_count > 0,
                hit_count,
                record_indices,
            }
        })
        .collect()
}

/// Check whether a single resolved record matches the given query.
fn matches_query(query: &TriageQuery, record: &ResolvedRecord) -> bool {
    // An entirely empty query matches nothing (placeholder questions).
    if query.path_patterns.is_empty()
        && query.extension_filter.is_empty()
        && query.reasons.is_none()
        && query.exclude_patterns.is_empty()
        && query.filename_filter.is_empty()
        && query.source_filter.is_empty()
    {
        return false;
    }

    // Source filter: record source must match one of the listed sources.
    if !query.source_filter.is_empty() {
        let source_str = record.source.as_str();
        if !query.source_filter.contains(&source_str) {
            return false;
        }
    }

    // Reason flag check: record must share at least one flag with the query.
    if let Some(reasons) = query.reasons {
        if !record.record.reason.intersects(reasons) {
            return false;
        }
    }

    // Path pattern check: at least one regex must match the full path.
    if !query.path_patterns.is_empty() {
        let path_lower = record.full_path.to_lowercase();
        let any_match = query.path_patterns.iter().any(|pat| {
            Regex::new(&pat.to_lowercase())
                .map(|re| re.is_match(&path_lower))
                .unwrap_or(false)
        });
        if !any_match {
            return false;
        }
    }

    // Extension filter: filename must end with one of the listed extensions.
    if !query.extension_filter.is_empty() {
        let name_lower = record.record.filename.to_lowercase();
        let any_ext = query.extension_filter.iter().any(|ext| {
            let dot_ext = format!(".{}", ext.to_lowercase());
            name_lower.ends_with(&dot_ext)
        });
        if !any_ext {
            return false;
        }
    }

    // Filename filter: filename must contain at least one of the keywords.
    if !query.filename_filter.is_empty() {
        let name_lower = record.record.filename.to_lowercase();
        let any_name = query
            .filename_filter
            .iter()
            .any(|kw| name_lower.contains(&kw.to_lowercase()));
        if !any_name {
            return false;
        }
    }

    // Exclude patterns: if any regex matches the full path, exclude the record.
    if !query.exclude_patterns.is_empty() {
        let path_lower = record.full_path.to_lowercase();
        let any_exclude = query.exclude_patterns.iter().any(|pat| {
            Regex::new(&pat.to_lowercase())
                .map(|re| re.is_match(&path_lower))
                .unwrap_or(false)
        });
        if any_exclude {
            return false;
        }
    }

    true
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{FileAttributes, UsnRecord};
    use chrono::DateTime;

    /// Helper to create a `ResolvedRecord` for testing (defaults to Allocated source).
    fn make_resolved(full_path: &str, filename: &str, reason: UsnReason) -> ResolvedRecord {
        ResolvedRecord {
            record: UsnRecord {
                mft_entry: 100,
                mft_sequence: 1,
                parent_mft_entry: 5,
                parent_mft_sequence: 5,
                usn: 1000,
                timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                reason,
                filename: filename.to_string(),
                file_attributes: FileAttributes::ARCHIVE,
                source_info: 0,
                security_id: 0,
                major_version: 2,
            },
            full_path: full_path.to_string(),
            parent_path: ".".to_string(),
            source: crate::rewind::RecordSource::Allocated,
        }
    }

    #[test]
    fn test_malware_query_matches_exe_in_system32() {
        let records = vec![make_resolved(
            r".\Windows\System32\evil.exe",
            "evil.exe",
            UsnReason::FILE_CREATE,
        )];

        let questions = vec![TriageQuestion {
            id: "malware_deployed",
            category: "Breach & Malware",
            question: "Were executables dropped in suspicious locations?",
            query: TriageQuery {
                path_patterns: vec![r"System32", r"SysWOW64", r"Temp", r"AppData"],
                extension_filter: vec!["exe", "dll"],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results.len(), 1);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_query_excludes_by_pattern() {
        let records = vec![
            make_resolved(
                r".\Windows\System32\legit.dll",
                "legit.dll",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Users\admin\AppData\Local\Temp\dropper.exe",
                "dropper.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        let questions = vec![TriageQuestion {
            id: "test_exclude",
            category: "Test",
            question: "Test exclusion",
            query: TriageQuery {
                path_patterns: vec![r"System32", r"Temp", r"AppData"],
                extension_filter: vec!["exe", "dll"],
                reasons: Some(UsnReason::FILE_CREATE),
                exclude_patterns: vec![r"Windows"],
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results.len(), 1);
        // Only the Temp record should match; the Windows one is excluded.
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![1]);
    }

    #[test]
    fn test_query_no_hits_returns_empty() {
        let records = vec![make_resolved(
            r".\Documents\report.pdf",
            "report.pdf",
            UsnReason::DATA_EXTEND,
        )];

        let questions = vec![TriageQuestion {
            id: "no_hits",
            category: "Test",
            question: "Should find nothing",
            query: TriageQuery {
                path_patterns: vec![r"System32"],
                extension_filter: vec!["exe"],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results.len(), 1);
        assert!(!results[0].has_hits);
        assert_eq!(results[0].hit_count, 0);
        assert!(results[0].record_indices.is_empty());
    }

    #[test]
    fn test_filename_filter_matches() {
        let records = vec![
            make_resolved(
                r".\Windows\System32\mimikatz.exe",
                "mimikatz.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Users\admin\Desktop\notes.txt",
                "notes.txt",
                UsnReason::DATA_EXTEND,
            ),
        ];

        let questions = vec![TriageQuestion {
            id: "cred_access",
            category: "Credential Access",
            question: "Were credential tools used?",
            query: TriageQuery {
                filename_filter: vec!["mimikatz", "procdump", "lsass"],
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results.len(), 1);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    // ─── Tests for source filtering ───────────────────────────────────────

    fn make_resolved_with_source(
        full_path: &str,
        filename: &str,
        reason: UsnReason,
        source: crate::rewind::RecordSource,
    ) -> ResolvedRecord {
        let mut r = make_resolved(full_path, filename, reason);
        r.source = source;
        r
    }

    #[test]
    fn test_source_filter_matches_carved_only() {
        use crate::rewind::RecordSource;

        let records = vec![
            make_resolved_with_source(
                r".\Users\admin\secret.docx",
                "secret.docx",
                UsnReason::FILE_CREATE,
                RecordSource::Allocated,
            ),
            make_resolved_with_source(
                r".\Users\admin\deleted.exe",
                "deleted.exe",
                UsnReason::FILE_CREATE,
                RecordSource::Carved,
            ),
            make_resolved_with_source(
                r".\Users\admin\ghost.dll",
                "ghost.dll",
                UsnReason::FILE_CREATE,
                RecordSource::Ghost,
            ),
        ];

        let questions = vec![TriageQuestion {
            id: "carved_only",
            category: "Test",
            question: "Only carved records?",
            query: TriageQuery {
                source_filter: vec!["entry-carved"],
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results[0].hit_count, 1, "only carved record should match");
        assert_eq!(results[0].record_indices, vec![1]);
    }

    #[test]
    fn test_source_filter_matches_carved_and_ghost() {
        use crate::rewind::RecordSource;

        let records = vec![
            make_resolved_with_source(
                r".\allocated.txt",
                "allocated.txt",
                UsnReason::FILE_CREATE,
                RecordSource::Allocated,
            ),
            make_resolved_with_source(
                r".\carved.exe",
                "carved.exe",
                UsnReason::FILE_CREATE,
                RecordSource::Carved,
            ),
            make_resolved_with_source(
                r".\ghost.dll",
                "ghost.dll",
                UsnReason::FILE_CREATE,
                RecordSource::Ghost,
            ),
        ];

        let questions = vec![TriageQuestion {
            id: "recovered",
            category: "Test",
            question: "All recovered?",
            query: TriageQuery {
                source_filter: vec!["entry-carved", "ghost"],
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results[0].hit_count, 2, "carved + ghost should match");
        assert_eq!(results[0].record_indices, vec![1, 2]);
    }

    #[test]
    fn test_empty_source_filter_matches_all() {
        use crate::rewind::RecordSource;

        let records = vec![
            make_resolved_with_source(
                r".\a.txt",
                "a.txt",
                UsnReason::FILE_CREATE,
                RecordSource::Allocated,
            ),
            make_resolved_with_source(
                r".\b.txt",
                "b.txt",
                UsnReason::FILE_CREATE,
                RecordSource::Carved,
            ),
        ];

        // source_filter is empty but reasons is set, so this is NOT a
        // placeholder query — the empty source filter should not restrict
        // which sources match.
        let questions = vec![TriageQuestion {
            id: "all",
            category: "Test",
            question: "All records?",
            query: TriageQuery {
                reasons: Some(UsnReason::FILE_CREATE),
                source_filter: vec![], // empty = match all
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(
            results[0].hit_count, 2,
            "empty filter should match all sources"
        );
    }

    #[test]
    fn test_recovered_evidence_query_uses_source_filter() {
        use crate::rewind::RecordSource;

        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "recovered_evidence")
            .expect("missing recovered_evidence");

        // Verify the query actually has a source filter
        assert!(
            !q.query.source_filter.is_empty(),
            "recovered_evidence must have a source_filter"
        );

        let records = vec![
            make_resolved_with_source(
                r".\normal.txt",
                "normal.txt",
                UsnReason::FILE_CREATE,
                RecordSource::Allocated,
            ),
            make_resolved_with_source(
                r".\recovered.exe",
                "recovered.exe",
                UsnReason::FILE_CREATE,
                RecordSource::Carved,
            ),
            make_resolved_with_source(
                r".\ghost.dll",
                "ghost.dll",
                UsnReason::FILE_CREATE,
                RecordSource::Ghost,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 2, "carved + ghost should match");
    }

    // ─── Tests for expanded triage question set ────────────────────────────

    #[test]
    fn test_builtin_questions_returns_12() {
        let questions = crate::triage::queries::builtin_questions();
        assert_eq!(
            questions.len(),
            12,
            "expected 12 triage questions, got {}",
            questions.len()
        );
    }

    #[test]
    fn test_builtin_has_execution_evidence_question() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions.iter().find(|q| q.id == "execution_evidence");
        assert!(q.is_some(), "missing execution_evidence question");
    }

    #[test]
    fn test_prefetch_creation_proves_execution() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "execution_evidence")
            .expect("missing execution_evidence");

        let records = vec![
            make_resolved(
                r".\Windows\Prefetch\COREUPDATE.EXE-A1B2C3D4.pf",
                "COREUPDATE.EXE-A1B2C3D4.pf",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Windows\Prefetch\SVCHOST.EXE-12345678.pf",
                "SVCHOST.EXE-12345678.pf",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits, "prefetch creation should be detected");
        assert_eq!(results[0].hit_count, 2);
    }

    #[test]
    fn test_data_staging_detects_archive_in_user_dir() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "data_staging")
            .expect("missing data_staging");

        let records = vec![
            make_resolved(
                r".\Users\admin\Desktop\exfil.zip",
                "exfil.zip",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Program Files\7zip\7z.dll",
                "7z.dll",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(
            results[0].hit_count, 1,
            "only the user-dir archive should match"
        );
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_credential_access_matches_sam_by_path() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "credential_access")
            .expect("missing credential_access");

        let records = vec![
            // Real SAM hive path — should match
            make_resolved(r".\Windows\System32\config\SAM", "SAM", UsnReason::CLOSE),
            // Random file named "sam" — should NOT match
            make_resolved(
                r".\Users\sam\Documents\report.docx",
                "report.docx",
                UsnReason::CLOSE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(
            results[0].hit_count, 1,
            "should only match the config\\SAM path, not random 'sam' user dir"
        );
    }

    #[test]
    fn test_evidence_destruction_detects_evtx_deletion() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "evidence_destruction")
            .expect("missing evidence_destruction");

        let records = vec![
            make_resolved(
                r".\Windows\System32\winevt\Logs\Security.evtx",
                "Security.evtx",
                UsnReason::FILE_DELETE,
            ),
            make_resolved(
                r".\Windows\Prefetch\MIMIKATZ.EXE-AABBCCDD.pf",
                "MIMIKATZ.EXE-AABBCCDD.pf",
                UsnReason::FILE_DELETE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(
            results[0].hit_count, 2,
            "both evtx and pf deletion should match"
        );
    }

    #[test]
    fn test_file_disguise_detects_ads_operations() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "file_disguise")
            .expect("missing file_disguise");

        let records = vec![
            make_resolved(
                r".\Users\admin\document.docx",
                "document.docx",
                UsnReason::NAMED_DATA_EXTEND,
            ),
            make_resolved(
                r".\Users\admin\normal.txt",
                "normal.txt",
                UsnReason::DATA_EXTEND,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1, "only ADS operation should match");
    }

    #[test]
    fn test_initial_access_detects_exe_in_downloads() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "initial_access")
            .expect("missing initial_access");

        let records = vec![
            make_resolved(
                r".\Users\admin\Downloads\payload.exe",
                "payload.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Windows\System32\cmd.exe",
                "cmd.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(
            results[0].hit_count, 1,
            "only the Downloads drop should match, not System32"
        );
    }

    #[test]
    fn test_malware_deployed_detects_exe_in_programdata() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "malware_deployed")
            .expect("missing malware_deployed");

        let records = vec![
            make_resolved(
                r".\ProgramData\evil.exe",
                "evil.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Documents\readme.txt",
                "readme.txt",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_sensitive_data_detects_xlsx_access() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "sensitive_data")
            .expect("missing sensitive_data");

        let records = vec![
            make_resolved(
                r".\Users\admin\Documents\financials.xlsx",
                "financials.xlsx",
                UsnReason::DATA_EXTEND | UsnReason::CLOSE,
            ),
            make_resolved(
                r".\Windows\ProgramData\config.xml",
                "config.xml",
                UsnReason::DATA_EXTEND,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
    }

    #[test]
    fn test_persistence_detects_exe_in_startup() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "persistence")
            .expect("missing persistence");

        let records = vec![
            make_resolved(
                r".\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.exe",
                "backdoor.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Users\admin\Desktop\normal.exe",
                "normal.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_lateral_movement_detects_psexec() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "lateral_movement")
            .expect("missing lateral_movement");

        let records = vec![
            make_resolved(
                r".\Windows\System32\psexec.exe",
                "psexec.exe",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Windows\System32\notepad.exe",
                "notepad.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_timestomping_detects_basic_info_change_on_exe() {
        let questions = crate::triage::queries::builtin_questions();
        let q = questions
            .iter()
            .find(|q| q.id == "timestomping")
            .expect("missing timestomping");

        let records = vec![
            make_resolved(
                r".\Users\admin\Temp\payload.exe",
                "payload.exe",
                UsnReason::BASIC_INFO_CHANGE,
            ),
            make_resolved(
                r".\Windows\WinSxS\something.exe",
                "something.exe",
                UsnReason::BASIC_INFO_CHANGE,
            ),
        ];

        let results = run_triage(std::slice::from_ref(q), &records);
        assert!(results[0].has_hits);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_source_filter_ghost_only() {
        use crate::rewind::RecordSource;

        let records = vec![
            make_resolved_with_source(
                r".\file_a.exe",
                "file_a.exe",
                UsnReason::FILE_CREATE,
                RecordSource::Allocated,
            ),
            make_resolved_with_source(
                r".\file_b.exe",
                "file_b.exe",
                UsnReason::FILE_CREATE,
                RecordSource::Carved,
            ),
            make_resolved_with_source(
                r".\file_c.exe",
                "file_c.exe",
                UsnReason::FILE_CREATE,
                RecordSource::Ghost,
            ),
        ];

        let questions = vec![TriageQuestion {
            id: "ghost_only",
            category: "Test",
            question: "Only ghost records?",
            query: TriageQuery {
                source_filter: vec!["ghost"],
                ..Default::default()
            },
        }];

        let results = run_triage(&questions, &records);
        assert_eq!(results[0].hit_count, 1, "only ghost record should match");
        assert_eq!(results[0].record_indices, vec![2]);
    }

    #[test]
    fn test_record_source_as_str() {
        use crate::rewind::RecordSource;
        assert_eq!(RecordSource::Allocated.as_str(), "allocated");
        assert_eq!(RecordSource::Carved.as_str(), "entry-carved");
        assert_eq!(RecordSource::Ghost.as_str(), "ghost");
    }

    // ─── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn test_run_triage_with_empty_records() {
        let questions = crate::triage::queries::builtin_questions();
        let results = run_triage(&questions, &[]);
        assert_eq!(results.len(), 12);
        for r in &results {
            assert!(!r.has_hits);
            assert_eq!(r.hit_count, 0);
            assert!(r.record_indices.is_empty());
        }
    }

    #[test]
    fn test_run_triage_with_empty_questions() {
        let records = vec![make_resolved(
            r".\test.exe",
            "test.exe",
            UsnReason::FILE_CREATE,
        )];
        let results = run_triage(&[], &records);
        assert!(results.is_empty());
    }

    #[test]
    fn test_matches_query_empty_query_matches_nothing() {
        let records = vec![make_resolved(
            r".\test.exe",
            "test.exe",
            UsnReason::FILE_CREATE,
        )];
        let questions = vec![TriageQuestion {
            id: "empty",
            category: "Test",
            question: "Empty query?",
            query: TriageQuery::default(),
        }];
        let results = run_triage(&questions, &records);
        assert!(!results[0].has_hits);
        assert_eq!(results[0].hit_count, 0);
    }

    #[test]
    fn test_matches_query_reasons_only() {
        let records = vec![
            make_resolved(r".\anything.txt", "anything.txt", UsnReason::FILE_DELETE),
            make_resolved(r".\other.txt", "other.txt", UsnReason::FILE_CREATE),
        ];
        let questions = vec![TriageQuestion {
            id: "reasons_only",
            category: "Test",
            question: "Only reason filter?",
            query: TriageQuery {
                reasons: Some(UsnReason::FILE_DELETE),
                ..Default::default()
            },
        }];
        let results = run_triage(&questions, &records);
        assert_eq!(results[0].hit_count, 1);
        assert_eq!(results[0].record_indices, vec![0]);
    }

    #[test]
    fn test_source_filter_case_sensitivity() {
        use crate::rewind::RecordSource;
        let records = vec![make_resolved_with_source(
            r".\test.exe",
            "test.exe",
            UsnReason::FILE_CREATE,
            RecordSource::Carved,
        )];
        let questions = vec![TriageQuestion {
            id: "case_test",
            category: "Test",
            question: "Case sensitive?",
            query: TriageQuery {
                source_filter: vec!["Carved"], // uppercase C - should NOT match
                ..Default::default()
            },
        }];
        let results = run_triage(&questions, &records);
        assert_eq!(
            results[0].hit_count, 0,
            "source filter should be case-sensitive"
        );
    }

    #[test]
    fn test_multiple_questions_independent_results() {
        let records = vec![
            make_resolved(
                r".\Windows\Prefetch\CMD.EXE-12345678.pf",
                "CMD.EXE-12345678.pf",
                UsnReason::FILE_CREATE,
            ),
            make_resolved(
                r".\Users\admin\Downloads\payload.exe",
                "payload.exe",
                UsnReason::FILE_CREATE,
            ),
        ];
        let questions = crate::triage::queries::builtin_questions();
        let results = run_triage(&questions, &records);

        // execution_evidence should match the prefetch file
        let exec = results
            .iter()
            .find(|r| r.id == "execution_evidence")
            .unwrap();
        assert!(exec.has_hits);

        // initial_access should match the Downloads file
        let init = results.iter().find(|r| r.id == "initial_access").unwrap();
        assert!(init.has_hits);

        // data_staging should match nothing (no archive extensions)
        let staging = results.iter().find(|r| r.id == "data_staging").unwrap();
        assert!(!staging.has_hits);
    }
}
