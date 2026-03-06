//! Built-in triage questions for common forensic investigations.
//!
//! These questions cover the most frequent incident-response scenarios:
//! malware deployment, data theft, lateral movement, persistence,
//! credential access, and anti-forensics.

use crate::usn::UsnReason;

use super::{TriageQuery, TriageQuestion};

/// Returns the built-in set of triage questions.
pub fn builtin_questions() -> Vec<TriageQuestion> {
    vec![
        // ── 1. Malware Deployed ─────────────────────────────────────────
        TriageQuestion {
            id: "malware_deployed",
            category: "Breach & Malware",
            question: "Were executables dropped in suspicious locations?",
            query: TriageQuery {
                path_patterns: vec![
                    r"System32",
                    r"SysWOW64",
                    r"[Tt]emp",
                    r"AppData",
                    r"ProgramData",
                ],
                extension_filter: vec![
                    "exe", "dll", "scr", "bat", "ps1", "cmd", "vbs", "js", "hta",
                ],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        },
        // ── 2. Sensitive Files Accessed ─────────────────────────────────
        TriageQuestion {
            id: "sensitive_files_accessed",
            category: "Data Theft",
            question: "Were sensitive file types accessed outside system directories?",
            query: TriageQuery {
                extension_filter: vec![
                    "docx", "xlsx", "pdf", "txt", "csv", "pst", "kdbx", "key", "pem",
                ],
                reasons: Some(
                    UsnReason::DATA_EXTEND | UsnReason::CLOSE | UsnReason::DATA_TRUNCATION,
                ),
                exclude_patterns: vec![r"Windows", r"ProgramData", r"Program Files"],
                ..Default::default()
            },
        },
        // ── 3. Data Theft ───────────────────────────────────────────────
        TriageQuestion {
            id: "data_theft",
            category: "Data Theft",
            question: "Were user documents accessed or staged for exfiltration?",
            query: TriageQuery {
                path_patterns: vec![r"Documents", r"Desktop", r"Downloads"],
                extension_filter: vec!["docx", "xlsx", "pdf", "txt", "csv", "zip", "7z", "rar"],
                reasons: Some(UsnReason::DATA_EXTEND | UsnReason::CLOSE),
                ..Default::default()
            },
        },
        // ── 4. Lateral Movement ─────────────────────────────────────────
        TriageQuestion {
            id: "lateral_movement",
            category: "Lateral Movement",
            question: "Are there signs of lateral movement tools?",
            query: TriageQuery {
                filename_filter: vec![
                    "rdpclip.exe",
                    "tstheme.exe",
                    "mstsc.exe",
                    "psexec",
                    "wmiexec",
                    "smbexec",
                    "winrs.exe",
                ],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        },
        // ── 5. Persistence ──────────────────────────────────────────────
        TriageQuestion {
            id: "persistence",
            category: "Persistence",
            question: "Were persistence mechanisms created or modified?",
            query: TriageQuery {
                path_patterns: vec![r"Startup", r"Start Menu", r"Tasks", r"services"],
                extension_filter: vec!["exe", "dll", "bat", "ps1", "cmd", "vbs", "lnk"],
                reasons: Some(UsnReason::FILE_CREATE | UsnReason::RENAME_NEW_NAME),
                ..Default::default()
            },
        },
        // ── 6. Credential Access ────────────────────────────────────────
        TriageQuestion {
            id: "credential_access",
            category: "Credential Access",
            question: "Were credential stores or dumping tools touched?",
            query: TriageQuery {
                filename_filter: vec![
                    "ntds.dit",
                    "sam",
                    "security",
                    "system",
                    "lsass",
                    "mimikatz",
                    "procdump",
                    "lazagne",
                    "rubeus",
                    "kerberoast",
                ],
                ..Default::default()
            },
        },
        // ── 7. Anti-Forensics ───────────────────────────────────────────
        TriageQuestion {
            id: "anti_forensics",
            category: "Anti-Forensics",
            question: "Is there evidence of anti-forensic activity?",
            query: TriageQuery::default(), // Populated by detection modules
        },
        // ── 8. Recovered Evidence ───────────────────────────────────────
        TriageQuestion {
            id: "recovered_evidence",
            category: "Recovered Evidence",
            question: "Were deleted records recovered from unallocated space?",
            query: TriageQuery::default(), // Populated by carving stats
        },
    ]
}
