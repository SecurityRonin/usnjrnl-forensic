//! Built-in triage questions for rapid incident response.
//!
//! Questions are ordered by urgency — what a panicked incident commander
//! needs to tell the CEO in 10 minutes. Business-outcome first, technical
//! detail underneath.
//!
//! ## Question order
//!
//! 1-3:  "What happened?" — initial access, malware, execution proof
//! 4-6:  "How bad is it?" — data access, staging, credentials
//! 7-8:  "Are we still at risk?" — persistence, lateral movement
//! 9-11: "Did they cover tracks?" — evidence destruction, timestomping, disguise
//! 12:   "What did we recover?" — carved/ghost records (populated by report generator)

use crate::usn::UsnReason;

use super::{TriageQuery, TriageQuestion};

/// Returns the 12 built-in forensic triage questions.
pub fn builtin_questions() -> Vec<TriageQuestion> {
    vec![
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TIER 1: "What happened?"
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // ── 1. Initial Access ─────────────────────────────────────────────
        TriageQuestion {
            id: "initial_access",
            category: "What Happened",
            question: "How was the system compromised?",
            query: TriageQuery {
                path_patterns: vec![r"Downloads", r"[Tt]emp", r"AppData"],
                extension_filter: vec![
                    "exe", "dll", "scr", "bat", "ps1", "cmd", "vbs", "js", "hta", "wsf", "msi",
                ],
                reasons: Some(UsnReason::FILE_CREATE),
                exclude_patterns: vec![r"Windows\\", r"Program Files"],
                ..Default::default()
            },
        },
        // ── 2. Malware Deployed ───────────────────────────────────────────
        TriageQuestion {
            id: "malware_deployed",
            category: "What Happened",
            question: "What malware or tools are on the system?",
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
        // ── 3. Execution Evidence ─────────────────────────────────────────
        TriageQuestion {
            id: "execution_evidence",
            category: "What Happened",
            question: "What programs did the attacker run?",
            query: TriageQuery {
                path_patterns: vec![r"Prefetch"],
                extension_filter: vec!["pf"],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        },
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TIER 2: "How bad is it?"
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // ── 4. Sensitive Data Accessed ─────────────────────────────────────
        TriageQuestion {
            id: "sensitive_data",
            category: "Business Impact",
            question: "Was sensitive data accessed?",
            query: TriageQuery {
                extension_filter: vec![
                    "docx", "xlsx", "pdf", "txt", "csv", "pst", "ost", "kdbx", "key", "pem", "pfx",
                    "p12",
                ],
                reasons: Some(
                    UsnReason::DATA_EXTEND | UsnReason::CLOSE | UsnReason::DATA_TRUNCATION,
                ),
                exclude_patterns: vec![
                    r"Windows\\",
                    r"ProgramData\\",
                    r"Program Files",
                    r"Packages\\Microsoft\.",
                ],
                ..Default::default()
            },
        },
        // ── 5. Data Staging ───────────────────────────────────────────────
        TriageQuestion {
            id: "data_staging",
            category: "Business Impact",
            question: "Was data staged for theft?",
            query: TriageQuery {
                path_patterns: vec![
                    r"Users\\",
                    r"Desktop",
                    r"Documents",
                    r"Downloads",
                    r"[Tt]emp",
                ],
                extension_filter: vec!["zip", "7z", "rar", "tar", "gz", "cab"],
                reasons: Some(UsnReason::FILE_CREATE),
                exclude_patterns: vec![r"Windows\\", r"Program Files"],
                ..Default::default()
            },
        },
        // ── 6. Credential Access ──────────────────────────────────────────
        TriageQuestion {
            id: "credential_access",
            category: "Business Impact",
            question: "Were credentials compromised?",
            query: TriageQuery {
                // Path patterns match against full_path (includes filename).
                // Hive files are matched by directory path to avoid noisy
                // bare "sam"/"system" hits. Tool names match anywhere in path.
                path_patterns: vec![
                    r"\\config\\SAM\b",
                    r"\\config\\SECURITY\b",
                    r"\\config\\SYSTEM\b",
                    r"ntds\.dit",
                    r"mimikatz",
                    r"procdump",
                    r"lsass\.dmp",
                    r"lazagne",
                    r"rubeus",
                    r"kerberoast",
                    r"secretsdump",
                    r"hashdump",
                    r"pwdump",
                    r"wce\.exe",
                ],
                ..Default::default()
            },
        },
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TIER 3: "Are we still at risk?"
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // ── 7. Persistence / Backdoors ────────────────────────────────────
        TriageQuestion {
            id: "persistence",
            category: "Ongoing Risk",
            question: "Do backdoors or persistence mechanisms remain?",
            query: TriageQuery {
                path_patterns: vec![
                    r"Startup",
                    r"Start Menu",
                    r"\\Tasks\\",
                    r"\\services\\",
                    r"CurrentVersion\\Run",
                    r"WMI\\",
                ],
                extension_filter: vec!["exe", "dll", "bat", "ps1", "cmd", "vbs", "lnk", "job"],
                reasons: Some(UsnReason::FILE_CREATE | UsnReason::RENAME_NEW_NAME),
                ..Default::default()
            },
        },
        // ── 8. Lateral Movement ───────────────────────────────────────────
        TriageQuestion {
            id: "lateral_movement",
            category: "Ongoing Risk",
            question: "Did the attacker move to other systems?",
            query: TriageQuery {
                filename_filter: vec![
                    "rdpclip.exe",
                    "tstheme.exe",
                    "mstsc.exe",
                    "psexec",
                    "paexec",
                    "wmiexec",
                    "smbexec",
                    "winrs.exe",
                    "wsmprovhost.exe",
                    "chisel",
                    "plink.exe",
                    "ncat",
                    "socat",
                ],
                reasons: Some(UsnReason::FILE_CREATE),
                ..Default::default()
            },
        },
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TIER 4: "Did they cover their tracks?"
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // ── 9. Evidence Destruction ───────────────────────────────────────
        TriageQuestion {
            id: "evidence_destruction",
            category: "Cover-Up",
            question: "Did the attacker destroy evidence?",
            query: TriageQuery {
                extension_filter: vec!["evtx", "pf", "log", "etl"],
                reasons: Some(UsnReason::FILE_DELETE | UsnReason::DATA_TRUNCATION),
                path_patterns: vec![r"winevt\\Logs", r"Prefetch", r"\\Logs\\"],
                exclude_patterns: vec![r"WindowsUpdate"],
                ..Default::default()
            },
        },
        // ── 10. Timestomping ──────────────────────────────────────────────
        TriageQuestion {
            id: "timestomping",
            category: "Cover-Up",
            question: "Were file timestamps manipulated?",
            query: TriageQuery {
                // BASIC_INFO_CHANGE on executables suggests timestamp manipulation.
                // The detection module provides confidence scoring; this query
                // catches the raw indicators.
                extension_filter: vec!["exe", "dll", "sys", "bat", "ps1"],
                reasons: Some(UsnReason::BASIC_INFO_CHANGE),
                exclude_patterns: vec![
                    r"Windows\\WinSxS",
                    r"Windows\\assembly",
                    r"WindowsApps",
                    r"Program Files",
                ],
                ..Default::default()
            },
        },
        // ── 11. File Disguise ─────────────────────────────────────────────
        TriageQuestion {
            id: "file_disguise",
            category: "Cover-Up",
            question: "Were files disguised or hidden?",
            query: TriageQuery {
                // Alternate Data Stream operations are almost invisible to every
                // tool except the USN journal. Attackers hide payloads in ADS.
                reasons: Some(
                    UsnReason::NAMED_DATA_EXTEND
                        | UsnReason::NAMED_DATA_OVERWRITE
                        | UsnReason::NAMED_DATA_TRUNCATION,
                ),
                ..Default::default()
            },
        },
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TIER 5: "What did we recover?"
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // ── 12. Recovered Evidence ────────────────────────────────────────
        TriageQuestion {
            id: "recovered_evidence",
            category: "Recovery",
            question: "What did we recover that the attacker deleted?",
            query: TriageQuery {
                source_filter: vec!["entry-carved", "ghost"],
                ..Default::default()
            },
        },
    ]
}
