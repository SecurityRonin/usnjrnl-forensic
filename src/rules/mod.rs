//! Rule engine for pattern-matching USN journal activity.
//!
//! Lets analysts define rules that flag suspicious filenames, reason flags,
//! and combinations thereof. Ships with forensically useful built-in rules.

use regex::Regex;

use crate::usn::{UsnReason, UsnRecord};

// ─── Types ──────────────────────────────────────────────────────────────────

/// Severity level for a matched rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// How to match a filename.
#[derive(Debug, Clone)]
pub enum FilenameMatch {
    /// Shell-style glob: supports `*` (any chars) and `?` (single char).
    Glob(String),
    /// Full regex pattern.
    Regex(String),
    /// Match file extension (e.g. `".ps1"`).
    Extension(String),
}

/// A single detection rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub filename_match: Option<FilenameMatch>,
    /// Glob pattern; files matching this are excluded even if filename_match hits.
    pub exclude_pattern: Option<String>,
    /// Match if ANY of these reason flags are present on the record.
    pub any_reasons: Option<UsnReason>,
    /// Match only if ALL of these reason flags are present on the record.
    pub all_reasons: Option<UsnReason>,
}

/// Result of a rule matching a record.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_name: String,
    pub severity: Severity,
    pub record: UsnRecord,
    pub description: String,
}

/// A collection of rules evaluated against USN records.
pub struct RuleSet {
    rules: Vec<Rule>,
}

// ─── Glob matching (manual, no deps) ───────────────────────────────────────

/// Simple case-insensitive glob match supporting `*` (any chars) and `?` (single char).
fn glob_matches(pattern: &str, text: &str) -> bool {
    glob_matches_inner(
        pattern.to_ascii_lowercase().as_bytes(),
        text.to_ascii_lowercase().as_bytes(),
    )
}

fn glob_matches_inner(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

// ─── Rule evaluation ────────────────────────────────────────────────────────

impl Rule {
    /// Check whether this rule matches the given record. Returns `true` if all
    /// configured conditions are satisfied (AND logic across condition types).
    fn matches(&self, record: &UsnRecord) -> bool {
        // Check exclude pattern first
        if let Some(ref exclude) = self.exclude_pattern {
            if glob_matches(exclude, &record.filename) {
                return false;
            }
        }

        // Check filename match
        if let Some(ref fm) = self.filename_match {
            let name_ok = match fm {
                FilenameMatch::Glob(pat) => glob_matches(pat, &record.filename),
                FilenameMatch::Regex(pat) => {
                    if let Ok(re) = Regex::new(pat) {
                        re.is_match(&record.filename)
                    } else {
                        false
                    }
                }
                FilenameMatch::Extension(ext) => {
                    let lower = record.filename.to_ascii_lowercase();
                    let ext_lower = ext.to_ascii_lowercase();
                    lower.ends_with(&ext_lower)
                }
            };
            if !name_ok {
                return false;
            }
        }

        // Check any_reasons (OR logic: record must have at least one of the flags)
        if let Some(any) = self.any_reasons {
            if !record.reason.intersects(any) {
                return false;
            }
        }

        // Check all_reasons (AND logic: record must have every flag)
        if let Some(all) = self.all_reasons {
            if !record.reason.contains(all) {
                return false;
            }
        }

        true
    }
}

// ─── RuleSet ────────────────────────────────────────────────────────────────

impl RuleSet {
    /// Create an empty rule set.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create a rule set from a pre-built list of rules.
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Add a rule to the set.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Evaluate all rules against a single record and return every match.
    pub fn evaluate(&self, record: &UsnRecord) -> Vec<RuleMatch> {
        self.rules
            .iter()
            .filter(|r| r.matches(record))
            .map(|r| RuleMatch {
                rule_name: r.name.clone(),
                severity: r.severity,
                record: record.clone(),
                description: r.description.clone(),
            })
            .collect()
    }

    /// Create a rule set pre-loaded with forensically useful built-in rules.
    pub fn with_builtins() -> Self {
        let mut rs = Self::new();

        // ── suspicious_executables (High) ───────────────────────────────
        rs.add_rule(Rule {
            name: "suspicious_executables".into(),
            description: "Known offensive tool or suspicious executable detected".into(),
            severity: Severity::High,
            filename_match: Some(FilenameMatch::Regex(
                r"(?i)^(psexec(64)?|mimikatz|procdump(64)?|lazagne|rubeus|sharphound|bloodhound|cobalt|beacon|meterpreter|nc(at)?|whoami|pwdump|wce|gsecdump|secretsdump|kekeo|safetykatz)(\..+)?$".into(),
            )),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        });

        // ── ransomware_extensions (Critical) ────────────────────────────
        rs.add_rule(Rule {
            name: "ransomware_extensions".into(),
            description: "File with ransomware-associated extension detected".into(),
            severity: Severity::Critical,
            filename_match: Some(FilenameMatch::Regex(
                r"(?i)\.(encrypted|locked|crypto|crypt|enc|pay|ransom|locky|cerber|wcry|wncry|wncryt|zepto|odin|thor|aesir|osiris|hermes|dharma|phobos|ryuk|maze|conti|lockbit|hive)$".into(),
            )),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        });

        // ── secure_delete_pattern (High) ────────────────────────────────
        // SDelete renames files to sequences of the same character (AAAA, BBBB, ..., ZZZZ).
        // The regex crate doesn't support backreferences, so we enumerate A-Z repeats.
        {
            let alts: Vec<String> = (b'A'..=b'Z')
                .map(|c| format!("{c}{{{min},}}", c = c as char, min = 5))
                .collect();
            let pattern = format!(r"^({alts})\..+$", alts = alts.join("|"));
            rs.add_rule(Rule {
                name: "secure_delete_pattern".into(),
                description: "SDelete-style secure deletion pattern detected (repeated character filename)".into(),
                severity: Severity::High,
                filename_match: Some(FilenameMatch::Regex(pattern)),
                exclude_pattern: None,
                any_reasons: None,
                all_reasons: None,
            });
        }

        // ── script_execution (Medium) ───────────────────────────────────
        rs.add_rule(Rule {
            name: "script_execution".into(),
            description: "Script file activity detected".into(),
            severity: Severity::Medium,
            filename_match: Some(FilenameMatch::Regex(
                r"(?i)\.(ps1|vbs|bat|cmd|js|wsf|hta|wsh|sct)$".into(),
            )),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        });

        // ── credential_access (High) ────────────────────────────────────
        rs.add_rule(Rule {
            name: "credential_access".into(),
            description: "Activity on credential-related file detected".into(),
            severity: Severity::High,
            filename_match: Some(FilenameMatch::Regex(
                r"(?i)(ntds\.dit|sam|security|system)".into(),
            )),
            exclude_pattern: None,
            any_reasons: Some(UsnReason::FILE_CREATE | UsnReason::DATA_OVERWRITE),
            all_reasons: None,
        });

        rs
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use crate::usn::{FileAttributes, UsnReason, UsnRecord};

    /// Helper: build a minimal UsnRecord for testing.
    fn make_record(filename: &str, reason: UsnReason) -> UsnRecord {
        UsnRecord {
            mft_entry: 1,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 0,
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::from_bits_retain(0x20),
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    // ── Filename matching ───────────────────────────────────────────────

    #[test]
    fn test_rule_matches_filename_glob() {
        let rule = Rule {
            name: "exe_files".into(),
            description: "Detect executables".into(),
            severity: Severity::Medium,
            filename_match: Some(FilenameMatch::Glob("*.exe".into())),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("malware.exe", UsnReason::FILE_CREATE);
        let miss = make_record("readme.txt", UsnReason::FILE_CREATE);

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&miss).len(), 0);
    }

    #[test]
    fn test_rule_matches_filename_regex() {
        let rule = Rule {
            name: "exact_cmd".into(),
            description: "Exact cmd.exe".into(),
            severity: Severity::High,
            filename_match: Some(FilenameMatch::Regex(r"^cmd\.exe$".into())),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("cmd.exe", UsnReason::FILE_CREATE);
        let miss = make_record("xcmd.exe", UsnReason::FILE_CREATE);

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&miss).len(), 0);
    }

    #[test]
    fn test_rule_matches_extension() {
        let rule = Rule {
            name: "ps1".into(),
            description: "PowerShell scripts".into(),
            severity: Severity::Medium,
            filename_match: Some(FilenameMatch::Extension(".ps1".into())),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("invoke-mimikatz.ps1", UsnReason::FILE_CREATE);
        let miss = make_record("readme.txt", UsnReason::FILE_CREATE);

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&miss).len(), 0);
    }

    // ── Reason-flag matching ────────────────────────────────────────────

    #[test]
    fn test_rule_matches_reason_flags() {
        let rule = Rule {
            name: "created".into(),
            description: "File created".into(),
            severity: Severity::Info,
            filename_match: None,
            exclude_pattern: None,
            any_reasons: Some(UsnReason::FILE_CREATE),
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("anything.txt", UsnReason::FILE_CREATE);
        let miss = make_record("anything.txt", UsnReason::FILE_DELETE);

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&miss).len(), 0);
    }

    #[test]
    fn test_rule_matches_reason_any() {
        let rule = Rule {
            name: "create_or_delete".into(),
            description: "Created or deleted".into(),
            severity: Severity::Low,
            filename_match: None,
            exclude_pattern: None,
            any_reasons: Some(UsnReason::FILE_CREATE | UsnReason::FILE_DELETE),
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit1 = make_record("a.txt", UsnReason::FILE_CREATE);
        let hit2 = make_record("b.txt", UsnReason::FILE_DELETE);
        let miss = make_record("c.txt", UsnReason::DATA_OVERWRITE);

        assert_eq!(ruleset.evaluate(&hit1).len(), 1);
        assert_eq!(ruleset.evaluate(&hit2).len(), 1);
        assert_eq!(ruleset.evaluate(&miss).len(), 0);
    }

    #[test]
    fn test_rule_matches_reason_all() {
        let rule = Rule {
            name: "create_and_close".into(),
            description: "Created and closed".into(),
            severity: Severity::Low,
            filename_match: None,
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: Some(UsnReason::FILE_CREATE | UsnReason::CLOSE),
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("a.txt", UsnReason::FILE_CREATE | UsnReason::CLOSE);
        let miss = make_record("b.txt", UsnReason::FILE_CREATE); // missing CLOSE

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&miss).len(), 0);
    }

    // ── Combined conditions ─────────────────────────────────────────────

    #[test]
    fn test_rule_combined_conditions() {
        let rule = Rule {
            name: "exe_created".into(),
            description: "Executable created".into(),
            severity: Severity::High,
            filename_match: Some(FilenameMatch::Glob("*.exe".into())),
            exclude_pattern: None,
            any_reasons: Some(UsnReason::FILE_CREATE),
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("bad.exe", UsnReason::FILE_CREATE);
        let miss_name = make_record("bad.txt", UsnReason::FILE_CREATE);
        let miss_reason = make_record("bad.exe", UsnReason::FILE_DELETE);

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&miss_name).len(), 0);
        assert_eq!(ruleset.evaluate(&miss_reason).len(), 0);
    }

    // ── Negation / exclude ──────────────────────────────────────────────

    #[test]
    fn test_rule_negation() {
        let rule = Rule {
            name: "exe_not_svchost".into(),
            description: "Executables except svchost".into(),
            severity: Severity::Medium,
            filename_match: Some(FilenameMatch::Glob("*.exe".into())),
            exclude_pattern: Some("svchost*".into()),
            any_reasons: None,
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let hit = make_record("malware.exe", UsnReason::FILE_CREATE);
        let excluded = make_record("svchost.exe", UsnReason::FILE_CREATE);

        assert_eq!(ruleset.evaluate(&hit).len(), 1);
        assert_eq!(ruleset.evaluate(&excluded).len(), 0);
    }

    // ── RuleSet tests ───────────────────────────────────────────────────

    #[test]
    fn test_ruleset_evaluates_all_rules() {
        let rules = vec![
            Rule {
                name: "rule_a".into(),
                description: "A".into(),
                severity: Severity::Low,
                filename_match: Some(FilenameMatch::Glob("*.exe".into())),
                exclude_pattern: None,
                any_reasons: None,
                all_reasons: None,
            },
            Rule {
                name: "rule_b".into(),
                description: "B".into(),
                severity: Severity::Medium,
                filename_match: Some(FilenameMatch::Extension(".exe".into())),
                exclude_pattern: None,
                any_reasons: None,
                all_reasons: None,
            },
            Rule {
                name: "rule_c".into(),
                description: "C".into(),
                severity: Severity::High,
                filename_match: None,
                exclude_pattern: None,
                any_reasons: Some(UsnReason::FILE_CREATE),
                all_reasons: None,
            },
        ];
        let ruleset = RuleSet::from_rules(rules);

        let rec = make_record("evil.exe", UsnReason::FILE_CREATE);
        let matches = ruleset.evaluate(&rec);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_ruleset_returns_rule_name_and_severity() {
        let rule = Rule {
            name: "test_rule".into(),
            description: "A test".into(),
            severity: Severity::Critical,
            filename_match: Some(FilenameMatch::Glob("*.exe".into())),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let rec = make_record("payload.exe", UsnReason::FILE_CREATE);
        let matches = ruleset.evaluate(&rec);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "test_rule");
        assert_eq!(matches[0].severity, Severity::Critical);
        assert_eq!(matches[0].description, "A test");
    }

    #[test]
    fn test_rule_no_match_returns_empty() {
        let rule = Rule {
            name: "exe_only".into(),
            description: "Only exe".into(),
            severity: Severity::Medium,
            filename_match: Some(FilenameMatch::Glob("*.exe".into())),
            exclude_pattern: None,
            any_reasons: None,
            all_reasons: None,
        };
        let ruleset = RuleSet::from_rules(vec![rule]);

        let rec = make_record("safe.docx", UsnReason::DATA_OVERWRITE);
        assert!(ruleset.evaluate(&rec).is_empty());
    }

    // ── Built-in rules ──────────────────────────────────────────────────

    #[test]
    fn test_builtin_suspicious_executables() {
        let ruleset = RuleSet::with_builtins();

        for name in &["psexec.exe", "PsExec64.exe", "mimikatz.exe", "procdump.exe", "lazagne.exe"] {
            let rec = make_record(name, UsnReason::FILE_CREATE);
            let matches = ruleset.evaluate(&rec);
            let hit = matches.iter().any(|m| m.rule_name == "suspicious_executables");
            assert!(hit, "Expected suspicious_executables to match '{}'", name);
        }

        let safe = make_record("notepad.exe", UsnReason::FILE_CREATE);
        let matches = ruleset.evaluate(&safe);
        let hit = matches.iter().any(|m| m.rule_name == "suspicious_executables");
        assert!(!hit, "notepad.exe should NOT trigger suspicious_executables");
    }

    #[test]
    fn test_builtin_ransomware_extensions() {
        let ruleset = RuleSet::with_builtins();

        for name in &[
            "document.encrypted",
            "photo.locked",
            "data.crypto",
            "file.crypt",
            "report.enc",
            "budget.pay",
            "backup.ransom",
        ] {
            let rec = make_record(name, UsnReason::RENAME_NEW_NAME);
            let matches = ruleset.evaluate(&rec);
            let hit = matches.iter().any(|m| m.rule_name == "ransomware_extensions");
            assert!(hit, "Expected ransomware_extensions to match '{}'", name);
        }

        let safe = make_record("report.pdf", UsnReason::RENAME_NEW_NAME);
        let matches = ruleset.evaluate(&safe);
        let hit = matches.iter().any(|m| m.rule_name == "ransomware_extensions");
        assert!(!hit, "report.pdf should NOT trigger ransomware_extensions");
    }

    #[test]
    fn test_builtin_secure_delete() {
        let ruleset = RuleSet::with_builtins();

        for name in &["AAAAAAAAAAAA.txt", "BBBBBBBB.dat", "ZZZZZZZZZZ.bin"] {
            let rec = make_record(name, UsnReason::RENAME_NEW_NAME);
            let matches = ruleset.evaluate(&rec);
            let hit = matches.iter().any(|m| m.rule_name == "secure_delete_pattern");
            assert!(hit, "Expected secure_delete_pattern to match '{}'", name);
        }

        let safe = make_record("ABCDEF.txt", UsnReason::RENAME_NEW_NAME);
        let matches = ruleset.evaluate(&safe);
        let hit = matches.iter().any(|m| m.rule_name == "secure_delete_pattern");
        assert!(!hit, "ABCDEF.txt should NOT trigger secure_delete_pattern");
    }
}
