//! Reason breakdown statistics for USN journal records.

use std::collections::HashMap;
use std::io::Write;

use anyhow::Result;

use crate::usn::{UsnReason, UsnRecord};

/// Format reason breakdown statistics for USN records.
///
/// Returns a formatted string suitable for display. Counts each reason flag
/// independently (a record with FILE_CREATE|CLOSE increments both).
pub fn format_reason_stats(records: &[UsnRecord]) -> String {
    let mut reason_counts: HashMap<&str, usize> = HashMap::new();
    let mut v2_count = 0usize;
    let mut v3_count = 0usize;

    for r in records {
        match r.major_version {
            2 => v2_count += 1,
            3 => v3_count += 1,
            _ => {}
        }

        if r.reason.contains(UsnReason::FILE_CREATE) {
            *reason_counts.entry("FILE_CREATE").or_default() += 1;
        }
        if r.reason.contains(UsnReason::FILE_DELETE) {
            *reason_counts.entry("FILE_DELETE").or_default() += 1;
        }
        if r.reason.contains(UsnReason::RENAME_OLD_NAME) {
            *reason_counts.entry("RENAME").or_default() += 1;
        }
        if r.reason.contains(UsnReason::DATA_OVERWRITE) {
            *reason_counts.entry("DATA_OVERWRITE").or_default() += 1;
        }
        if r.reason.contains(UsnReason::DATA_EXTEND) {
            *reason_counts.entry("DATA_EXTEND").or_default() += 1;
        }
        if r.reason.contains(UsnReason::SECURITY_CHANGE) {
            *reason_counts.entry("SECURITY_CHANGE").or_default() += 1;
        }
        if r.reason.contains(UsnReason::BASIC_INFO_CHANGE) {
            *reason_counts.entry("BASIC_INFO_CHANGE").or_default() += 1;
        }
    }

    let mut output = String::new();
    output.push_str(&format!(
        "[*] Record versions: V2={v2_count}, V3={v3_count}\n"
    ));
    output.push_str("[*] Reason breakdown:\n");
    let mut sorted: Vec<_> = reason_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (reason, count) in sorted {
        output.push_str(&format!("    {reason}: {count}\n"));
    }
    output
}

/// Write reason breakdown statistics to a writer (typically stderr).
pub fn write_reason_stats<W: Write>(records: &[UsnRecord], writer: &mut W) -> Result<()> {
    let stats = format_reason_stats(records);
    write!(writer, "{}", stats)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{FileAttributes, UsnReason, UsnRecord};
    use chrono::DateTime;

    fn make_record(reason: UsnReason, version: u16) -> UsnRecord {
        UsnRecord {
            mft_entry: 100,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 1000,
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            reason,
            filename: "test.txt".into(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: version,
        }
    }

    #[test]
    fn test_format_reason_stats_empty() {
        let stats = format_reason_stats(&[]);
        assert!(stats.contains("V2=0, V3=0"));
        assert!(stats.contains("Reason breakdown"));
    }

    #[test]
    fn test_format_reason_stats_v2_records() {
        let records = vec![
            make_record(UsnReason::FILE_CREATE, 2),
            make_record(UsnReason::FILE_CREATE | UsnReason::CLOSE, 2),
            make_record(UsnReason::FILE_DELETE, 2),
        ];
        let stats = format_reason_stats(&records);
        assert!(stats.contains("V2=3, V3=0"));
        assert!(stats.contains("FILE_CREATE: 2"));
        assert!(stats.contains("FILE_DELETE: 1"));
    }

    #[test]
    fn test_format_reason_stats_v3_records() {
        let records = vec![make_record(UsnReason::DATA_EXTEND, 3)];
        let stats = format_reason_stats(&records);
        assert!(stats.contains("V2=0, V3=1"));
        assert!(stats.contains("DATA_EXTEND: 1"));
    }

    #[test]
    fn test_format_reason_stats_mixed_versions() {
        let records = vec![
            make_record(UsnReason::FILE_CREATE, 2),
            make_record(UsnReason::FILE_CREATE, 3),
        ];
        let stats = format_reason_stats(&records);
        assert!(stats.contains("V2=1, V3=1"));
        assert!(stats.contains("FILE_CREATE: 2"));
    }

    #[test]
    fn test_format_reason_stats_all_reasons() {
        let records = vec![
            make_record(UsnReason::FILE_CREATE, 2),
            make_record(UsnReason::FILE_DELETE, 2),
            make_record(UsnReason::RENAME_OLD_NAME, 2),
            make_record(UsnReason::DATA_OVERWRITE, 2),
            make_record(UsnReason::DATA_EXTEND, 2),
            make_record(UsnReason::SECURITY_CHANGE, 2),
            make_record(UsnReason::BASIC_INFO_CHANGE, 2),
        ];
        let stats = format_reason_stats(&records);
        assert!(stats.contains("FILE_CREATE: 1"));
        assert!(stats.contains("FILE_DELETE: 1"));
        assert!(stats.contains("RENAME: 1"));
        assert!(stats.contains("DATA_OVERWRITE: 1"));
        assert!(stats.contains("DATA_EXTEND: 1"));
        assert!(stats.contains("SECURITY_CHANGE: 1"));
        assert!(stats.contains("BASIC_INFO_CHANGE: 1"));
    }

    #[test]
    fn test_format_reason_stats_sorted_by_count() {
        let records = vec![
            make_record(UsnReason::FILE_CREATE, 2),
            make_record(UsnReason::FILE_CREATE, 2),
            make_record(UsnReason::FILE_CREATE, 2),
            make_record(UsnReason::FILE_DELETE, 2),
        ];
        let stats = format_reason_stats(&records);
        let create_pos = stats.find("FILE_CREATE").unwrap();
        let delete_pos = stats.find("FILE_DELETE").unwrap();
        assert!(
            create_pos < delete_pos,
            "Higher count should appear first"
        );
    }

    #[test]
    fn test_format_reason_stats_unknown_version() {
        let records = vec![make_record(UsnReason::FILE_CREATE, 4)];
        let stats = format_reason_stats(&records);
        assert!(stats.contains("V2=0, V3=0"));
        assert!(stats.contains("FILE_CREATE: 1"));
    }

    #[test]
    fn test_write_reason_stats() {
        let records = vec![make_record(UsnReason::FILE_CREATE, 2)];
        let mut buf = Vec::new();
        write_reason_stats(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("FILE_CREATE: 1"));
    }

    #[test]
    fn test_write_reason_stats_write_error() {
        struct FailWriter;
        impl std::io::Write for FailWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fail"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let records = vec![make_record(UsnReason::FILE_CREATE, 2)];
        let result = write_reason_stats(&records, &mut FailWriter);
        assert!(result.is_err());
    }
}
