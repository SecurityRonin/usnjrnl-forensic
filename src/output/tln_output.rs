/// TLN (5-field pipe-delimited timeline) format output.
///
/// Format: `timestamp|source|host|user|description`
use std::io::Write;

use anyhow::Result;

use crate::rewind::ResolvedRecord;

/// Export resolved USN records to TLN (5-field pipe-delimited timeline) format.
pub fn export_tln<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    for resolved in records {
        let r = &resolved.record;
        let ts = r.timestamp.timestamp();
        writeln!(
            writer,
            "{}|USN|||USN: {} {}",
            ts, r.reason, resolved.full_path
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewind::ResolvedRecord;
    use crate::usn::{FileAttributes, UsnReason, UsnRecord};
    use chrono::DateTime;

    fn make_record(
        filename: &str,
        full_path: &str,
        parent_path: &str,
        timestamp_secs: i64,
        reason: UsnReason,
    ) -> ResolvedRecord {
        ResolvedRecord {
            record: UsnRecord {
                mft_entry: 100,
                mft_sequence: 3,
                parent_mft_entry: 50,
                parent_mft_sequence: 1,
                usn: 12345,
                timestamp: DateTime::from_timestamp(timestamp_secs, 0).unwrap(),
                reason,
                filename: filename.into(),
                file_attributes: FileAttributes::ARCHIVE,
                source_info: 0,
                security_id: 0,
                major_version: 2,
            },
            full_path: full_path.into(),
            parent_path: parent_path.into(),
            source: crate::rewind::RecordSource::Allocated,
        }
    }

    #[test]
    fn test_tln_single_record() {
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            1700000000,
            UsnReason::FILE_CREATE,
        )];
        let mut buf = Vec::new();
        export_tln(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim().split('|').collect();
        assert_eq!(fields.len(), 5, "TLN must have 5 pipe-delimited fields");
        assert_eq!(fields[0], "1700000000", "timestamp as Unix epoch");
        assert_eq!(fields[1], "USN", "source");
        assert_eq!(fields[2], "", "host is empty");
        assert_eq!(fields[3], "", "user is empty");
        assert_eq!(
            fields[4], "USN: FILE_CREATE .\\temp\\test.exe",
            "description"
        );
    }

    #[test]
    fn test_tln_multiple_records() {
        let resolved = vec![
            make_record(
                "a.txt",
                ".\\docs\\a.txt",
                ".\\docs",
                1700000000,
                UsnReason::FILE_CREATE,
            ),
            make_record(
                "b.log",
                ".\\logs\\b.log",
                ".\\logs",
                1700001000,
                UsnReason::DATA_EXTEND,
            ),
        ];
        let mut buf = Vec::new();
        export_tln(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2, "should have two TLN lines");
        assert!(lines[0].contains("USN: FILE_CREATE .\\docs\\a.txt"));
        assert!(lines[1].contains("USN: DATA_EXTEND .\\logs\\b.log"));
    }

    #[test]
    fn test_tln_empty_input() {
        let resolved: Vec<ResolvedRecord> = vec![];
        let mut buf = Vec::new();
        export_tln(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.is_empty(), "empty input should produce empty output");
    }

    /// A writer that fails after writing a specified number of bytes.
    struct FailWriter {
        remaining: usize,
    }

    impl std::io::Write for FailWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("write failed"));
            }
            let n = buf.len().min(self.remaining);
            self.remaining -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_tln_write_error_propagated() {
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            1700000000,
            UsnReason::FILE_CREATE,
        )];
        let mut writer = FailWriter { remaining: 5 };
        let result = export_tln(&resolved, &mut writer);
        assert!(result.is_err(), "Should propagate write error");
    }

    #[test]
    fn test_tln_write_error_immediate_fail() {
        // Writer that fails on the very first write attempt, ensuring the
        // writeln! formatting line (line 18) is covered when write_fmt fails
        // immediately without accepting any bytes.
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            1700000000,
            UsnReason::FILE_CREATE,
        )];
        let mut writer = FailWriter { remaining: 0 };
        let result = export_tln(&resolved, &mut writer);
        assert!(result.is_err(), "Should fail immediately on first write");
    }

    #[test]
    fn test_tln_verifies_reason_in_description() {
        // Ensure the writeln! line 19 is exercised with multiple reason flags
        let resolved = vec![make_record(
            "data.bin",
            ".\\root\\data.bin",
            ".\\root",
            1234567890,
            UsnReason::DATA_EXTEND | UsnReason::CLOSE,
        )];
        let mut buf = Vec::new();
        export_tln(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("1234567890|USN|||USN:"));
        assert!(output.contains(".\\root\\data.bin"));
    }
}
