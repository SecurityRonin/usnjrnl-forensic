/// Sleuthkit bodyfile format output (pipe-delimited, used by mactime/log2timeline).
///
/// Format: `0|full_path|mft_entry|0|0|0|file_size|atime|mtime|ctime|crtime`
use std::io::Write;

use anyhow::Result;

use crate::rewind::ResolvedRecord;

/// Export resolved USN records to Sleuthkit bodyfile format.
pub fn export_body<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    for resolved in records {
        let r = &resolved.record;
        let ts = r.timestamp.timestamp();
        writeln!(
            writer,
            "0|{}|{}|0|0|0|0|{}|{}|{}|{}",
            resolved.full_path, r.mft_entry, ts, ts, ts, ts
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
        mft_entry: u64,
        timestamp_secs: i64,
        reason: UsnReason,
    ) -> ResolvedRecord {
        ResolvedRecord {
            record: UsnRecord {
                mft_entry,
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
    fn test_body_single_record() {
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            100,
            1700000000,
            UsnReason::FILE_CREATE,
        )];
        let mut buf = Vec::new();
        export_body(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim().split('|').collect();
        assert_eq!(
            fields.len(),
            11,
            "bodyfile must have 11 pipe-delimited fields"
        );
        assert_eq!(fields[0], "0", "MD5 is always 0");
        assert_eq!(fields[1], ".\\temp\\test.exe", "full_path");
        assert_eq!(fields[2], "100", "mft_entry");
        assert_eq!(fields[3], "0", "mode");
        assert_eq!(fields[4], "0", "UID");
        assert_eq!(fields[5], "0", "GID");
        assert_eq!(fields[6], "0", "file_size");
        assert_eq!(fields[7], "1700000000", "atime");
        assert_eq!(fields[8], "1700000000", "mtime");
        assert_eq!(fields[9], "1700000000", "ctime");
        assert_eq!(fields[10], "1700000000", "crtime");
    }

    #[test]
    fn test_body_multiple_records() {
        let resolved = vec![
            make_record(
                "a.txt",
                ".\\docs\\a.txt",
                ".\\docs",
                10,
                1700000000,
                UsnReason::FILE_CREATE,
            ),
            make_record(
                "b.log",
                ".\\logs\\b.log",
                ".\\logs",
                20,
                1700001000,
                UsnReason::DATA_EXTEND,
            ),
        ];
        let mut buf = Vec::new();
        export_body(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2, "should have two bodyfile lines");
        assert!(lines[0].contains(".\\docs\\a.txt"));
        assert!(lines[1].contains(".\\logs\\b.log"));
        assert!(lines[1].contains("1700001000"));
    }

    #[test]
    fn test_body_empty_input() {
        let resolved: Vec<ResolvedRecord> = vec![];
        let mut buf = Vec::new();
        export_body(&resolved, &mut buf).unwrap();
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
    fn test_body_write_error_propagated() {
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            100,
            1700000000,
            UsnReason::FILE_CREATE,
        )];
        let mut writer = FailWriter { remaining: 5 };
        let result = export_body(&resolved, &mut writer);
        assert!(result.is_err(), "Should propagate write error");
    }

    #[test]
    fn test_body_write_error_immediate_fail() {
        // Writer that fails on the very first write attempt, ensuring the
        // writeln! formatting line (line 18) is covered when write_fmt fails
        // immediately without accepting any bytes.
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            100,
            1700000000,
            UsnReason::FILE_CREATE,
        )];
        let mut writer = FailWriter { remaining: 0 };
        let result = export_body(&resolved, &mut writer);
        assert!(result.is_err(), "Should fail immediately on first write");
    }

    #[test]
    fn test_body_verifies_all_timestamp_fields() {
        // Ensure the writeln! line 19 is exercised with different timestamps
        let resolved = vec![make_record(
            "data.bin",
            ".\\root\\data.bin",
            ".\\root",
            999,
            1234567890,
            UsnReason::DATA_EXTEND | UsnReason::CLOSE,
        )];
        let mut buf = Vec::new();
        export_body(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Verify all 4 timestamp fields in the bodyfile line
        let fields: Vec<&str> = output.trim().split('|').collect();
        assert_eq!(fields[7], "1234567890");
        assert_eq!(fields[8], "1234567890");
        assert_eq!(fields[9], "1234567890");
        assert_eq!(fields[10], "1234567890");
    }

    #[test]
    fn test_body_writeln_format_exact_line() {
        // Directly exercise the writeln! on line 18 and verify exact output format.
        // Uses a BufWriter to ensure the write path through write_fmt is fully covered.
        let resolved = vec![make_record(
            "payload.dll",
            ".\\Windows\\System32\\payload.dll",
            ".\\Windows\\System32",
            42,
            1600000000,
            UsnReason::FILE_DELETE | UsnReason::CLOSE,
        )];
        let mut buf = std::io::BufWriter::new(Vec::new());
        export_body(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf.into_inner().unwrap()).unwrap();
        assert_eq!(
            output.trim(),
            "0|.\\Windows\\System32\\payload.dll|42|0|0|0|0|1600000000|1600000000|1600000000|1600000000"
        );
    }
}
