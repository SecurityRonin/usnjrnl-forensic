use std::io::Write;

use anyhow::Result;

use crate::rewind::ResolvedRecord;

/// Export resolved USN records to CSV.
///
/// Compatible with MFTECmd CSV format for interoperability.
pub fn export_csv<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    // Header matching MFTECmd format
    wtr.write_record(&[
        "UpdateTimestamp",
        "UpdateSequenceNumber",
        "EntryNumber",
        "SequenceNumber",
        "ParentEntryNumber",
        "ParentSequenceNumber",
        "ParentPath",
        "FileName",
        "Extension",
        "FileAttributes",
        "UpdateReasons",
        "SourceInfo",
        "SecurityId",
        "MajorVersion",
    ])?;

    for resolved in records {
        let r = &resolved.record;
        let extension = r
            .filename
            .rsplit('.')
            .next()
            .filter(|ext| ext.len() < r.filename.len())
            .unwrap_or("");

        wtr.write_record(&[
            r.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            r.usn.to_string(),
            r.mft_entry.to_string(),
            r.mft_sequence.to_string(),
            r.parent_mft_entry.to_string(),
            r.parent_mft_sequence.to_string(),
            resolved.parent_path.clone(),
            r.filename.clone(),
            extension.to_string(),
            r.file_attributes.to_string(),
            r.reason.to_string(),
            r.source_info.to_string(),
            r.security_id.to_string(),
            r.major_version.to_string(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{UsnRecord, UsnReason, FileAttributes};
    use crate::rewind::ResolvedRecord;
    use chrono::DateTime;

    #[test]
    fn test_csv_export_header() {
        let records: Vec<ResolvedRecord> = vec![];
        let mut buf = Vec::new();
        export_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("UpdateTimestamp"));
        assert!(output.contains("ParentPath"));
        assert!(output.contains("FileName"));
    }

    #[test]
    fn test_csv_export_record() {
        let record = UsnRecord {
            mft_entry: 100,
            mft_sequence: 3,
            parent_mft_entry: 50,
            parent_mft_sequence: 1,
            usn: 12345,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason: UsnReason::FILE_CREATE,
            filename: "test.exe".into(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };
        let resolved = vec![ResolvedRecord {
            record,
            full_path: ".\\Users\\test.exe".into(),
            parent_path: ".\\Users".into(),
        }];
        let mut buf = Vec::new();
        export_csv(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("test.exe"));
        assert!(output.contains(".\\Users"));
        assert!(output.contains("FILE_CREATE"));
    }
}
