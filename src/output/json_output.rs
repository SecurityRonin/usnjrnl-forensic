use std::io::Write;

use anyhow::Result;
use serde::Serialize;

use crate::rewind::ResolvedRecord;

#[derive(Serialize)]
struct JsonRecord {
    timestamp: String,
    usn: i64,
    entry_number: u64,
    sequence_number: u16,
    parent_entry_number: u64,
    parent_sequence_number: u16,
    parent_path: String,
    full_path: String,
    filename: String,
    extension: String,
    file_attributes: String,
    reasons: String,
    source_info: u32,
    security_id: u32,
    major_version: u16,
}

/// Export resolved USN records to JSON Lines (one JSON object per line).
pub fn export_jsonl<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    for resolved in records {
        let r = &resolved.record;
        let extension = r
            .filename
            .rsplit('.')
            .next()
            .filter(|ext| ext.len() < r.filename.len())
            .unwrap_or("")
            .to_string();

        let json_rec = JsonRecord {
            timestamp: r.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            usn: r.usn,
            entry_number: r.mft_entry,
            sequence_number: r.mft_sequence,
            parent_entry_number: r.parent_mft_entry,
            parent_sequence_number: r.parent_mft_sequence,
            parent_path: resolved.parent_path.clone(),
            full_path: resolved.full_path.clone(),
            filename: r.filename.clone(),
            extension,
            file_attributes: r.file_attributes.to_string(),
            reasons: r.reason.to_string(),
            source_info: r.source_info,
            security_id: r.security_id,
            major_version: r.major_version,
        };

        serde_json::to_writer(&mut *writer, &json_rec)?;
        writeln!(writer)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{UsnRecord, UsnReason, FileAttributes};
    use crate::rewind::ResolvedRecord;
    use chrono::DateTime;

    #[test]
    fn test_jsonl_export() {
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
            full_path: ".\\temp\\test.exe".into(),
            parent_path: ".\\temp".into(),
        }];
        let mut buf = Vec::new();
        export_jsonl(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed["filename"], "test.exe");
        assert_eq!(parsed["full_path"], ".\\temp\\test.exe");
    }
}
