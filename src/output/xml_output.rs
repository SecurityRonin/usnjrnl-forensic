/// XML output format for USN Journal records.

use std::io::Write;

use anyhow::Result;

use crate::rewind::ResolvedRecord;

/// Export resolved USN records to XML format.
pub fn export_xml<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    writeln!(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(writer, "<usnjrnl>")?;
    for resolved in records {
        let r = &resolved.record;
        let extension = r
            .filename
            .rsplit('.')
            .next()
            .filter(|ext| ext.len() < r.filename.len())
            .unwrap_or("")
            .to_string();

        writeln!(writer, "  <record>")?;
        writeln!(
            writer,
            "    <timestamp>{}</timestamp>",
            r.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        )?;
        writeln!(writer, "    <usn>{}</usn>", r.usn)?;
        writeln!(writer, "    <entry_number>{}</entry_number>", r.mft_entry)?;
        writeln!(
            writer,
            "    <sequence_number>{}</sequence_number>",
            r.mft_sequence
        )?;
        writeln!(
            writer,
            "    <parent_entry_number>{}</parent_entry_number>",
            r.parent_mft_entry
        )?;
        writeln!(
            writer,
            "    <parent_sequence_number>{}</parent_sequence_number>",
            r.parent_mft_sequence
        )?;
        writeln!(
            writer,
            "    <parent_path>{}</parent_path>",
            resolved.parent_path
        )?;
        writeln!(
            writer,
            "    <full_path>{}</full_path>",
            resolved.full_path
        )?;
        writeln!(writer, "    <filename>{}</filename>", r.filename)?;
        writeln!(writer, "    <extension>{}</extension>", extension)?;
        writeln!(
            writer,
            "    <file_attributes>{}</file_attributes>",
            r.file_attributes
        )?;
        writeln!(writer, "    <reasons>{}</reasons>", r.reason)?;
        writeln!(writer, "    <source_info>{}</source_info>", r.source_info)?;
        writeln!(
            writer,
            "    <security_id>{}</security_id>",
            r.security_id
        )?;
        writeln!(
            writer,
            "    <major_version>{}</major_version>",
            r.major_version
        )?;
        writeln!(writer, "  </record>")?;
    }
    writeln!(writer, "</usnjrnl>")?;
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
        mft_sequence: u16,
        parent_mft_entry: u64,
        parent_mft_sequence: u16,
        usn: i64,
        timestamp_secs: i64,
        reason: UsnReason,
        source_info: u32,
        security_id: u32,
    ) -> ResolvedRecord {
        ResolvedRecord {
            record: UsnRecord {
                mft_entry,
                mft_sequence,
                parent_mft_entry,
                parent_mft_sequence,
                usn,
                timestamp: DateTime::from_timestamp(timestamp_secs, 0).unwrap(),
                reason,
                filename: filename.into(),
                file_attributes: FileAttributes::ARCHIVE,
                source_info,
                security_id,
                major_version: 2,
            },
            full_path: full_path.into(),
            parent_path: parent_path.into(),
        }
    }

    #[test]
    fn test_xml_single_record() {
        let resolved = vec![make_record(
            "test.exe",
            ".\\temp\\test.exe",
            ".\\temp",
            100, 3, 50, 1, 12345,
            1700000000,
            UsnReason::FILE_CREATE,
            0, 0,
        )];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(output.contains("<usnjrnl>"));
        assert!(output.contains("</usnjrnl>"));
        assert!(output.contains("<record>"));
        assert!(output.contains("</record>"));
        assert!(output.contains("<filename>test.exe</filename>"));
        assert!(output.contains("<full_path>.\\temp\\test.exe</full_path>"));
        assert!(output.contains("<parent_path>.\\temp</parent_path>"));
        assert!(output.contains("<entry_number>100</entry_number>"));
        assert!(output.contains("<sequence_number>3</sequence_number>"));
        assert!(output.contains("<parent_entry_number>50</parent_entry_number>"));
        assert!(output.contains("<parent_sequence_number>1</parent_sequence_number>"));
        assert!(output.contains("<usn>12345</usn>"));
        assert!(output.contains("<reasons>FILE_CREATE</reasons>"));
        assert!(output.contains("<file_attributes>ARCHIVE</file_attributes>"));
        assert!(output.contains("<source_info>0</source_info>"));
        assert!(output.contains("<security_id>0</security_id>"));
        assert!(output.contains("<major_version>2</major_version>"));
        assert!(output.contains("<extension>exe</extension>"));
        assert!(output.contains("<timestamp>"));
    }

    #[test]
    fn test_xml_multiple_records() {
        let resolved = vec![
            make_record("a.txt", ".\\docs\\a.txt", ".\\docs", 10, 1, 5, 1, 100, 1700000000, UsnReason::FILE_CREATE, 0, 0),
            make_record("b.log", ".\\logs\\b.log", ".\\logs", 20, 2, 6, 1, 200, 1700001000, UsnReason::DATA_EXTEND, 0, 0),
        ];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Count record tags - should be exactly 2
        let record_count = output.matches("<record>").count();
        assert_eq!(record_count, 2, "should have two <record> elements");
        assert!(output.contains("<filename>a.txt</filename>"));
        assert!(output.contains("<filename>b.log</filename>"));
    }

    #[test]
    fn test_xml_empty_input() {
        let resolved: Vec<ResolvedRecord> = vec![];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(output.contains("<usnjrnl>"));
        assert!(output.contains("</usnjrnl>"));
        assert!(!output.contains("<record>"), "no records for empty input");
    }
}
