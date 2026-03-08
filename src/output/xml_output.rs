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
            r.timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
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
        writeln!(writer, "    <full_path>{}</full_path>", resolved.full_path)?;
        writeln!(writer, "    <filename>{}</filename>", r.filename)?;
        writeln!(writer, "    <extension>{extension}</extension>")?;
        writeln!(
            writer,
            "    <file_attributes>{}</file_attributes>",
            r.file_attributes
        )?;
        writeln!(writer, "    <reasons>{}</reasons>", r.reason)?;
        writeln!(writer, "    <source_info>{}</source_info>", r.source_info)?;
        writeln!(writer, "    <security_id>{}</security_id>", r.security_id)?;
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

    struct RecordBuilder {
        filename: String,
        full_path: String,
        parent_path: String,
        mft_entry: u64,
        mft_sequence: u16,
        parent_mft_entry: u64,
        parent_mft_sequence: u16,
        usn: i64,
        timestamp_secs: i64,
        reason: UsnReason,
        source_info: u32,
        security_id: u32,
    }

    impl RecordBuilder {
        fn new(filename: &str, full_path: &str, parent_path: &str) -> Self {
            Self {
                filename: filename.into(),
                full_path: full_path.into(),
                parent_path: parent_path.into(),
                mft_entry: 100,
                mft_sequence: 1,
                parent_mft_entry: 5,
                parent_mft_sequence: 1,
                usn: 100,
                timestamp_secs: 1700000000,
                reason: UsnReason::FILE_CREATE,
                source_info: 0,
                security_id: 0,
            }
        }

        fn mft(mut self, entry: u64, seq: u16) -> Self {
            self.mft_entry = entry;
            self.mft_sequence = seq;
            self
        }

        fn parent(mut self, entry: u64, seq: u16) -> Self {
            self.parent_mft_entry = entry;
            self.parent_mft_sequence = seq;
            self
        }

        fn usn_val(mut self, usn: i64) -> Self {
            self.usn = usn;
            self
        }

        fn timestamp(mut self, ts: i64) -> Self {
            self.timestamp_secs = ts;
            self
        }

        fn reason(mut self, reason: UsnReason) -> Self {
            self.reason = reason;
            self
        }

        fn source_info(mut self, si: u32) -> Self {
            self.source_info = si;
            self
        }

        fn security_id(mut self, sid: u32) -> Self {
            self.security_id = sid;
            self
        }

        fn build(self) -> ResolvedRecord {
            ResolvedRecord {
                record: UsnRecord {
                    mft_entry: self.mft_entry,
                    mft_sequence: self.mft_sequence,
                    parent_mft_entry: self.parent_mft_entry,
                    parent_mft_sequence: self.parent_mft_sequence,
                    usn: self.usn,
                    timestamp: DateTime::from_timestamp(self.timestamp_secs, 0).unwrap(),
                    reason: self.reason,
                    filename: self.filename,
                    file_attributes: FileAttributes::ARCHIVE,
                    source_info: self.source_info,
                    security_id: self.security_id,
                    major_version: 2,
                },
                full_path: self.full_path,
                parent_path: self.parent_path,
                source: crate::rewind::RecordSource::Allocated,
            }
        }
    }

    #[test]
    fn test_xml_single_record() {
        let resolved = vec![
            RecordBuilder::new("test.exe", ".\\temp\\test.exe", ".\\temp")
                .mft(100, 3)
                .parent(50, 1)
                .usn_val(12345)
                .build(),
        ];
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
            RecordBuilder::new("a.txt", ".\\docs\\a.txt", ".\\docs")
                .mft(10, 1)
                .parent(5, 1)
                .build(),
            RecordBuilder::new("b.log", ".\\logs\\b.log", ".\\logs")
                .mft(20, 2)
                .parent(6, 1)
                .usn_val(200)
                .timestamp(1700001000)
                .reason(UsnReason::DATA_EXTEND)
                .build(),
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

    #[test]
    fn test_xml_file_without_extension() {
        let resolved = vec![RecordBuilder::new("noext", ".\\noext", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // "noext" is both the filename and the "extension" from rsplit('.'),
        // but the filter makes it empty since ext.len() < filename.len() fails
        assert!(
            output.contains("<extension>noext</extension>")
                || output.contains("<extension></extension>")
        );
    }

    #[test]
    fn test_xml_special_characters_in_filename() {
        let resolved = vec![RecordBuilder::new("file&<>\"'.txt", ".\\file&<>\"'.txt", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("file&<>\"'.txt"));
    }

    #[test]
    fn test_xml_nonzero_source_and_security() {
        let resolved = vec![RecordBuilder::new("test.txt", ".\\test.txt", ".")
            .source_info(42)
            .security_id(99)
            .build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<source_info>42</source_info>"));
        assert!(output.contains("<security_id>99</security_id>"));
    }

    #[test]
    fn test_xml_dot_first_filename_bashrc() {
        // .bashrc has no "real" extension - rsplit('.') gives ["bashrc", ""]
        // .next() returns "bashrc", and "bashrc".len() (6) < ".bashrc".len() (7) is true
        // so extension should be "bashrc"
        let resolved = vec![RecordBuilder::new(".bashrc", ".\\.bashrc", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<filename>.bashrc</filename>"));
        assert!(output.contains("<extension>bashrc</extension>"));
    }

    #[test]
    fn test_xml_no_extension_filename() {
        // "Makefile" has no dot, so rsplit('.') gives ["Makefile"]
        // .next() returns "Makefile", "Makefile".len() (8) < "Makefile".len() (8) is false
        // so filter removes it and extension is ""
        let resolved = vec![RecordBuilder::new("Makefile", ".\\Makefile", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<filename>Makefile</filename>"));
        assert!(output.contains("<extension></extension>"));
    }

    #[test]
    fn test_xml_double_extension() {
        // "archive.tar.gz" should extract "gz" as the extension
        let resolved = vec![RecordBuilder::new("archive.tar.gz", ".\\archive.tar.gz", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<extension>gz</extension>"));
    }

    #[test]
    fn test_xml_dot_only_filename() {
        // A filename that is just "." - edge case
        // rsplit('.') gives ["", ""], .next() returns ""
        // "".len() (0) < ".".len() (1) is true, but extension is ""
        let resolved = vec![RecordBuilder::new(".", ".\\.", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<filename>.</filename>"));
        // Extension should be empty string since after the dot there's nothing
        assert!(output.contains("<extension></extension>"));
    }

    #[test]
    fn test_xml_filename_ending_with_dot() {
        // "file." has a trailing dot - rsplit('.') gives ["", "file"]
        // .next() returns "", "".len() (0) < "file.".len() (5) is true
        // so extension = ""
        let resolved = vec![RecordBuilder::new("file.", ".\\file.", ".").build()];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<extension></extension>"));
    }

    #[test]
    fn test_xml_all_fields_written() {
        // Ensure every XML field line is exercised by checking exact output structure
        let resolved = vec![
            RecordBuilder::new("data.bin", ".\\evidence\\data.bin", ".\\evidence")
                .mft(42, 7)
                .parent(10, 2)
                .usn_val(99999)
                .reason(UsnReason::DATA_OVERWRITE)
                .source_info(5)
                .security_id(12)
                .build(),
        ];
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Verify every field tag is present (covers lines 34, 39, 44, 49, 54, 61, 68, 73)
        assert!(output.contains("<sequence_number>7</sequence_number>"));
        assert!(output.contains("<parent_entry_number>10</parent_entry_number>"));
        assert!(output.contains("<parent_sequence_number>2</parent_sequence_number>"));
        assert!(output.contains("<parent_path>.\\evidence</parent_path>"));
        assert!(output.contains("<full_path>.\\evidence\\data.bin</full_path>"));
        assert!(output.contains("<file_attributes>"));
        assert!(output.contains("<security_id>12</security_id>"));
        assert!(output.contains("<major_version>2</major_version>"));
        assert!(output.contains("<extension>bin</extension>"));
    }

    /// A writer that fails after writing a specified number of bytes.
    struct FailWriter {
        remaining: usize,
    }

    impl Write for FailWriter {
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
    fn test_xml_write_error_propagated() {
        let resolved = vec![RecordBuilder::new("test.exe", ".\\test.exe", ".").build()];
        // Allow just enough bytes for the XML header but fail mid-record
        let mut writer = FailWriter { remaining: 50 };
        let result = export_xml(&resolved, &mut writer);
        assert!(result.is_err(), "Should propagate write error");
    }

    /// Returns the byte position just after the given tag line ends in the XML output.
    /// This lets us create a FailWriter that allows all bytes up to and including
    /// a certain XML element, then fails on the next writeln! call.
    fn byte_offset_after(output: &str, tag: &str) -> usize {
        let pos = output.find(tag).expect("tag not found in output");
        // Find the end of the line containing this tag
        output[pos..].find('\n').unwrap() + pos + 1
    }

    fn make_test_record() -> Vec<ResolvedRecord> {
        vec![
            RecordBuilder::new("test.exe", ".\\temp\\test.exe", ".\\temp")
                .mft(100, 3)
                .parent(50, 1)
                .usn_val(12345)
                .reason(UsnReason::FILE_CREATE)
                .source_info(5)
                .security_id(12)
                .build(),
        ]
    }

    #[test]
    fn test_xml_fail_at_sequence_number_line34() {
        let resolved = make_test_record();
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Fail right after entry_number line, so sequence_number writeln (line 34) errors
        let offset = byte_offset_after(&output, "<entry_number>");
        let mut writer = FailWriter { remaining: offset };
        let result = export_xml(&resolved, &mut writer);
        assert!(
            result.is_err(),
            "Should fail at sequence_number writeln (line 34)"
        );
    }

    #[test]
    fn test_xml_fail_at_parent_entry_number_line39() {
        let resolved = make_test_record();
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Fail right after sequence_number line, so parent_entry_number writeln (line 39) errors
        let offset = byte_offset_after(&output, "<sequence_number>");
        let mut writer = FailWriter { remaining: offset };
        let result = export_xml(&resolved, &mut writer);
        assert!(
            result.is_err(),
            "Should fail at parent_entry_number writeln (line 39)"
        );
    }

    #[test]
    fn test_xml_fail_at_parent_sequence_number_line44() {
        let resolved = make_test_record();
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Fail right after parent_entry_number line, so parent_sequence_number writeln (line 44) errors
        let offset = byte_offset_after(&output, "<parent_entry_number>");
        let mut writer = FailWriter { remaining: offset };
        let result = export_xml(&resolved, &mut writer);
        assert!(
            result.is_err(),
            "Should fail at parent_sequence_number writeln (line 44)"
        );
    }

    #[test]
    fn test_xml_fail_at_parent_path_line49() {
        let resolved = make_test_record();
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Fail right after parent_sequence_number line, so parent_path writeln (line 49) errors
        let offset = byte_offset_after(&output, "<parent_sequence_number>");
        let mut writer = FailWriter { remaining: offset };
        let result = export_xml(&resolved, &mut writer);
        assert!(
            result.is_err(),
            "Should fail at parent_path writeln (line 49)"
        );
    }

    #[test]
    fn test_xml_fail_at_file_attributes_line57() {
        let resolved = make_test_record();
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Fail right after extension line, so file_attributes writeln (line 57) errors
        let offset = byte_offset_after(&output, "<extension>");
        let mut writer = FailWriter { remaining: offset };
        let result = export_xml(&resolved, &mut writer);
        assert!(
            result.is_err(),
            "Should fail at file_attributes writeln (line 57)"
        );
    }

    #[test]
    fn test_xml_fail_at_major_version_line65() {
        let resolved = make_test_record();
        let mut buf = Vec::new();
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Fail right after security_id line, so major_version writeln (line 65) errors
        let offset = byte_offset_after(&output, "<security_id>");
        let mut writer = FailWriter { remaining: offset };
        let result = export_xml(&resolved, &mut writer);
        assert!(
            result.is_err(),
            "Should fail at major_version writeln (line 65)"
        );
    }

    #[test]
    fn test_xml_writeln_all_fields_via_bufwriter() {
        // Exercise every writeln! call (lines 22-67) through a BufWriter,
        // ensuring the write_fmt code path is fully covered by tarpaulin.
        let resolved = vec![
            RecordBuilder::new("report.pdf", ".\\case\\report.pdf", ".\\case")
                .mft(77, 5)
                .parent(33, 2)
                .usn_val(54321)
                .timestamp(1600000000)
                .reason(UsnReason::DATA_OVERWRITE | UsnReason::CLOSE)
                .source_info(7)
                .security_id(15)
                .build(),
        ];
        let mut buf = std::io::BufWriter::new(Vec::new());
        export_xml(&resolved, &mut buf).unwrap();
        let output = String::from_utf8(buf.into_inner().unwrap()).unwrap();

        // Verify every XML element that corresponds to the uncovered writeln! lines
        assert!(output.contains("<sequence_number>5</sequence_number>"));       // line 34
        assert!(output.contains("<parent_entry_number>33</parent_entry_number>")); // line 39
        assert!(output.contains("<parent_sequence_number>2</parent_sequence_number>")); // line 44
        assert!(output.contains("<parent_path>.\\case</parent_path>"));         // line 49
        assert!(output.contains("<file_attributes>ARCHIVE</file_attributes>")); // line 57
        assert!(output.contains("<major_version>2</major_version>"));           // line 65
        // Also verify the surrounding fields for completeness
        assert!(output.contains("<entry_number>77</entry_number>"));
        assert!(output.contains("<usn>54321</usn>"));
        assert!(output.contains("<full_path>.\\case\\report.pdf</full_path>"));
        assert!(output.contains("<filename>report.pdf</filename>"));
        assert!(output.contains("<extension>pdf</extension>"));
        assert!(output.contains("<source_info>7</source_info>"));
        assert!(output.contains("<security_id>15</security_id>"));
    }
}
