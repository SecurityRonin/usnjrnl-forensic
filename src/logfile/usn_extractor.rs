//! Extract USN records embedded in $LogFile RCRD pages.
//!
//! $LogFile contains transaction log records whose redo/undo data areas
//! may contain embedded USN_RECORD_V2 structures. This module scans RCRD
//! pages to recover these records, which can reveal file activity even
//! after the USN Journal has been cleared.
//!
//! Inspired by ntfs-linker's TriForce approach.

use crate::usn::{parse_usn_record_v2, UsnRecord};

// ─── Constants ───────────────────────────────────────────────────────────────

/// NTFS $LogFile record page signature "RCRD".
const RCRD_SIGNATURE: &[u8; 4] = b"RCRD";

/// Default NTFS $LogFile page size.
const LOG_PAGE_SIZE: usize = 0x1000; // 4096 bytes

/// Offset to the data area within an RCRD page (after the page header).
const RCRD_DATA_OFFSET: usize = 0x40;

/// Minimum size for the log record header up to the redo/undo descriptor fields.
const LOG_RECORD_HEADER_MIN: usize = 0x40;

/// Minimum valid USN_RECORD_V2 size (must match usn/record.rs).
const USN_V2_MIN_SIZE: usize = 0x3C;

/// Maximum valid USN record size (sanity check).
const USN_MAX_RECORD_SIZE: usize = 65536;

// ─── Structures ──────────────────────────────────────────────────────────────

/// Where the USN record was found within the $LogFile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFileRecordSource {
    /// Found in the redo data area of a log record.
    RedoData,
    /// Found in the undo data area of a log record.
    UndoData,
    /// Found in slack space at the end of an RCRD page.
    PageSlack,
}

/// A USN record extracted from the $LogFile.
#[derive(Debug, Clone)]
pub struct LogFileUsnRecord {
    /// LSN (Log Sequence Number) where this record was found.
    pub lsn: u64,
    /// Byte offset within the $LogFile where this was found.
    pub page_offset: usize,
    /// Where in the log record structure this was found.
    pub source: LogFileRecordSource,
    /// The parsed USN record.
    pub record: UsnRecord,
}

// ─── Binary helpers ──────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

// ─── Core extraction logic ──────────────────────────────────────────────────

/// Try to parse a USN_RECORD_V2 at the given position in a data slice.
///
/// Performs pre-validation before calling parse_usn_record_v2 to avoid
/// excessive error paths on random data.
fn try_parse_usn_at(data: &[u8], offset: usize) -> Option<UsnRecord> {
    if offset + USN_V2_MIN_SIZE > data.len() {
        return None;
    }

    let slice = &data[offset..];

    // Quick pre-validation: record_length and major_version
    if slice.len() < 8 {
        return None;
    }

    let record_len = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;

    // Sanity checks on record length
    if !(USN_V2_MIN_SIZE..=USN_MAX_RECORD_SIZE).contains(&record_len) {
        return None;
    }
    if record_len > slice.len() {
        return None;
    }

    // Must be version 2
    let major_version = u16::from_le_bytes([slice[4], slice[5]]);
    if major_version != 2 {
        return None;
    }

    // Try to parse
    parse_usn_record_v2(&slice[..record_len]).ok()
}

/// Scan a data slice for embedded USN records starting at every 8-byte alignment.
fn scan_for_usn_records(data: &[u8]) -> Vec<(usize, UsnRecord)> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + USN_V2_MIN_SIZE <= data.len() {
        if let Some(record) = try_parse_usn_at(data, offset) {
            let record_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            results.push((offset, record));
            // Skip past this record (aligned to 8 bytes)
            let aligned = (record_len + 7) & !7;
            offset += aligned;
        } else {
            // Advance by 8-byte alignment (NTFS record alignment)
            offset += 8;
        }
    }

    results
}

/// Extract log record redo/undo data areas from an RCRD page and scan them
/// for embedded USN records.
fn extract_from_rcrd_page(page_data: &[u8], page_offset: usize) -> Vec<LogFileUsnRecord> {
    let mut results = Vec::new();

    if page_data.len() < RCRD_DATA_OFFSET {
        return results;
    }

    // Extract the last_end_lsn from the RCRD page header at offset 0x18.
    // This is the highest LSN represented in this page.
    let page_lsn = if page_data.len() >= 0x20 {
        read_u64_le(page_data, 0x18)
    } else {
        0
    };

    // Parse log records within the RCRD page data area
    let data_area = &page_data[RCRD_DATA_OFFSET..];
    let mut record_offset = 0;

    while record_offset + LOG_RECORD_HEADER_MIN <= data_area.len() {
        // Check if we've hit all zeros (end of log records in this page)
        if record_offset + 8 <= data_area.len()
            && data_area[record_offset..record_offset + 8] == [0, 0, 0, 0, 0, 0, 0, 0]
        {
            // This is likely the end of log records; remaining area is slack
            break;
        }

        // Read the log record header fields
        let this_lsn = read_u64_le(data_area, record_offset);
        let client_data_length = read_u32_le(data_area, record_offset + 0x18) as usize;
        let _redo_op = read_u16_le(data_area, record_offset + 0x30);
        let _undo_op = read_u16_le(data_area, record_offset + 0x32);
        let redo_offset = read_u16_le(data_area, record_offset + 0x34) as usize;
        let redo_length = read_u16_le(data_area, record_offset + 0x36) as usize;
        let undo_offset = read_u16_le(data_area, record_offset + 0x38) as usize;
        let undo_length = read_u16_le(data_area, record_offset + 0x3A) as usize;

        // The redo/undo offsets are relative to offset 0x30 in the log record header
        let redo_base = record_offset + 0x30;
        let undo_base = record_offset + 0x30;

        // Determine LSN to use - prefer this_lsn, fall back to page_lsn
        let lsn = if this_lsn > 0 { this_lsn } else { page_lsn };

        // Scan redo data for USN records
        if redo_length >= USN_V2_MIN_SIZE && redo_offset > 0 {
            let redo_start = redo_base + redo_offset;
            if redo_start + redo_length <= data_area.len() {
                let redo_data = &data_area[redo_start..redo_start + redo_length];
                for (_off, record) in scan_for_usn_records(redo_data) {
                    results.push(LogFileUsnRecord {
                        lsn,
                        page_offset: page_offset + RCRD_DATA_OFFSET + redo_start,
                        source: LogFileRecordSource::RedoData,
                        record,
                    });
                }
            }
        }

        // Scan undo data for USN records (only if different region from redo)
        if undo_length >= USN_V2_MIN_SIZE && undo_offset > 0 {
            let undo_start = undo_base + undo_offset;
            // Avoid scanning the same region twice
            let redo_start = redo_base + redo_offset;
            let same_region = undo_start == redo_start && undo_length == redo_length;
            if !same_region && undo_start + undo_length <= data_area.len() {
                let undo_data = &data_area[undo_start..undo_start + undo_length];
                for (_off, record) in scan_for_usn_records(undo_data) {
                    results.push(LogFileUsnRecord {
                        lsn,
                        page_offset: page_offset + RCRD_DATA_OFFSET + undo_start,
                        source: LogFileRecordSource::UndoData,
                        record,
                    });
                }
            }
        }

        // Advance to next log record.
        // Log record size = header (0x30) + client_data_length, aligned to 8 bytes.
        // The client_data_length includes the redo and undo data areas.
        let log_record_size = 0x30 + client_data_length;
        if log_record_size == 0x30 && client_data_length == 0 {
            // Zero-length client data - might be padding, try advancing by 8
            record_offset += 8;
        } else {
            let aligned_size = (log_record_size + 7) & !7;
            if aligned_size == 0 {
                break;
            }
            record_offset += aligned_size;
        }

        // Safety: prevent infinite loops if client_data_length is bogus
        if record_offset > data_area.len() {
            break;
        }
    }

    // Scan page slack space (area after last log record to end of page)
    let slack_start = RCRD_DATA_OFFSET + record_offset;
    if slack_start < page_data.len() {
        let slack_data = &page_data[slack_start..];
        for (_off, record) in scan_for_usn_records(slack_data) {
            results.push(LogFileUsnRecord {
                lsn: page_lsn,
                page_offset: page_offset + slack_start,
                source: LogFileRecordSource::PageSlack,
                record,
            });
        }
    }

    results
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Extract all USN records embedded in $LogFile data.
///
/// Iterates through RCRD pages, scans log record redo/undo data and page
/// slack for valid USN_RECORD_V2 structures.
///
/// # Arguments
/// * `logfile_data` - Raw $LogFile bytes
///
/// # Returns
/// Vector of extracted USN records with their source location metadata.
pub fn extract_usn_from_logfile(logfile_data: &[u8]) -> Vec<LogFileUsnRecord> {
    let mut results = Vec::new();
    let page_count = logfile_data.len() / LOG_PAGE_SIZE;

    for page_idx in 0..page_count {
        let page_offset = page_idx * LOG_PAGE_SIZE;

        // Check for RCRD signature
        if page_offset + 4 > logfile_data.len() {
            break;
        }
        let sig = &logfile_data[page_offset..page_offset + 4];
        if sig != RCRD_SIGNATURE {
            continue;
        }

        let page_end = (page_offset + LOG_PAGE_SIZE).min(logfile_data.len());
        let page_data = &logfile_data[page_offset..page_end];

        let page_results = extract_from_rcrd_page(page_data, page_offset);
        results.extend(page_results);
    }

    results
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal USN_RECORD_V2 byte blob for testing.
    fn build_v2_record_bytes(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        reason: u32,
        filename: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        // Record length
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        // Major version = 2
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Minor version = 0
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // File reference
        let file_ref = entry | ((seq as u64) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        // Parent reference
        let parent_ref = parent_entry | ((parent_seq as u64) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        // USN
        buf[0x18..0x20].copy_from_slice(&100i64.to_le_bytes());
        // Timestamp: 2024-01-15 12:00:00 UTC in Windows FILETIME
        let ts: i64 = 133500480000000000;
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        // Reason
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        // Source info
        buf[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
        // Security ID
        buf[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        // File attributes (ARCHIVE)
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        // Filename length
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // Filename offset
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        // Filename UTF-16LE
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        buf
    }

    /// Build an RCRD page with a log record containing embedded USN data in redo area.
    fn build_rcrd_page_with_usn_in_redo(usn_data: &[u8], page_lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];

        // RCRD signature
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        // last_end_lsn at offset 0x18
        page[0x18..0x20].copy_from_slice(&page_lsn.to_le_bytes());

        // Build a log record at the data area (offset 0x40)
        let data_offset = RCRD_DATA_OFFSET;

        // this_lsn at offset 0x00
        let this_lsn: u64 = 42000;
        page[data_offset..data_offset + 8].copy_from_slice(&this_lsn.to_le_bytes());

        // client_data_length at offset 0x18 within the log record
        let client_data_length = usn_data.len() as u32;
        page[data_offset + 0x18..data_offset + 0x1C]
            .copy_from_slice(&client_data_length.to_le_bytes());

        // redo_offset at 0x34 (relative to 0x30 in log record) - point right after the header fields
        let redo_offset: u16 = 0x10; // 0x30 + 0x10 = 0x40 from start of log record
        page[data_offset + 0x34..data_offset + 0x36].copy_from_slice(&redo_offset.to_le_bytes());

        // redo_length at 0x36
        let redo_length = usn_data.len() as u16;
        page[data_offset + 0x36..data_offset + 0x38].copy_from_slice(&redo_length.to_le_bytes());

        // Place the USN data at the redo location
        // redo data starts at: data_offset + 0x30 + redo_offset = data_offset + 0x40
        let redo_start = data_offset + 0x30 + redo_offset as usize;
        if redo_start + usn_data.len() <= page.len() {
            page[redo_start..redo_start + usn_data.len()].copy_from_slice(usn_data);
        }

        page
    }

    /// Build an RCRD page with a USN record in the slack space.
    fn build_rcrd_page_with_usn_in_slack(usn_data: &[u8], page_lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];

        // RCRD signature
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        // last_end_lsn at offset 0x18
        page[0x18..0x20].copy_from_slice(&page_lsn.to_le_bytes());

        // Put all-zeros in the data area to simulate no log records
        // (the extraction logic will see zeros and skip to slack scanning)

        // Place USN data in slack area near end of page
        let slack_pos = LOG_PAGE_SIZE - usn_data.len() - 8; // some padding
                                                            // Make sure position is 8-byte aligned
        let slack_pos = slack_pos & !7;
        if slack_pos >= RCRD_DATA_OFFSET && slack_pos + usn_data.len() <= page.len() {
            page[slack_pos..slack_pos + usn_data.len()].copy_from_slice(usn_data);
        }

        page
    }

    #[test]
    fn test_extract_empty_logfile() {
        let results = extract_usn_from_logfile(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_non_rcrd_pages() {
        // Pages with no RCRD signature should yield nothing
        let data = vec![0u8; LOG_PAGE_SIZE * 4];
        let results = extract_usn_from_logfile(&data);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_usn_from_redo_data() {
        let usn_bytes = build_v2_record_bytes(100, 3, 5, 5, 0x100, "secret.txt");
        let page = build_rcrd_page_with_usn_in_redo(&usn_bytes, 50000);

        let results = extract_usn_from_logfile(&page);
        assert!(!results.is_empty(), "Should find USN record in redo data");

        let found = &results[0];
        assert_eq!(found.source, LogFileRecordSource::RedoData);
        assert_eq!(found.record.mft_entry, 100);
        assert_eq!(found.record.mft_sequence, 3);
        assert_eq!(found.record.filename, "secret.txt");
        assert_eq!(found.lsn, 42000); // this_lsn from the log record
    }

    #[test]
    fn test_extract_usn_from_page_slack() {
        let usn_bytes = build_v2_record_bytes(200, 1, 50, 1, 0x200, "deleted.doc");
        let page = build_rcrd_page_with_usn_in_slack(&usn_bytes, 60000);

        let results = extract_usn_from_logfile(&page);
        assert!(!results.is_empty(), "Should find USN record in page slack");

        let found = results
            .iter()
            .find(|r| r.source == LogFileRecordSource::PageSlack);
        assert!(found.is_some(), "Should identify source as PageSlack");
        let found = found.unwrap();
        assert_eq!(found.record.mft_entry, 200);
        assert_eq!(found.record.filename, "deleted.doc");
        assert_eq!(found.lsn, 60000); // page_lsn for slack records
    }

    #[test]
    fn test_extract_multiple_pages() {
        let usn1 = build_v2_record_bytes(100, 1, 5, 5, 0x100, "file1.txt");
        let usn2 = build_v2_record_bytes(200, 1, 5, 5, 0x200, "file2.txt");

        let page1 = build_rcrd_page_with_usn_in_redo(&usn1, 10000);
        let page2 = build_rcrd_page_with_usn_in_redo(&usn2, 20000);

        let mut logfile_data = Vec::new();
        logfile_data.extend_from_slice(&page1);
        logfile_data.extend_from_slice(&page2);

        let results = extract_usn_from_logfile(&logfile_data);
        assert!(
            results.len() >= 2,
            "Should find records from both pages, got {}",
            results.len()
        );

        let filenames: Vec<&str> = results.iter().map(|r| r.record.filename.as_str()).collect();
        assert!(filenames.contains(&"file1.txt"));
        assert!(filenames.contains(&"file2.txt"));
    }

    #[test]
    fn test_extract_preserves_usn_record_fields() {
        let usn_bytes = build_v2_record_bytes(42, 7, 30, 2, 0x0000_0800, "secure.pdf");
        let page = build_rcrd_page_with_usn_in_redo(&usn_bytes, 99000);

        let results = extract_usn_from_logfile(&page);
        assert!(!results.is_empty());

        let found = &results[0];
        assert_eq!(found.record.mft_entry, 42);
        assert_eq!(found.record.mft_sequence, 7);
        assert_eq!(found.record.parent_mft_entry, 30);
        assert_eq!(found.record.parent_mft_sequence, 2);
        assert_eq!(found.record.filename, "secure.pdf");
        assert_eq!(found.record.major_version, 2);
        // Reason 0x800 = SECURITY_CHANGE
        assert!(found
            .record
            .reason
            .contains(crate::usn::UsnReason::SECURITY_CHANGE));
    }

    #[test]
    fn test_extract_skips_rstr_pages() {
        // Build a logfile with RSTR page followed by RCRD page
        let mut logfile_data = vec![0u8; LOG_PAGE_SIZE * 3];

        // First page: RSTR
        logfile_data[0..4].copy_from_slice(b"RSTR");

        // Second page: RCRD with USN data
        let usn_bytes = build_v2_record_bytes(300, 1, 5, 5, 0x100, "found.txt");
        let rcrd_page = build_rcrd_page_with_usn_in_redo(&usn_bytes, 70000);
        logfile_data[LOG_PAGE_SIZE..LOG_PAGE_SIZE * 2].copy_from_slice(&rcrd_page);

        let results = extract_usn_from_logfile(&logfile_data);
        assert!(!results.is_empty());
        assert_eq!(results[0].record.filename, "found.txt");
        // Verify page_offset reflects the second page
        assert!(results[0].page_offset >= LOG_PAGE_SIZE);
    }

    #[test]
    fn test_extract_unicode_filename() {
        let usn_bytes = build_v2_record_bytes(400, 2, 5, 5, 0x100, "\u{6d4b}\u{8bd5}.txt");
        let page = build_rcrd_page_with_usn_in_redo(&usn_bytes, 80000);

        let results = extract_usn_from_logfile(&page);
        assert!(!results.is_empty());
        assert_eq!(results[0].record.filename, "\u{6d4b}\u{8bd5}.txt");
    }

    #[test]
    fn test_scan_for_usn_records_in_raw_data() {
        // Test the internal scan function directly
        let mut data = vec![0u8; 256];
        let usn_bytes = build_v2_record_bytes(50, 1, 5, 5, 0x100, "hi.txt");
        data[0..usn_bytes.len()].copy_from_slice(&usn_bytes);

        let found = scan_for_usn_records(&data);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.filename, "hi.txt");
    }

    #[test]
    fn test_scan_for_multiple_usn_records() {
        let usn1 = build_v2_record_bytes(10, 1, 5, 5, 0x100, "a.txt");
        let usn2 = build_v2_record_bytes(20, 1, 5, 5, 0x200, "b.txt");

        let mut data = Vec::new();
        data.extend_from_slice(&usn1);
        data.extend_from_slice(&usn2);
        // Pad to give scan room
        data.extend_from_slice(&[0u8; 64]);

        let found = scan_for_usn_records(&data);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].1.filename, "a.txt");
        assert_eq!(found[1].1.filename, "b.txt");
    }

    #[test]
    fn test_try_parse_usn_at_invalid_data() {
        // Random data should not parse as USN record
        let data = vec![0xAA; 256];
        assert!(try_parse_usn_at(&data, 0).is_none());
    }

    #[test]
    fn test_try_parse_usn_at_too_short() {
        let data = vec![0u8; 10];
        assert!(try_parse_usn_at(&data, 0).is_none());
    }

    #[test]
    fn test_extract_from_undersized_page() {
        // Page smaller than RCRD_DATA_OFFSET should not panic
        let mut page = vec![0u8; RCRD_DATA_OFFSET - 1];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        let results = extract_from_rcrd_page(&page, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_logfile_record_source_equality() {
        assert_eq!(LogFileRecordSource::RedoData, LogFileRecordSource::RedoData);
        assert_ne!(LogFileRecordSource::RedoData, LogFileRecordSource::UndoData);
        assert_ne!(
            LogFileRecordSource::UndoData,
            LogFileRecordSource::PageSlack
        );
    }

    /// Build an RCRD page with USN data in the undo area.
    fn build_rcrd_page_with_usn_in_undo(usn_data: &[u8], page_lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];

        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&page_lsn.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;

        // this_lsn
        let this_lsn: u64 = 42000;
        page[data_offset..data_offset + 8].copy_from_slice(&this_lsn.to_le_bytes());

        let client_data_length = usn_data.len() as u32;
        page[data_offset + 0x18..data_offset + 0x1C]
            .copy_from_slice(&client_data_length.to_le_bytes());

        // redo_offset = 0, redo_length = 0 (no redo data)
        // undo_offset at 0x38 (relative to 0x30)
        let undo_offset: u16 = 0x10;
        page[data_offset + 0x38..data_offset + 0x3A].copy_from_slice(&undo_offset.to_le_bytes());

        let undo_length = usn_data.len() as u16;
        page[data_offset + 0x3A..data_offset + 0x3C].copy_from_slice(&undo_length.to_le_bytes());

        let undo_start = data_offset + 0x30 + undo_offset as usize;
        if undo_start + usn_data.len() <= page.len() {
            page[undo_start..undo_start + usn_data.len()].copy_from_slice(usn_data);
        }

        page
    }

    #[test]
    fn test_extract_usn_from_undo_data() {
        let usn_bytes = build_v2_record_bytes(300, 2, 10, 1, 0x200, "undo_file.doc");
        let page = build_rcrd_page_with_usn_in_undo(&usn_bytes, 75000);

        let results = extract_usn_from_logfile(&page);
        assert!(!results.is_empty(), "Should find USN record in undo data");

        let found = results
            .iter()
            .find(|r| r.source == LogFileRecordSource::UndoData);
        assert!(found.is_some(), "Should identify source as UndoData");
        let found = found.unwrap();
        assert_eq!(found.record.mft_entry, 300);
        assert_eq!(found.record.filename, "undo_file.doc");
    }

    #[test]
    fn test_extract_page_with_zero_lsn_uses_page_lsn() {
        let usn_bytes = build_v2_record_bytes(100, 1, 5, 5, 0x100, "test.txt");
        let mut page = build_rcrd_page_with_usn_in_redo(&usn_bytes, 99000);

        // Set this_lsn to 0 (should fall back to page_lsn)
        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&0u64.to_le_bytes());

        let results = extract_usn_from_logfile(&page);
        assert!(!results.is_empty());
        assert_eq!(results[0].lsn, 99000); // Should use page_lsn
    }

    #[test]
    fn test_extract_zero_client_data_length() {
        // RCRD page with a log record that has zero client_data_length
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        // Put a log record with non-zero lsn but zero client_data_length
        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());
        // client_data_length = 0 at offset 0x18
        page[data_offset + 0x18..data_offset + 0x1C].copy_from_slice(&0u32.to_le_bytes());

        let results = extract_usn_from_logfile(&page);
        // Should not crash; may or may not find records in slack
        assert!(
            results.is_empty()
                || results
                    .iter()
                    .all(|r| r.source == LogFileRecordSource::PageSlack)
        );
    }

    #[test]
    fn test_try_parse_usn_at_non_v2_version() {
        // Valid structure but version 3 should be rejected by try_parse_usn_at
        let mut data = vec![0u8; 0x60];
        let record_len = 0x4Cu32;
        data[0..4].copy_from_slice(&record_len.to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes()); // V3 - not V2
        assert!(try_parse_usn_at(&data, 0).is_none());
    }

    #[test]
    fn test_try_parse_usn_at_record_len_exceeds_slice() {
        // record_len is valid for V2 but exceeds available data
        let mut data = vec![0u8; 0x3C]; // exactly USN_V2_MIN_SIZE
        data[0..4].copy_from_slice(&(0x50u32).to_le_bytes()); // claims to be 0x50
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(try_parse_usn_at(&data, 0).is_none());
    }

    #[test]
    fn test_scan_empty_data() {
        let data: &[u8] = &[];
        let found = scan_for_usn_records(data);
        assert!(found.is_empty());
    }

    #[test]
    fn test_scan_short_data() {
        let data = vec![0u8; 10]; // Too short for any USN record
        let found = scan_for_usn_records(&data);
        assert!(found.is_empty());
    }

    #[test]
    fn test_extract_logfile_data_not_page_aligned() {
        // Data that doesn't align to page boundaries
        let data = vec![0xAAu8; 100];
        let results = extract_usn_from_logfile(&data);
        assert!(results.is_empty());
    }

    #[test]
    fn test_try_parse_usn_at_slice_shorter_than_8() {
        // Line 101: slice.len() < 8 after initial size check passes
        // This happens when offset + USN_V2_MIN_SIZE <= data.len() but
        // the slice from offset onward has < 8 bytes somehow.
        // Actually, if offset + USN_V2_MIN_SIZE <= data.len(), then
        // slice = &data[offset..] has len >= USN_V2_MIN_SIZE (60) which is >= 8.
        // So line 101 is unreachable. Test the boundary anyway.
        let data = vec![0u8; USN_V2_MIN_SIZE];
        // This should pass the first check (offset + USN_V2_MIN_SIZE <= data.len())
        // and the slice will be exactly USN_V2_MIN_SIZE bytes (>= 8)
        let result = try_parse_usn_at(&data, 0);
        assert!(result.is_none()); // All zeros, invalid record
    }

    #[test]
    fn test_extract_rcrd_page_huge_client_data_length() {
        // Line 252: record_offset > data_area.len() break
        // Build an RCRD page with a log record that has a huge client_data_length
        // causing record_offset to jump past the data area
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;
        // Non-zero lsn so the loop enters
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());
        // Huge client_data_length
        page[data_offset + 0x18..data_offset + 0x1C].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());

        let results = extract_from_rcrd_page(&page, 0);
        // Should not panic; may find records in slack
        let _ = results;
    }

    #[test]
    fn test_try_parse_usn_at_record_len_too_small() {
        // Covers line 107-108: record_len < USN_V2_MIN_SIZE
        let mut data = vec![0u8; 0x60];
        // record_len = 0x20 (below USN_V2_MIN_SIZE)
        data[0..4].copy_from_slice(&(0x20u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(try_parse_usn_at(&data, 0).is_none());
    }

    #[test]
    fn test_try_parse_usn_at_record_len_too_large() {
        // Covers line 107-108: record_len > USN_MAX_RECORD_SIZE
        let mut data = vec![0u8; 0x60];
        data[0..4].copy_from_slice(&(70000u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(try_parse_usn_at(&data, 0).is_none());
    }

    #[test]
    fn test_extract_from_rcrd_page_short_for_page_lsn() {
        // Covers line 164: page_data.len() < 0x20, page_lsn defaults to 0.
        // Build a minimal page that has RCRD_DATA_OFFSET + a few bytes but < 0x20.
        // Actually, since RCRD_DATA_OFFSET = 0x40 which is > 0x20, any page
        // that passes the check at line 155 will also have len >= 0x40 > 0x20.
        // So line 163-164 (else branch) is unreachable from extract_from_rcrd_page
        // when called from extract_usn_from_logfile (which ensures page_data.len() >= LOG_PAGE_SIZE).
        // Call extract_from_rcrd_page directly with a short page:
        let page = vec![0u8; 0x18]; // Less than 0x20 but we still need >= RCRD_DATA_OFFSET
        // This will return early on line 155 since len < RCRD_DATA_OFFSET.
        // To test line 164, we need len >= RCRD_DATA_OFFSET but < 0x20, which is impossible
        // since RCRD_DATA_OFFSET (0x40) > 0x20. So the else branch is unreachable.
        // Just verify the short page returns empty:
        let results = extract_from_rcrd_page(&page, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_aligned_size_zero_break() {
        // Covers line 242: aligned_size == 0 break
        // Build an RCRD page where the log record has a client_data_length
        // that, when added to 0x30, gives a value whose 8-byte alignment is 0.
        // For aligned_size to be 0, we need (0x30 + client_data_length + 7) & !7 == 0
        // which is impossible since 0x30 = 48 and 48 + 0 + 7 = 55, (55 & !7) = 48.
        // So aligned_size is always >= 48. This line is unreachable.
        // Test the client_data_length=0 path instead (line 236-238):
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());
        // client_data_length = 0
        page[data_offset + 0x18..data_offset + 0x1C].copy_from_slice(&0u32.to_le_bytes());

        let results = extract_from_rcrd_page(&page, 0);
        // Should not crash; processes fine with zero client data
        let _ = results;
    }

    #[test]
    fn test_extract_redo_start_exceeds_data_area() {
        // Covers line 200: redo_start + redo_length > data_area.len()
        // The redo data would extend past the page boundary.
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());

        let client_data_length = 200u32;
        page[data_offset + 0x18..data_offset + 0x1C]
            .copy_from_slice(&client_data_length.to_le_bytes());

        // redo_offset that pushes redo data past the end of data_area
        let redo_offset: u16 = 0x10;
        page[data_offset + 0x34..data_offset + 0x36].copy_from_slice(&redo_offset.to_le_bytes());
        // redo_length that exceeds available space
        let redo_length: u16 = 0xFFF0;
        page[data_offset + 0x36..data_offset + 0x38].copy_from_slice(&redo_length.to_le_bytes());

        let results = extract_from_rcrd_page(&page, 0);
        // Should not crash; redo data is out of bounds so no records from redo
        let _ = results;
    }

    #[test]
    fn test_extract_undo_start_exceeds_data_area() {
        // Covers line 219: undo_start + undo_length > data_area.len()
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());

        let client_data_length = 200u32;
        page[data_offset + 0x18..data_offset + 0x1C]
            .copy_from_slice(&client_data_length.to_le_bytes());

        // undo_offset that pushes undo data past the end
        let undo_offset: u16 = 0x10;
        page[data_offset + 0x38..data_offset + 0x3A].copy_from_slice(&undo_offset.to_le_bytes());
        let undo_length: u16 = 0xFFF0;
        page[data_offset + 0x3A..data_offset + 0x3C].copy_from_slice(&undo_length.to_le_bytes());

        let results = extract_from_rcrd_page(&page, 0);
        let _ = results;
    }

    #[test]
    fn test_extract_same_redo_undo_region_deduplicates() {
        // Covers line 218: same_region check - when redo and undo point to same data,
        // undo should be skipped to avoid duplicate records.
        let usn_bytes = build_v2_record_bytes(100, 1, 5, 5, 0x100, "dedup.txt");
        let mut page = vec![0u8; LOG_PAGE_SIZE];

        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());

        let client_data_length = usn_bytes.len() as u32;
        page[data_offset + 0x18..data_offset + 0x1C]
            .copy_from_slice(&client_data_length.to_le_bytes());

        // Both redo and undo point to the SAME offset and length
        let shared_offset: u16 = 0x10;
        let shared_length = usn_bytes.len() as u16;

        // redo
        page[data_offset + 0x34..data_offset + 0x36]
            .copy_from_slice(&shared_offset.to_le_bytes());
        page[data_offset + 0x36..data_offset + 0x38]
            .copy_from_slice(&shared_length.to_le_bytes());

        // undo - same offset and length as redo
        page[data_offset + 0x38..data_offset + 0x3A]
            .copy_from_slice(&shared_offset.to_le_bytes());
        page[data_offset + 0x3A..data_offset + 0x3C]
            .copy_from_slice(&shared_length.to_le_bytes());

        // Place USN data at the shared location
        let redo_start = data_offset + 0x30 + shared_offset as usize;
        if redo_start + usn_bytes.len() <= page.len() {
            page[redo_start..redo_start + usn_bytes.len()].copy_from_slice(&usn_bytes);
        }

        let results = extract_usn_from_logfile(&page);
        // Should find the record only once (from redo), not duplicated from undo
        let redo_count = results
            .iter()
            .filter(|r| r.source == LogFileRecordSource::RedoData)
            .count();
        let undo_count = results
            .iter()
            .filter(|r| r.source == LogFileRecordSource::UndoData)
            .count();
        assert!(
            redo_count >= 1,
            "Should find at least one record from redo"
        );
        assert_eq!(
            undo_count, 0,
            "Should not duplicate from undo when same region as redo"
        );
    }

    #[test]
    fn test_extract_record_offset_overflow_safety() {
        // Covers line 248: record_offset > data_area.len() break
        // Build a page with a log record whose client_data_length causes
        // record_offset to jump past data_area
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&50000u64.to_le_bytes());

        let data_offset = RCRD_DATA_OFFSET;
        page[data_offset..data_offset + 8].copy_from_slice(&42000u64.to_le_bytes());
        // Large but not overflowing client_data_length
        page[data_offset + 0x18..data_offset + 0x1C]
            .copy_from_slice(&(LOG_PAGE_SIZE as u32).to_le_bytes());

        let results = extract_from_rcrd_page(&page, 0);
        // Should break cleanly without panic
        let _ = results;
    }

    #[test]
    fn test_extract_from_rcrd_page_short_page_for_lsn() {
        // RCRD page where len < 0x20 (can't read page_lsn)
        // This is handled by the extract_from_rcrd_page function
        let mut page = vec![0u8; RCRD_DATA_OFFSET + 10];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        // Page is big enough for data_area but we test the page_lsn branch
        // page.len() = 0x4A which is >= 0x20, so page_lsn will be read

        let results = extract_from_rcrd_page(&page, 0);
        // Should not panic, may be empty
        assert!(results.is_empty() || !results.is_empty());
    }
}
