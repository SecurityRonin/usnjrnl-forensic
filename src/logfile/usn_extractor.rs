//! Extract USN records embedded in $LogFile RCRD pages.
//!
//! $LogFile contains transaction log records whose redo/undo data areas
//! may contain embedded USN_RECORD_V2 structures. This module scans RCRD
//! pages to recover these records, which can reveal file activity even
//! after the USN Journal has been cleared.
//!
//! Inspired by ntfs-linker's TriForce approach.

use crate::usn::{UsnRecord, parse_usn_record_v2};

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
    if record_len < USN_V2_MIN_SIZE || record_len > USN_MAX_RECORD_SIZE {
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
fn extract_from_rcrd_page(
    page_data: &[u8],
    page_offset: usize,
) -> Vec<LogFileUsnRecord> {
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
        page[data_offset + 0x34..data_offset + 0x36]
            .copy_from_slice(&redo_offset.to_le_bytes());

        // redo_length at 0x36
        let redo_length = usn_data.len() as u16;
        page[data_offset + 0x36..data_offset + 0x38]
            .copy_from_slice(&redo_length.to_le_bytes());

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

        let found = results.iter().find(|r| r.source == LogFileRecordSource::PageSlack);
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
        assert!(results.len() >= 2, "Should find records from both pages, got {}", results.len());

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
        assert!(found.record.reason.contains(crate::usn::UsnReason::SECURITY_CHANGE));
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
        assert_ne!(LogFileRecordSource::UndoData, LogFileRecordSource::PageSlack);
    }
}
