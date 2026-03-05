//! USN record carving from unallocated space or raw disk data.
//!
//! Scans arbitrary binary data looking for valid USN_RECORD_V2 and V3
//! signatures, validates each candidate, and extracts valid records.
//! Handles overlapping and corrupt regions gracefully.

use log::debug;

use super::record::{parse_usn_record_v2, parse_usn_record_v3, UsnRecord};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Minimum valid USN_RECORD_V2 size.
const USN_V2_MIN_SIZE: usize = 0x3C;

/// Minimum valid USN_RECORD_V3 size.
const USN_V3_MIN_SIZE: usize = 0x4C;

/// Maximum valid record size.
const USN_MAX_RECORD_SIZE: usize = 65536;

/// Earliest valid timestamp: 2000-01-01T00:00:00 UTC as Windows FILETIME.
const FILETIME_2000: i64 = 125_911_584_000_000_000;

/// Latest valid timestamp: 2030-01-01T00:00:00 UTC as Windows FILETIME.
const FILETIME_2030: i64 = 135_379_776_000_000_000;

// ─── Result types ────────────────────────────────────────────────────────────

/// A carved USN record with its offset in the source data.
#[derive(Debug, Clone)]
pub struct CarvedRecord {
    /// Offset in the source data where this record was found.
    pub offset: usize,
    /// The parsed USN record.
    pub record: UsnRecord,
}

/// Statistics from a carving operation.
#[derive(Debug, Clone, Default)]
pub struct CarvingStats {
    /// Total bytes scanned.
    pub bytes_scanned: usize,
    /// Number of candidate positions examined.
    pub candidates_examined: u64,
    /// Number of records successfully carved.
    pub records_carved: usize,
    /// Number of candidates rejected due to invalid timestamps.
    pub rejected_timestamp: u64,
    /// Number of candidates rejected due to invalid structure.
    pub rejected_structure: u64,
}

// ─── Carver ──────────────────────────────────────────────────────────────────

/// Carve USN records from raw binary data (unallocated space, disk images, etc.).
///
/// Scans the data byte-by-byte (aligned to 8-byte boundaries for efficiency)
/// looking for valid USN_RECORD_V2/V3 signatures and validates each candidate.
///
/// # Arguments
/// * `data` - Raw binary data to scan
///
/// # Returns
/// A tuple of (carved records, carving statistics).
pub fn carve_usn_records(data: &[u8]) -> (Vec<CarvedRecord>, CarvingStats) {
    let mut results = Vec::new();
    let mut stats = CarvingStats {
        bytes_scanned: data.len(),
        ..Default::default()
    };

    let len = data.len();
    let mut offset = 0;

    // Scan on 8-byte aligned boundaries (USN records are always 8-byte aligned)
    while offset + 8 <= len {
        // Quick check: skip zero-filled regions
        if data[offset..offset + 4] == [0, 0, 0, 0] {
            offset += 8;
            continue;
        }

        let record_len = read_u32_le(data, offset) as usize;
        let major_version = read_u16_le(data, offset + 4);

        // Check if this could be a valid USN record
        match major_version {
            2 => {
                if (USN_V2_MIN_SIZE..=USN_MAX_RECORD_SIZE).contains(&record_len)
                    && offset + record_len <= len
                {
                    stats.candidates_examined += 1;
                    if let Some(carved) = try_carve_v2(data, offset, record_len, &mut stats) {
                        // Skip past this record to avoid overlapping matches
                        let aligned = (record_len + 7) & !7;
                        offset += aligned;
                        results.push(carved);
                        continue;
                    }
                }
            }
            3 => {
                if (USN_V3_MIN_SIZE..=USN_MAX_RECORD_SIZE).contains(&record_len)
                    && offset + record_len <= len
                {
                    stats.candidates_examined += 1;
                    if let Some(carved) = try_carve_v3(data, offset, record_len, &mut stats) {
                        let aligned = (record_len + 7) & !7;
                        offset += aligned;
                        results.push(carved);
                        continue;
                    }
                }
            }
            _ => {}
        }

        offset += 8;
    }

    stats.records_carved = results.len();
    (results, stats)
}

/// Attempt to carve a V2 record at the given offset.
fn try_carve_v2(
    data: &[u8],
    offset: usize,
    record_len: usize,
    stats: &mut CarvingStats,
) -> Option<CarvedRecord> {
    let record_data = &data[offset..offset + record_len];

    // Validate filename offset is within record
    if record_len < USN_V2_MIN_SIZE {
        stats.rejected_structure += 1;
        return None;
    }

    let filename_length = read_u16_le(record_data, 0x38) as usize;
    let filename_offset = read_u16_le(record_data, 0x3A) as usize;

    // Filename offset must be at 0x3C for V2
    if filename_offset != 0x3C {
        stats.rejected_structure += 1;
        return None;
    }

    // Filename must fit within record
    if filename_offset + filename_length > record_len {
        stats.rejected_structure += 1;
        return None;
    }

    // Filename length must be even (UTF-16) and non-zero
    if filename_length == 0 || !filename_length.is_multiple_of(2) {
        stats.rejected_structure += 1;
        return None;
    }

    // Validate timestamp
    let timestamp_raw = read_i64_le(record_data, 0x20);
    if !is_valid_timestamp(timestamp_raw) {
        stats.rejected_timestamp += 1;
        return None;
    }

    // Try to parse the full record
    match parse_usn_record_v2(record_data) {
        Ok(record) => {
            debug!(
                "Carved V2 record at offset 0x{:x}: {}",
                offset, record.filename
            );
            Some(CarvedRecord { offset, record })
        }
        Err(_) => {
            stats.rejected_structure += 1;
            None
        }
    }
}

/// Attempt to carve a V3 record at the given offset.
fn try_carve_v3(
    data: &[u8],
    offset: usize,
    record_len: usize,
    stats: &mut CarvingStats,
) -> Option<CarvedRecord> {
    let record_data = &data[offset..offset + record_len];

    if record_len < USN_V3_MIN_SIZE {
        stats.rejected_structure += 1;
        return None;
    }

    let filename_length = read_u16_le(record_data, 0x48) as usize;
    let filename_offset = read_u16_le(record_data, 0x4A) as usize;

    // Filename offset must be at 0x4C for V3
    if filename_offset != 0x4C {
        stats.rejected_structure += 1;
        return None;
    }

    if filename_offset + filename_length > record_len {
        stats.rejected_structure += 1;
        return None;
    }

    if filename_length == 0 || !filename_length.is_multiple_of(2) {
        stats.rejected_structure += 1;
        return None;
    }

    // Validate timestamp
    let timestamp_raw = read_i64_le(record_data, 0x30);
    if !is_valid_timestamp(timestamp_raw) {
        stats.rejected_timestamp += 1;
        return None;
    }

    match parse_usn_record_v3(record_data) {
        Ok(record) => {
            debug!(
                "Carved V3 record at offset 0x{:x}: {}",
                offset, record.filename
            );
            Some(CarvedRecord { offset, record })
        }
        Err(_) => {
            stats.rejected_structure += 1;
            None
        }
    }
}

/// Check if a Windows FILETIME value falls within a valid range (2000-2030).
fn is_valid_timestamp(filetime: i64) -> bool {
    (FILETIME_2000..=FILETIME_2030).contains(&filetime)
}

// ─── Binary helpers (duplicated to keep carver self-contained) ───────────────

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

fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid V2 record with configurable timestamp.
    fn build_v2_record_with_timestamp(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        reason: u32,
        filename: &str,
        timestamp: i64,
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
        // Timestamp
        buf[0x20..0x28].copy_from_slice(&timestamp.to_le_bytes());
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

    /// Build a V2 record with a default valid timestamp (2024-01-15).
    fn build_v2_record(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        reason: u32,
        filename: &str,
    ) -> Vec<u8> {
        // 2024-01-15 12:00:00 UTC
        let ts: i64 = 133_500_480_000_000_000;
        build_v2_record_with_timestamp(entry, seq, parent_entry, parent_seq, reason, filename, ts)
    }

    #[test]
    fn test_carve_from_random_data() {
        // Random-ish data that should not contain valid USN records
        let mut data = vec![0xDE; 8192];
        // Mix in some random patterns
        for i in (0..data.len()).step_by(7) {
            data[i] = (i % 256) as u8;
        }
        // Make sure no accidental valid version fields
        for i in (4..data.len() - 2).step_by(8) {
            // Overwrite potential version fields with invalid values
            data[i] = 0xFF;
            data[i + 1] = 0xFF;
        }

        let (records, stats) = carve_usn_records(&data);
        assert_eq!(
            records.len(),
            0,
            "Should not find any records in random data"
        );
        assert_eq!(stats.bytes_scanned, 8192);
    }

    #[test]
    fn test_carve_embedded_v2_record() {
        // Create garbage data with a valid V2 record embedded in the middle
        let mut data = vec![0xAA; 512]; // garbage prefix
                                        // Ensure prefix is 8-byte aligned and doesn't accidentally look like a record
        for i in (4..512).step_by(8) {
            data[i] = 0xFF;
            data[i + 1] = 0xFF;
        }

        let record = build_v2_record(42, 1, 5, 5, 0x100, "carved_file.txt");
        let record_offset = data.len();
        data.extend_from_slice(&record);
        data.extend_from_slice(&vec![0xBB; 512]); // garbage suffix

        let (records, stats) = carve_usn_records(&data);

        assert_eq!(records.len(), 1, "Should find exactly one record");
        assert_eq!(records[0].offset, record_offset);
        assert_eq!(records[0].record.filename, "carved_file.txt");
        assert_eq!(records[0].record.mft_entry, 42);
        assert_eq!(records[0].record.major_version, 2);
        assert!(stats.candidates_examined >= 1);
        assert_eq!(stats.records_carved, 1);
    }

    #[test]
    fn test_carve_multiple_records_with_gaps() {
        let mut data = Vec::new();

        // Garbage prefix
        let mut garbage = vec![0xCC; 256];
        for i in (4..garbage.len()).step_by(8) {
            garbage[i] = 0xFF;
            garbage[i + 1] = 0xFF;
        }
        data.extend_from_slice(&garbage);

        // First record
        let r1_offset = data.len();
        let r1 = build_v2_record(100, 1, 5, 5, 0x100, "first.txt");
        data.extend_from_slice(&r1);

        // Gap of garbage between records
        let mut gap = vec![0xDD; 128];
        for i in (4..gap.len()).step_by(8) {
            gap[i] = 0xFF;
            gap[i + 1] = 0xFF;
        }
        data.extend_from_slice(&gap);

        // Second record
        let r2_offset = data.len();
        let r2 = build_v2_record(200, 2, 100, 1, 0x200, "second.doc");
        data.extend_from_slice(&r2);

        // More garbage
        let mut garbage2 = vec![0xEE; 64];
        for i in (4..garbage2.len()).step_by(8) {
            garbage2[i] = 0xFF;
            garbage2[i + 1] = 0xFF;
        }
        data.extend_from_slice(&garbage2);

        // Third record
        let r3_offset = data.len();
        let r3 = build_v2_record(300, 1, 5, 5, 0x100, "third.pdf");
        data.extend_from_slice(&r3);

        // Garbage suffix
        data.extend_from_slice(&vec![0xFF; 256]);

        let (records, stats) = carve_usn_records(&data);

        assert_eq!(records.len(), 3, "Should find all three embedded records");
        assert_eq!(records[0].offset, r1_offset);
        assert_eq!(records[0].record.filename, "first.txt");
        assert_eq!(records[1].offset, r2_offset);
        assert_eq!(records[1].record.filename, "second.doc");
        assert_eq!(records[2].offset, r3_offset);
        assert_eq!(records[2].record.filename, "third.pdf");
        assert_eq!(stats.records_carved, 3);
    }

    #[test]
    fn test_carve_rejects_invalid_timestamps() {
        // Record with timestamp before 2000 (Windows epoch = 1601, so use a 1990 timestamp)
        let ts_1990: i64 = 119_600_064_000_000_000; // ~1990
        let r_old = build_v2_record_with_timestamp(100, 1, 5, 5, 0x100, "old.txt", ts_1990);

        // Record with timestamp after 2030
        let ts_2035: i64 = 136_957_344_000_000_000; // ~2035
        let r_future = build_v2_record_with_timestamp(200, 1, 5, 5, 0x100, "future.txt", ts_2035);

        // Record with valid timestamp (2024)
        let r_valid = build_v2_record(300, 1, 5, 5, 0x100, "valid.txt");

        let mut data = Vec::new();
        data.extend_from_slice(&r_old);
        data.extend_from_slice(&r_future);
        data.extend_from_slice(&r_valid);

        let (records, stats) = carve_usn_records(&data);

        assert_eq!(
            records.len(),
            1,
            "Should only find the record with valid timestamp"
        );
        assert_eq!(records[0].record.filename, "valid.txt");
        assert_eq!(
            stats.rejected_timestamp, 2,
            "Should reject two records with invalid timestamps"
        );
    }

    #[test]
    fn test_carve_handles_truncated_record() {
        // Create a valid record but truncate it
        let record = build_v2_record(42, 1, 5, 5, 0x100, "truncated.txt");
        let truncated = &record[..record.len() / 2];

        let (records, _stats) = carve_usn_records(truncated);
        assert_eq!(records.len(), 0, "Should not carve truncated records");
    }

    #[test]
    fn test_carve_empty_data() {
        let (records, stats) = carve_usn_records(&[]);
        assert_eq!(records.len(), 0);
        assert_eq!(stats.bytes_scanned, 0);
    }

    #[test]
    fn test_carve_all_zeros() {
        let data = vec![0u8; 4096];
        let (records, stats) = carve_usn_records(&data);
        assert_eq!(records.len(), 0);
        assert_eq!(stats.bytes_scanned, 4096);
        assert_eq!(stats.candidates_examined, 0);
    }

    #[test]
    fn test_carve_preserves_record_fields() {
        let mut data = vec![0u8; 64]; // zero prefix (will be skipped)
        let record = build_v2_record(12345, 7, 999, 3, 0x100 | 0x8000_0000, "important.xlsx");
        data.extend_from_slice(&record);

        let (records, _) = carve_usn_records(&data);
        assert_eq!(records.len(), 1);

        let r = &records[0].record;
        assert_eq!(r.mft_entry, 12345);
        assert_eq!(r.mft_sequence, 7);
        assert_eq!(r.parent_mft_entry, 999);
        assert_eq!(r.parent_mft_sequence, 3);
        assert_eq!(r.filename, "important.xlsx");
        assert!(r
            .reason
            .contains(super::super::reason::UsnReason::FILE_CREATE));
        assert!(r.reason.contains(super::super::reason::UsnReason::CLOSE));
    }

    #[test]
    fn test_carve_record_with_wrong_filename_offset() {
        // Build a valid record but change the filename_offset to not 0x3C
        let mut data = build_v2_record(42, 1, 5, 5, 0x100, "test.txt");
        // Change filename_offset from 0x3C to 0x40 (invalid for V2)
        data[0x3A..0x3C].copy_from_slice(&0x40u16.to_le_bytes());

        let (records, stats) = carve_usn_records(&data);
        assert_eq!(records.len(), 0, "Wrong filename offset should be rejected");
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_carve_record_with_zero_filename_length() {
        let mut data = build_v2_record(42, 1, 5, 5, 0x100, "test.txt");
        // Set filename_length to 0 (invalid for carver)
        data[0x38..0x3A].copy_from_slice(&0u16.to_le_bytes());

        let (records, stats) = carve_usn_records(&data);
        assert_eq!(records.len(), 0, "Zero filename length should be rejected");
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_carve_record_with_odd_filename_length() {
        let mut data = build_v2_record(42, 1, 5, 5, 0x100, "test.txt");
        // Set filename_length to 5 (odd, invalid for UTF-16)
        data[0x38..0x3A].copy_from_slice(&5u16.to_le_bytes());

        let (records, stats) = carve_usn_records(&data);
        assert_eq!(records.len(), 0, "Odd filename length should be rejected");
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_carve_record_filename_exceeds_record() {
        let mut data = build_v2_record(42, 1, 5, 5, 0x100, "test.txt");
        // Set filename_length to something that extends past record length
        data[0x38..0x3A].copy_from_slice(&500u16.to_le_bytes());

        let (records, stats) = carve_usn_records(&data);
        assert_eq!(
            records.len(),
            0,
            "Filename exceeding record should be rejected"
        );
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_carve_v3_record() {
        // Build a V3 record with valid timestamp
        let name_utf16: Vec<u16> = "v3carved.txt".encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes()); // V3
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[0x08..0x18].copy_from_slice(&100u128.to_le_bytes());
        buf[0x18..0x28].copy_from_slice(&5u128.to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&200i64.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000; // 2024-01-15 (valid range)
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&0x100u32.to_le_bytes());
        buf[0x44..0x48].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x4C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let (records, stats) = carve_usn_records(&buf);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.filename, "v3carved.txt");
        assert_eq!(records[0].record.major_version, 3);
        assert_eq!(stats.records_carved, 1);
    }

    #[test]
    fn test_carve_v3_wrong_filename_offset() {
        // V3 record with filename_offset != 0x4C
        let name_utf16: Vec<u16> = "test.txt".encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000;
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&0x50u16.to_le_bytes()); // Wrong offset

        let (records, stats) = carve_usn_records(&buf);
        assert_eq!(records.len(), 0);
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_carve_v3_invalid_timestamp() {
        let name_utf16: Vec<u16> = "old.txt".encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        let ts_old: i64 = 119_600_064_000_000_000; // ~1990, before 2000
        buf[0x30..0x38].copy_from_slice(&ts_old.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());

        let (records, stats) = carve_usn_records(&buf);
        assert_eq!(records.len(), 0);
        assert!(stats.rejected_timestamp > 0);
    }

    #[test]
    fn test_carve_v3_zero_filename() {
        let record_len = 0x4Cu32;
        let aligned_len = ((record_len as usize) + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000;
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&0u16.to_le_bytes()); // zero filename
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());

        let (records, stats) = carve_usn_records(&buf);
        assert_eq!(records.len(), 0);
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_is_valid_timestamp() {
        assert!(is_valid_timestamp(FILETIME_2000));
        assert!(is_valid_timestamp(FILETIME_2030));
        assert!(is_valid_timestamp(133_500_480_000_000_000)); // 2024
        assert!(!is_valid_timestamp(FILETIME_2000 - 1));
        assert!(!is_valid_timestamp(FILETIME_2030 + 1));
        assert!(!is_valid_timestamp(0));
        assert!(!is_valid_timestamp(-1));
    }

    #[test]
    fn test_carve_skips_version_0_and_1() {
        // Records with version 0 or 1 should not be carved
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&(0x40u32).to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // version 1

        let (records, _) = carve_usn_records(&data);
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_carving_stats_default() {
        let stats = CarvingStats::default();
        assert_eq!(stats.bytes_scanned, 0);
        assert_eq!(stats.candidates_examined, 0);
        assert_eq!(stats.records_carved, 0);
        assert_eq!(stats.rejected_timestamp, 0);
        assert_eq!(stats.rejected_structure, 0);
    }

    #[test]
    fn test_try_carve_v2_parse_error() {
        // Call try_carve_v2 directly with a record_len parameter that differs
        // from the internal record_len field in the data. The carver slices
        // record_len bytes and passes them to parse_usn_record_v2, which
        // re-reads the internal record_len field. If that field is invalid,
        // the parser returns Err and the carver increments rejected_structure.
        let valid_ts: i64 = 133_500_480_000_000_000;
        let mut stats = CarvingStats::default();

        let mut data = vec![0u8; 0x50]; // 80 bytes
                                        // Internal record_len = 0x20 (too small for V2, triggers parse error)
        data[0..4].copy_from_slice(&(0x20u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        data[0x38..0x3A].copy_from_slice(&4u16.to_le_bytes()); // filename_length = 4
        data[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes()); // filename_offset = 0x3C
        data[0x20..0x28].copy_from_slice(&valid_ts.to_le_bytes());

        // Outer record_len = 0x50, but internal says 0x20 -> parse_usn_record_v2 bails
        let result = try_carve_v2(&data, 0, 0x50, &mut stats);
        assert!(
            result.is_none(),
            "Should fail because internal record_len is invalid"
        );
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_try_carve_v3_parse_error() {
        // Same approach as v2: create data where the internal record_len differs
        // from what the carver passes, causing parse_usn_record_v3 to fail.
        let valid_ts: i64 = 133_500_480_000_000_000;
        let mut stats = CarvingStats::default();

        let mut data = vec![0u8; 0x60]; // 96 bytes
                                        // Set internal record_len to something invalid (< USN_V3_MIN_SIZE)
        data[0..4].copy_from_slice(&(0x30u32).to_le_bytes()); // too small for V3
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        data[0x48..0x4A].copy_from_slice(&4u16.to_le_bytes()); // filename_length = 4
        data[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes()); // filename_offset = 0x4C
        data[0x30..0x38].copy_from_slice(&valid_ts.to_le_bytes());

        // Call try_carve_v3 with outer record_len=0x60 but data says 0x30 internally
        let result = try_carve_v3(&data, 0, 0x60, &mut stats);
        assert!(
            result.is_none(),
            "Should fail because internal record_len is invalid for V3"
        );
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_try_carve_v2_record_len_below_min() {
        // Directly call try_carve_v2 with record_len < USN_V2_MIN_SIZE
        // This covers lines 139-140
        let mut stats = CarvingStats::default();
        let data = vec![0u8; 0x30]; // 48 bytes, less than USN_V2_MIN_SIZE (60)
        let result = try_carve_v2(&data, 0, 0x30, &mut stats);
        assert!(result.is_none());
        assert_eq!(stats.rejected_structure, 1);
    }

    #[test]
    fn test_try_carve_v3_record_len_below_min() {
        // Directly call try_carve_v3 with record_len < USN_V3_MIN_SIZE
        // This covers lines 197-198
        let mut stats = CarvingStats::default();
        let data = vec![0u8; 0x40]; // 64 bytes, less than USN_V3_MIN_SIZE (76)
        let result = try_carve_v3(&data, 0, 0x40, &mut stats);
        assert!(result.is_none());
        assert_eq!(stats.rejected_structure, 1);
    }

    #[test]
    fn test_try_carve_v3_filename_exceeds_record() {
        // V3 record where filename_offset + filename_length > record_len
        // Covers lines 211-212
        let valid_ts: i64 = 133_500_480_000_000_000;
        let mut stats = CarvingStats::default();

        let record_len = 0x50usize; // just barely over V3_MIN
        let mut data = vec![0u8; record_len];
        data[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        data[0x30..0x38].copy_from_slice(&valid_ts.to_le_bytes());
        // filename_length = 100, which extends past record_len
        data[0x48..0x4A].copy_from_slice(&100u16.to_le_bytes());
        data[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());

        let result = try_carve_v3(&data, 0, record_len, &mut stats);
        assert!(result.is_none());
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_try_carve_v3_odd_filename_length() {
        // V3 record where filename_length is odd (not valid UTF-16)
        // Covers line 215-217 (filename_length == 0 || filename_length % 2 != 0)
        let valid_ts: i64 = 133_500_480_000_000_000;
        let mut stats = CarvingStats::default();

        let record_len = 0x60usize;
        let mut data = vec![0u8; record_len];
        data[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        data[0x30..0x38].copy_from_slice(&valid_ts.to_le_bytes());
        // filename_length = 3 (odd)
        data[0x48..0x4A].copy_from_slice(&3u16.to_le_bytes());
        data[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());

        let result = try_carve_v3(&data, 0, record_len, &mut stats);
        assert!(result.is_none());
        assert!(stats.rejected_structure > 0);
    }

    #[test]
    fn test_carve_v2_successful_with_logging() {
        // Covers line 173: the debug! format args inside try_carve_v2's Ok branch.
        // Enable debug logging so the debug! macro evaluates its arguments.
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let mut data = vec![0u8; 64]; // zero prefix (skipped)
        let record = build_v2_record(42, 1, 5, 5, 0x100, "logged_v2.txt");
        data.extend_from_slice(&record);

        let (records, stats) = carve_usn_records(&data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.filename, "logged_v2.txt");
        assert_eq!(stats.records_carved, 1);
    }

    #[test]
    fn test_carve_v3_successful_with_logging() {
        // Covers line 228: the debug! format args inside try_carve_v3's Ok branch.
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let name_utf16: Vec<u16> = "logged_v3.txt".encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes()); // V3
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[0x08..0x18].copy_from_slice(&100u128.to_le_bytes());
        buf[0x18..0x28].copy_from_slice(&5u128.to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&200i64.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000;
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&0x100u32.to_le_bytes());
        buf[0x44..0x48].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x4C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let (records, stats) = carve_usn_records(&buf);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.filename, "logged_v3.txt");
        assert_eq!(records[0].record.major_version, 3);
        assert_eq!(stats.records_carved, 1);
    }

    #[test]
    fn test_carve_v2_record_with_mismatched_internal_length() {
        // Embed a record in larger data where the record's own length field
        // is set to > USN_MAX_RECORD_SIZE, triggering parse_usn_record_v2 to bail.
        let valid_ts: i64 = 133_500_480_000_000_000;
        let name_utf16: Vec<u16> = "ab".encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2; // 4 bytes
        let outer_len = 0x3C + name_bytes_len; // 64 bytes
        let aligned = (outer_len + 7) & !7;
        let mut buf = vec![0u8; aligned];

        // Set internal record_len to something > USN_MAX_RECORD_SIZE
        buf[0..4].copy_from_slice(&(70000u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[0x20..0x28].copy_from_slice(&valid_ts.to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            buf[0x3C + i * 2..0x3C + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let mut stats = CarvingStats::default();
        let result = try_carve_v2(&buf, 0, aligned, &mut stats);
        assert!(result.is_none());
        assert!(stats.rejected_structure > 0);
    }
}
