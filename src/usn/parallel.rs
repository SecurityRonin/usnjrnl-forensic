//! Parallel USN Journal record parsing using rayon.
//!
//! Splits raw $UsnJrnl:$J data into chunks and parses them concurrently,
//! then merges results sorted by USN offset.

use anyhow::Result;
use rayon::prelude::*;

use super::record::{parse_usn_journal, UsnRecord};

/// Chunk size for parallel processing (1 MB).
const CHUNK_SIZE: usize = 1024 * 1024;

/// Minimum valid USN_RECORD_V2 size (without filename).
const USN_V2_MIN_SIZE: usize = 0x3C;

/// Maximum valid record size (sanity check).
const USN_MAX_RECORD_SIZE: usize = 65536;

/// Check if the bytes at the given offset look like a valid V2 or V3 record start.
///
/// A valid record has:
/// - record_length (u32 at offset 0): >= 0x3C and <= 0x10000
/// - major_version (u16 at offset 4): 2 or 3
/// - minor_version (u16 at offset 6): 0
fn is_valid_record_start(data: &[u8], offset: usize) -> bool {
    if offset + 8 > data.len() {
        return false;
    }

    let record_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;

    if record_len < USN_V2_MIN_SIZE || record_len > USN_MAX_RECORD_SIZE {
        return false;
    }

    let major_version = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
    let minor_version = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);

    (major_version == 2 || major_version == 3) && minor_version == 0
}

/// Find the offset of the first valid record boundary starting at or after `start`.
///
/// Scans forward in 8-byte increments (USN records are 8-byte aligned) looking
/// for a valid record header signature.
fn find_first_record_boundary(data: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    while offset + 8 <= data.len() {
        // Skip zero-filled regions
        if data[offset..offset + 4] == [0, 0, 0, 0] {
            offset += 8;
            continue;
        }

        if is_valid_record_start(data, offset) {
            return Some(offset);
        }

        offset += 8;
    }
    None
}

/// Parse all USN records from raw $UsnJrnl:$J data using parallel processing.
///
/// The data is split into chunks of approximately `CHUNK_SIZE` bytes.
/// Each chunk is parsed independently in parallel using rayon's thread pool.
/// Each chunk scans forward to find the first valid record boundary to handle
/// records that may span chunk boundaries.
///
/// Results are merged and sorted by USN offset to ensure deterministic ordering.
pub fn parse_usn_journal_parallel(data: &[u8]) -> Result<Vec<UsnRecord>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // For small data that fits in a single chunk, just use the sequential parser
    if data.len() <= CHUNK_SIZE {
        let mut records = parse_usn_journal(data)?;
        records.sort_by_key(|r| r.usn);
        return Ok(records);
    }

    // Build chunk descriptors: (chunk_start, chunk_end) pairs
    // The first chunk starts at 0. Subsequent chunks find their first valid
    // record boundary to avoid splitting a record across chunks.
    let mut chunk_ranges: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let chunk_end = std::cmp::min(pos + CHUNK_SIZE, data.len());

        if chunk_end < data.len() {
            // Find the actual boundary for the next chunk: scan from chunk_end
            // to find the first valid record start. That becomes the start of
            // the next chunk, and this chunk extends up to that point.
            match find_first_record_boundary(data, chunk_end) {
                Some(next_start) => {
                    chunk_ranges.push((pos, next_start));
                    pos = next_start;
                }
                None => {
                    // No more valid records after chunk_end; this chunk gets the rest
                    chunk_ranges.push((pos, data.len()));
                    break;
                }
            }
        } else {
            chunk_ranges.push((pos, chunk_end));
            break;
        }
    }

    // Parse each chunk in parallel
    let mut all_records: Vec<UsnRecord> = chunk_ranges
        .par_iter()
        .filter_map(|&(start, end)| {
            let chunk = &data[start..end];
            parse_usn_journal(chunk).ok()
        })
        .flatten()
        .collect();

    // Sort by USN offset for deterministic ordering
    all_records.sort_by_key(|r| r.usn);

    Ok(all_records)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::record::parse_usn_journal;
    use crate::usn::reason::UsnReason;

    /// Build a valid V2 USN record with the given parameters.
    /// Mirrors the test helper from record.rs.
    fn build_v2_record(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        usn_offset: i64,
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
        // USN offset
        buf[0x18..0x20].copy_from_slice(&usn_offset.to_le_bytes());
        // Timestamp: 2024-01-15 12:00:00 UTC
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

    /// Build multiple V2 records with sequential USN offsets.
    fn build_multi_record_data(count: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for i in 0..count {
            let rec = build_v2_record(
                (i + 1) as u64,   // mft entry
                1,                 // seq
                5,                 // parent entry
                1,                 // parent seq
                (i * 100) as i64,  // usn offset - sequential
                0x100,             // reason: FILE_CREATE
                &format!("file_{:04}.txt", i),
            );
            data.extend_from_slice(&rec);
        }
        data
    }

    #[test]
    fn test_parallel_parse_produces_same_results_as_sequential() {
        // Build a substantial dataset with many records
        let data = build_multi_record_data(500);

        let sequential = parse_usn_journal(&data).unwrap();
        let parallel = parse_usn_journal_parallel(&data).unwrap();

        // Same number of records
        assert_eq!(
            sequential.len(),
            parallel.len(),
            "Record counts differ: sequential={}, parallel={}",
            sequential.len(),
            parallel.len()
        );

        // Same content in same order
        for (i, (s, p)) in sequential.iter().zip(parallel.iter()).enumerate() {
            assert_eq!(s.mft_entry, p.mft_entry, "mft_entry mismatch at index {}", i);
            assert_eq!(s.mft_sequence, p.mft_sequence, "mft_sequence mismatch at index {}", i);
            assert_eq!(s.parent_mft_entry, p.parent_mft_entry, "parent_mft_entry mismatch at index {}", i);
            assert_eq!(s.usn, p.usn, "usn mismatch at index {}", i);
            assert_eq!(s.filename, p.filename, "filename mismatch at index {}", i);
            assert_eq!(s.reason, p.reason, "reason mismatch at index {}", i);
            assert_eq!(s.major_version, p.major_version, "major_version mismatch at index {}", i);
        }
    }

    #[test]
    fn test_parallel_parse_empty_data() {
        let data: &[u8] = &[];
        let records = parse_usn_journal_parallel(data).unwrap();
        assert!(records.is_empty(), "Empty input should return empty vec");
    }

    #[test]
    fn test_parallel_parse_single_record() {
        let data = build_v2_record(
            42,       // mft entry
            3,        // seq
            10,       // parent entry
            1,        // parent seq
            1000,     // usn offset
            0x100,    // reason: FILE_CREATE
            "single.txt",
        );

        let records = parse_usn_journal_parallel(&data).unwrap();
        assert_eq!(records.len(), 1, "Should parse exactly one record");

        let rec = &records[0];
        assert_eq!(rec.mft_entry, 42);
        assert_eq!(rec.mft_sequence, 3);
        assert_eq!(rec.parent_mft_entry, 10);
        assert_eq!(rec.parent_mft_sequence, 1);
        assert_eq!(rec.usn, 1000);
        assert_eq!(rec.filename, "single.txt");
        assert!(rec.reason.contains(UsnReason::FILE_CREATE));
        assert_eq!(rec.major_version, 2);
    }

    #[test]
    fn test_parallel_parse_preserves_sort_order() {
        // Build records with non-sequential USN offsets to verify sorting
        let mut data = Vec::new();
        // Record with USN 300
        data.extend_from_slice(&build_v2_record(1, 1, 5, 1, 300, 0x100, "third.txt"));
        // Record with USN 100
        data.extend_from_slice(&build_v2_record(2, 1, 5, 1, 100, 0x100, "first.txt"));
        // Record with USN 200
        data.extend_from_slice(&build_v2_record(3, 1, 5, 1, 200, 0x100, "second.txt"));

        let records = parse_usn_journal_parallel(&data).unwrap();
        assert_eq!(records.len(), 3);

        // Should be sorted by USN offset
        assert!(
            records.windows(2).all(|w| w[0].usn <= w[1].usn),
            "Records should be sorted by USN offset, got: {:?}",
            records.iter().map(|r| r.usn).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_parallel_parse_handles_zero_filled_regions() {
        // Zero-filled gap followed by a record (simulates sparse journal pages)
        let mut data = vec![0u8; 4096];
        data.extend_from_slice(&build_v2_record(99, 1, 5, 1, 500, 0x100, "after_gap.txt"));

        let records = parse_usn_journal_parallel(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "after_gap.txt");
    }

    #[test]
    fn test_parallel_parse_skips_close_only_records() {
        // CLOSE reason = 0x8000_0000
        let data = build_v2_record(1, 1, 5, 1, 100, 0x8000_0000, "closed.txt");
        let records = parse_usn_journal_parallel(&data).unwrap();
        assert!(records.is_empty(), "Close-only records should be skipped");
    }

    #[test]
    fn test_parallel_parse_large_dataset_spans_chunks() {
        // Build enough records to exceed CHUNK_SIZE and force multi-chunk processing.
        // Each record is ~76 bytes (0x3C + ~16 bytes filename, aligned to 8).
        // For 1MB chunk, we need ~13,000+ records to exceed one chunk.
        // Use 20,000 to guarantee multi-chunk processing.
        let data = build_multi_record_data(20_000);
        assert!(
            data.len() > CHUNK_SIZE,
            "Test data should exceed chunk size: {} <= {}",
            data.len(),
            CHUNK_SIZE
        );

        let sequential = parse_usn_journal(&data).unwrap();
        let parallel = parse_usn_journal_parallel(&data).unwrap();

        assert_eq!(
            sequential.len(),
            parallel.len(),
            "Multi-chunk: record counts differ: seq={}, par={}",
            sequential.len(),
            parallel.len()
        );

        // Verify ordering matches
        for (i, (s, p)) in sequential.iter().zip(parallel.iter()).enumerate() {
            assert_eq!(s.filename, p.filename, "filename mismatch at index {}", i);
            assert_eq!(s.usn, p.usn, "usn mismatch at index {}", i);
        }
    }
}
