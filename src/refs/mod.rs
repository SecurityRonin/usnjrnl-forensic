//! ReFS (Resilient File System) aware handling of USN V3 records.
//!
//! ReFS uses full 128-bit file reference numbers instead of NTFS's 48-bit entry
//! + 16-bit sequence format. This module provides types and analysis for ReFS
//! volumes where USN_RECORD_V3 records contain these wider references.
//!
//! Key differences from NTFS:
//! - File references are opaque 128-bit IDs, not split into entry+sequence
//! - No traditional $MFT, so path reconstruction relies solely on journal rewind
//! - V3 records have `major_version: 3`

use std::collections::HashMap;
use std::fmt;

use crate::usn::UsnRecord;

// ---- Types ----

/// A full 128-bit ReFS file identifier.
///
/// Unlike NTFS which splits its 64-bit reference into a 48-bit MFT entry number
/// and a 16-bit sequence number, ReFS uses an opaque 128-bit identifier. The upper
/// and lower 64-bit halves have no defined entry/sequence semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefsFileId(pub u128);

impl RefsFileId {
    /// Create a RefsFileId from a raw u128 value.
    pub fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// Extract the high 64 bits of the file ID.
    pub fn high(&self) -> u64 {
        (self.0 >> 64) as u64
    }

    /// Extract the low 64 bits of the file ID.
    pub fn low(&self) -> u64 {
        self.0 as u64
    }
}

impl fmt::Display for RefsFileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}:0x{:016x}", self.high(), self.low())
    }
}

/// A USN V3 record enriched with full 128-bit ReFS file references.
///
/// The standard `UsnRecord` truncates the 128-bit references to fit into
/// `mft_entry: u64` + `mft_sequence: u16`. This wrapper preserves the full
/// 128-bit file and parent references as they appeared in the raw V3 record.
#[derive(Debug, Clone)]
pub struct RefsRecord {
    /// The underlying parsed USN record.
    pub record: UsnRecord,
    /// Full 128-bit file reference.
    pub file_id: RefsFileId,
    /// Full 128-bit parent reference.
    pub parent_id: RefsFileId,
}

impl RefsRecord {
    /// Wrap a UsnRecord with explicit 128-bit file references.
    pub fn new(record: UsnRecord, file_id: RefsFileId, parent_id: RefsFileId) -> Self {
        Self {
            record,
            file_id,
            parent_id,
        }
    }
}

/// Analyzer for ReFS USN journal data.
///
/// Provides grouping by full 128-bit file ID, ReFS vs NTFS volume detection,
/// and journal-rewind-only path reconstruction (since ReFS has no traditional MFT).
pub struct RefsAnalyzer {
    records: Vec<RefsRecord>,
}

impl RefsAnalyzer {
    /// Create a new analyzer from a set of RefsRecords.
    pub fn new(records: Vec<RefsRecord>) -> Self {
        Self { records }
    }

    /// Detect whether the records likely originate from a ReFS volume.
    ///
    /// Heuristic: if all records have `major_version == 3` and any record has
    /// a file_id whose upper 64 bits are non-zero, it is likely ReFS.
    /// Pure NTFS V3 records would have upper bits all zero.
    pub fn is_likely_refs(&self) -> bool {
        if self.records.is_empty() {
            return false;
        }

        let all_v3 = self.records.iter().all(|r| r.record.major_version == 3);
        if !all_v3 {
            return false;
        }

        // If any file or parent reference has non-zero upper 64 bits,
        // this is likely a ReFS volume (NTFS V3 refs fit in lower 64 bits).
        self.records.iter().any(|r| {
            r.file_id.high() != 0 || r.parent_id.high() != 0
        })
    }

    /// Group records by their full 128-bit file ID.
    ///
    /// Returns a map from RefsFileId to all records referencing that file.
    pub fn group_by_file_id(&self) -> HashMap<RefsFileId, Vec<&RefsRecord>> {
        let mut groups: HashMap<RefsFileId, Vec<&RefsRecord>> = HashMap::new();
        for rec in &self.records {
            groups.entry(rec.file_id).or_default().push(rec);
        }
        groups
    }

    /// Reconstruct file paths using journal rewind only (no MFT seeding).
    ///
    /// ReFS has no traditional $MFT, so path reconstruction must rely entirely
    /// on walking the USN journal backwards to build the directory tree from
    /// rename and create events.
    ///
    /// Returns a map from RefsFileId to reconstructed path (if resolvable).
    pub fn reconstruct_paths(&self) -> HashMap<RefsFileId, String> {
        // Build a lookup: file_id -> (filename, parent_id)
        // Use the most recent (last seen) name for each file ID.
        let mut lookup: HashMap<RefsFileId, (String, RefsFileId)> = HashMap::new();

        for rec in &self.records {
            lookup.insert(rec.file_id, (rec.record.filename.clone(), rec.parent_id));
        }

        // Determine root IDs: any parent_id that has no entry in the lookup
        // is considered a root anchor.
        let root_ids: std::collections::HashSet<RefsFileId> = self.records
            .iter()
            .map(|r| r.parent_id)
            .filter(|pid| !lookup.contains_key(pid))
            .collect();

        // Resolve paths by walking parent chains up to a root.
        let mut paths: HashMap<RefsFileId, String> = HashMap::new();

        for &file_id in lookup.keys() {
            if root_ids.contains(&file_id) {
                continue;
            }

            let mut components = Vec::new();
            let mut current = file_id;
            let mut visited = std::collections::HashSet::new();

            loop {
                if !visited.insert(current) {
                    // Cycle detected, stop
                    break;
                }

                if let Some((name, parent)) = lookup.get(&current) {
                    components.push(name.clone());
                    if root_ids.contains(parent) || !lookup.contains_key(parent) {
                        break;
                    }
                    current = *parent;
                } else {
                    break;
                }
            }

            components.reverse();
            if !components.is_empty() {
                paths.insert(file_id, components.join("\\"));
            }
        }

        paths
    }
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{UsnReason, FileAttributes};
    use chrono::{DateTime, Utc};

    /// Helper: build a UsnRecord with major_version 3 for testing.
    fn make_v3_record(
        mft_entry: u64,
        parent_mft_entry: u64,
        reason: UsnReason,
        filename: &str,
    ) -> UsnRecord {
        UsnRecord {
            mft_entry,
            mft_sequence: 0,
            parent_mft_entry,
            parent_mft_sequence: 0,
            usn: 1000,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::from_bits_retain(0x20), // ARCHIVE
            source_info: 0,
            security_id: 0,
            major_version: 3,
        }
    }

    #[test]
    fn test_refs_file_id_from_u128() {
        // ReFS uses full 128-bit file IDs. Verify round-trip conversion.
        let value: u128 = 0x0000_0000_0000_0001_0000_0000_0000_0064;
        let id = RefsFileId::from_u128(value);
        assert_eq!(id.0, value);

        // Verify high/low extraction
        assert_eq!(id.high(), 0x0000_0000_0000_0001);
        assert_eq!(id.low(), 0x0000_0000_0000_0064);

        // Zero is a valid file ID
        let zero_id = RefsFileId::from_u128(0);
        assert_eq!(zero_id.0, 0);
        assert_eq!(zero_id.high(), 0);
        assert_eq!(zero_id.low(), 0);

        // Max value
        let max_id = RefsFileId::from_u128(u128::MAX);
        assert_eq!(max_id.high(), u64::MAX);
        assert_eq!(max_id.low(), u64::MAX);
    }

    #[test]
    fn test_refs_file_id_display() {
        // Display format should show high:low in hex
        let id = RefsFileId::from_u128(0x0000_0000_0000_0001_0000_0000_0000_0064);
        let display = format!("{}", id);
        assert_eq!(display, "0x0000000000000001:0x0000000000000064");

        // Zero case
        let zero_id = RefsFileId::from_u128(0);
        assert_eq!(format!("{}", zero_id), "0x0000000000000000:0x0000000000000000");

        // Large values
        let large_id = RefsFileId::from_u128(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0);
        assert_eq!(
            format!("{}", large_id),
            "0xdeadbeefcafebabe:0x123456789abcdef0"
        );
    }

    #[test]
    fn test_refs_volume_detection() {
        // Case 1: V3 records with upper bits set -> likely ReFS
        let rec1 = make_v3_record(100, 5, UsnReason::FILE_CREATE, "file.txt");
        let refs_rec1 = RefsRecord::new(
            rec1,
            RefsFileId::from_u128(0x0000_0000_0000_0001_0000_0000_0000_0064),
            RefsFileId::from_u128(0x0000_0000_0000_0001_0000_0000_0000_0005),
        );

        let analyzer = RefsAnalyzer::new(vec![refs_rec1]);
        assert!(analyzer.is_likely_refs(), "V3 records with upper bits should be detected as ReFS");

        // Case 2: V3 records with upper bits all zero -> likely NTFS using V3 format
        let rec2 = make_v3_record(200, 5, UsnReason::FILE_CREATE, "ntfs_file.txt");
        let refs_rec2 = RefsRecord::new(
            rec2,
            RefsFileId::from_u128(0x0000_0000_0000_0000_0000_0000_0000_00C8),
            RefsFileId::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0005),
        );

        let analyzer2 = RefsAnalyzer::new(vec![refs_rec2]);
        assert!(!analyzer2.is_likely_refs(), "V3 records with zero upper bits should not be flagged as ReFS");

        // Case 3: Empty records -> not ReFS
        let analyzer3 = RefsAnalyzer::new(vec![]);
        assert!(!analyzer3.is_likely_refs(), "Empty set should not be detected as ReFS");
    }

    #[test]
    fn test_refs_record_grouping() {
        // Create multiple records for the same file and different files
        let file_id_a = RefsFileId::from_u128(0x0000_0000_0000_0001_0000_0000_0000_000A);
        let file_id_b = RefsFileId::from_u128(0x0000_0000_0000_0001_0000_0000_0000_000B);
        let parent_id = RefsFileId::from_u128(0x0000_0000_0000_0001_0000_0000_0000_0005);

        let rec1 = RefsRecord::new(
            make_v3_record(10, 5, UsnReason::FILE_CREATE, "alpha.txt"),
            file_id_a,
            parent_id,
        );
        let rec2 = RefsRecord::new(
            make_v3_record(10, 5, UsnReason::DATA_EXTEND, "alpha.txt"),
            file_id_a,
            parent_id,
        );
        let rec3 = RefsRecord::new(
            make_v3_record(11, 5, UsnReason::FILE_CREATE, "beta.txt"),
            file_id_b,
            parent_id,
        );

        let analyzer = RefsAnalyzer::new(vec![rec1, rec2, rec3]);
        let groups = analyzer.group_by_file_id();

        assert_eq!(groups.len(), 2, "Should have 2 distinct file IDs");
        assert_eq!(
            groups.get(&file_id_a).map(|v| v.len()),
            Some(2),
            "file_id_a should have 2 records"
        );
        assert_eq!(
            groups.get(&file_id_b).map(|v| v.len()),
            Some(1),
            "file_id_b should have 1 record"
        );

        // Verify the grouped records have the right filenames
        let a_records = groups.get(&file_id_a).unwrap();
        assert!(a_records.iter().all(|r| r.record.filename == "alpha.txt"));
    }

    #[test]
    fn test_refs_path_reconstruction_without_mft() {
        // Simulate a directory tree created purely through journal events:
        //   root (id=5) -> "Documents" (id=100) -> "report.docx" (id=200)
        //
        // ReFS has no MFT to seed from, so paths come only from journal entries.

        let root_id = RefsFileId::from_u128(5);
        let docs_id = RefsFileId::from_u128(100);
        let file_id = RefsFileId::from_u128(200);

        // Directory creation event: "Documents" created under root
        let dir_create = RefsRecord::new(
            {
                let mut r = make_v3_record(100, 5, UsnReason::FILE_CREATE, "Documents");
                r.file_attributes = FileAttributes::from_bits_retain(0x10); // DIRECTORY
                r
            },
            docs_id,
            root_id,
        );

        // File creation event: "report.docx" created under "Documents"
        let file_create = RefsRecord::new(
            make_v3_record(200, 100, UsnReason::FILE_CREATE, "report.docx"),
            file_id,
            docs_id,
        );

        let analyzer = RefsAnalyzer::new(vec![dir_create, file_create]);
        let paths = analyzer.reconstruct_paths();

        // The file should be resolvable to its full path
        assert_eq!(
            paths.get(&file_id).map(|s| s.as_str()),
            Some("Documents\\report.docx"),
            "File path should be reconstructed from journal events alone"
        );

        // The directory itself should be resolvable
        assert_eq!(
            paths.get(&docs_id).map(|s| s.as_str()),
            Some("Documents"),
            "Directory path should be reconstructed"
        );

        // Root should not appear in reconstructed paths (it's the anchor)
        assert!(
            !paths.contains_key(&root_id),
            "Root directory should not be in reconstructed paths"
        );
    }
}
