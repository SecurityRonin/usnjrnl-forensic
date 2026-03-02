//! Journal Rewind engine for complete path reconstruction.
//!
//! Implements the CyberCX "Rewind" algorithm: processes USN journal entries
//! in reverse chronological order to reconstruct full paths even when MFT
//! entries have been reallocated multiple times.
//!
//! ## Algorithm
//!
//! Traditional tools resolve USN parent references against the *current* MFT
//! state. When an MFT entry has been reused (sequence number changed), the
//! parent can't be found and the path is marked "UNKNOWN".
//!
//! The rewind approach:
//! 1. Seed a lookup table from the current $MFT state (entry -> name + parent)
//! 2. Process USN records from newest to oldest
//! 3. For each record, track the (entry, sequence) -> (name, parent_entry, parent_seq) mapping
//! 4. Handle renames by restoring old names when seeing RENAME_OLD_NAME events
//! 5. Recursively resolve paths through the lookup table
//!
//! This guarantees complete path resolution for every journal entry.

use std::collections::HashMap;

use crate::usn::{UsnRecord, UsnReason};

/// Key for the rewind lookup table: (mft_entry, mft_sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryKey {
    pub entry: u64,
    pub sequence: u16,
}

impl EntryKey {
    pub fn new(entry: u64, sequence: u16) -> Self {
        Self { entry, sequence }
    }

    /// The NTFS root directory is always entry 5, sequence 5.
    pub fn root() -> Self {
        Self { entry: 5, sequence: 5 }
    }

    pub fn is_root(&self) -> bool {
        self.entry == 5
    }
}

/// Value stored in the rewind lookup table.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// Filename of this entry (not full path).
    pub name: String,
    /// Key to the parent directory entry.
    pub parent: EntryKey,
}

/// Result of path resolution for a single USN record.
#[derive(Debug, Clone)]
pub struct ResolvedRecord {
    /// The original USN record.
    pub record: UsnRecord,
    /// The fully resolved path (e.g. ".\Users\admin\temp\malware.exe").
    pub full_path: String,
    /// The resolved parent path (e.g. ".\Users\admin\temp").
    pub parent_path: String,
}

/// The Rewind engine for full path reconstruction.
pub struct RewindEngine {
    /// Lookup table: (entry, sequence) -> (name, parent_key).
    lookup: HashMap<EntryKey, EntryInfo>,
}

impl RewindEngine {
    /// Create a new empty RewindEngine.
    pub fn new() -> Self {
        Self {
            lookup: HashMap::new(),
        }
    }

    /// Create a RewindEngine seeded with MFT entries.
    ///
    /// The `mft_entries` iterator yields (entry_number, sequence, filename, parent_entry, parent_sequence).
    pub fn from_mft<I>(mft_entries: I) -> Self
    where
        I: IntoIterator<Item = (u64, u16, String, u64, u16)>,
    {
        let mut engine = Self::new();
        for (entry, seq, name, parent_entry, parent_seq) in mft_entries {
            engine.lookup.insert(
                EntryKey::new(entry, seq),
                EntryInfo {
                    name,
                    parent: EntryKey::new(parent_entry, parent_seq),
                },
            );
        }
        engine
    }

    /// Number of entries in the lookup table.
    pub fn lookup_len(&self) -> usize {
        self.lookup.len()
    }

    /// Insert or update an entry in the lookup table.
    pub fn insert(&mut self, key: EntryKey, info: EntryInfo) {
        self.lookup.insert(key, info);
    }

    /// Resolve the full path for a given entry key.
    ///
    /// Recursively follows parent references until reaching the root.
    /// Returns "." as the root prefix (representing the volume root).
    pub fn resolve_path(&self, key: &EntryKey) -> String {
        self.resolve_path_inner(key, 0)
    }

    fn resolve_path_inner(&self, key: &EntryKey, depth: usize) -> String {
        // Prevent infinite loops from circular references
        if depth > 256 {
            return format!("UNRESOLVED({}:{})", key.entry, key.sequence);
        }

        if key.is_root() {
            return ".".to_string();
        }

        if let Some(info) = self.lookup.get(key) {
            let parent_path = self.resolve_path_inner(&info.parent, depth + 1);
            format!("{}\\{}", parent_path, info.name)
        } else {
            format!("UNKNOWN({}:{})", key.entry, key.sequence)
        }
    }

    /// Process USN records using the Rewind algorithm.
    ///
    /// Records MUST be sorted by USN/timestamp in ascending order (oldest first).
    /// This function processes them in reverse to build the lookup table, then
    /// resolves paths for each record in forward order.
    ///
    /// Returns resolved records with full paths.
    pub fn rewind(&mut self, records: &[UsnRecord]) -> Vec<ResolvedRecord> {
        // Phase 1: Process records in reverse to build/update the lookup table.
        // Going backwards from newest to oldest, we track how entries were
        // named and where they were parented at each point in time.
        for record in records.iter().rev() {
            let key = EntryKey::new(record.mft_entry, record.mft_sequence);
            let parent_key = EntryKey::new(record.parent_mft_entry, record.parent_mft_sequence);

            // Always record what we learn about this entry's name and parent.
            // Since we're going backwards, the first time we see an entry-sequence
            // pair is its LATEST state. We want to capture earlier states too.
            if record.reason.contains(UsnReason::RENAME_OLD_NAME) {
                // This is the OLD name before a rename. Going backwards, this means
                // the entry was renamed FROM this name TO something else.
                // We want to record this as the name for this entry-sequence pair
                // at this point in time.
                self.lookup.insert(key, EntryInfo {
                    name: record.filename.clone(),
                    parent: parent_key,
                });
            } else if !self.lookup.contains_key(&key) {
                // First time seeing this entry-sequence going backwards = latest state
                self.lookup.insert(key, EntryInfo {
                    name: record.filename.clone(),
                    parent: parent_key,
                });
            }

            // If this is a directory, also ensure the parent's chain is known
            // (the parent entry-sequence -> its name mapping may come from other records)
        }

        // Phase 2: Resolve paths for each record in forward order.
        // Now re-process records forward. For each record, we need to resolve
        // the path as it existed at that point in time.
        //
        // We rebuild the lookup as we go forward, updating names on renames
        // and tracking creates/deletes.
        let mut forward_lookup = self.lookup.clone();
        let mut results = Vec::with_capacity(records.len());

        for record in records {
            let key = EntryKey::new(record.mft_entry, record.mft_sequence);
            let parent_key = EntryKey::new(record.parent_mft_entry, record.parent_mft_sequence);

            // Update the forward lookup with what this record tells us
            if record.reason.contains(UsnReason::RENAME_NEW_NAME) {
                // Entry was renamed to this name
                forward_lookup.insert(key, EntryInfo {
                    name: record.filename.clone(),
                    parent: parent_key,
                });
            } else if record.reason.contains(UsnReason::FILE_CREATE) {
                // New entry created
                forward_lookup.insert(key, EntryInfo {
                    name: record.filename.clone(),
                    parent: parent_key,
                });
            } else if !forward_lookup.contains_key(&key) {
                forward_lookup.insert(key, EntryInfo {
                    name: record.filename.clone(),
                    parent: parent_key,
                });
            }

            // Resolve the parent path using the forward lookup
            let parent_path = resolve_path_from(&forward_lookup, &parent_key);
            let full_path = format!("{}\\{}", parent_path, record.filename);

            results.push(ResolvedRecord {
                record: record.clone(),
                full_path,
                parent_path,
            });
        }

        results
    }
}

/// Resolve a path from a lookup table (standalone function for forward pass).
fn resolve_path_from(lookup: &HashMap<EntryKey, EntryInfo>, key: &EntryKey) -> String {
    resolve_path_from_inner(lookup, key, 0)
}

fn resolve_path_from_inner(
    lookup: &HashMap<EntryKey, EntryInfo>,
    key: &EntryKey,
    depth: usize,
) -> String {
    if depth > 256 {
        return format!("UNRESOLVED({}:{})", key.entry, key.sequence);
    }
    if key.is_root() {
        return ".".to_string();
    }
    if let Some(info) = lookup.get(key) {
        let parent_path = resolve_path_from_inner(lookup, &info.parent, depth + 1);
        format!("{}\\{}", parent_path, info.name)
    } else {
        format!("UNKNOWN({}:{})", key.entry, key.sequence)
    }
}

impl Default for RewindEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use crate::usn::{FileAttributes, UsnReason};

    fn make_record(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        reason: UsnReason,
        filename: &str,
        usn: i64,
    ) -> UsnRecord {
        UsnRecord {
            mft_entry: entry,
            mft_sequence: seq,
            parent_mft_entry: parent_entry,
            parent_mft_sequence: parent_seq,
            usn,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    #[test]
    fn test_entry_key_root() {
        let root = EntryKey::root();
        assert!(root.is_root());
        assert_eq!(root.entry, 5);
    }

    #[test]
    fn test_resolve_path_simple() {
        // MFT has: entry 100 "Users" -> root, entry 200 "admin" -> 100
        let engine = RewindEngine::from_mft(vec![
            (100, 1, "Users".into(), 5, 5),
            (200, 1, "admin".into(), 100, 1),
        ]);

        let path = engine.resolve_path(&EntryKey::new(200, 1));
        assert_eq!(path, ".\\Users\\admin");
    }

    #[test]
    fn test_resolve_path_root() {
        let engine = RewindEngine::new();
        let path = engine.resolve_path(&EntryKey::root());
        assert_eq!(path, ".");
    }

    #[test]
    fn test_resolve_path_unknown_entry() {
        let engine = RewindEngine::new();
        let path = engine.resolve_path(&EntryKey::new(999, 1));
        assert!(path.contains("UNKNOWN"));
    }

    #[test]
    fn test_rewind_simple_create() {
        // Scenario: file created at .\temp\malware.exe
        let mut engine = RewindEngine::from_mft(vec![
            (50, 1, "temp".into(), 5, 5),
        ]);

        let records = vec![
            make_record(100, 1, 50, 1, UsnReason::FILE_CREATE, "malware.exe", 100),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].full_path, ".\\temp\\malware.exe");
        assert_eq!(resolved[0].parent_path, ".\\temp");
    }

    #[test]
    fn test_rewind_resolves_unknown_parent_via_journal() {
        // Scenario from CyberCX blog:
        // MFT entry 983 was reused. Current state has seq=6, but the journal
        // record refers to parent 983 with seq=4 (the old allocation).
        // The journal itself contains events that tell us entry 983 seq 4
        // was a folder named "ip_scanner" under entry 500 "Drivers".
        //
        // Without rewind, parent 983:4 would be UNKNOWN.
        // With rewind, we should resolve it to .\Intel\Drivers\ip_scanner

        let mut engine = RewindEngine::from_mft(vec![
            (30, 1, "Intel".into(), 5, 5),
        ]);

        // Journal records (oldest to newest):
        // 1. Folder "Drivers" created at entry 500, seq 1, parent 30:1 (Intel)
        // 2. Folder "ip_scanner" created at entry 983, seq 4, parent 500:1 (Drivers)
        // 3. File "data.txt" created at entry 1500, seq 1, parent 983:4 (ip_scanner)
        // 4. File "data.txt" deleted
        // 5. Folder "ip_scanner" deleted
        // 6. Entry 983 reused as seq 6 for something else
        let records = vec![
            make_record(500, 1, 30, 1, UsnReason::FILE_CREATE, "Drivers", 10),
            make_record(983, 4, 500, 1, UsnReason::FILE_CREATE, "ip_scanner", 20),
            make_record(1500, 1, 983, 4, UsnReason::FILE_CREATE, "data.txt", 30),
            make_record(1500, 1, 983, 4, UsnReason::FILE_DELETE, "data.txt", 40),
            make_record(983, 4, 500, 1, UsnReason::FILE_DELETE, "ip_scanner", 50),
            make_record(983, 6, 5, 5, UsnReason::FILE_CREATE, "NewFolder", 60),
        ];

        let resolved = engine.rewind(&records);

        // The data.txt create should resolve to .\Intel\Drivers\ip_scanner\data.txt
        assert_eq!(resolved[2].full_path, ".\\Intel\\Drivers\\ip_scanner\\data.txt");
        // The new folder at entry 983 seq 6 should be .\NewFolder
        assert_eq!(resolved[5].full_path, ".\\NewFolder");
    }

    #[test]
    fn test_rewind_handles_rename() {
        // Scenario: folder renamed from "old_name" to "new_name"
        // Files created under the folder should show correct name at each point.

        let mut engine = RewindEngine::from_mft(vec![]);

        let records = vec![
            // Folder created as "old_name"
            make_record(100, 1, 5, 5, UsnReason::FILE_CREATE, "old_name", 10),
            // File created under old_name
            make_record(200, 1, 100, 1, UsnReason::FILE_CREATE, "before.txt", 20),
            // Folder renamed: old_name -> new_name
            make_record(100, 1, 5, 5, UsnReason::RENAME_OLD_NAME, "old_name", 30),
            make_record(100, 1, 5, 5, UsnReason::RENAME_NEW_NAME, "new_name", 31),
            // File created under new_name
            make_record(300, 1, 100, 1, UsnReason::FILE_CREATE, "after.txt", 40),
        ];

        let resolved = engine.rewind(&records);

        // before.txt should be under old_name at the time it was created
        assert_eq!(resolved[1].full_path, ".\\old_name\\before.txt");
        // after.txt should be under new_name
        assert_eq!(resolved[4].full_path, ".\\new_name\\after.txt");
    }

    #[test]
    fn test_rewind_multiple_reuse() {
        // Entry 50 is reused 3 times with different sequence numbers
        let mut engine = RewindEngine::from_mft(vec![]);

        let records = vec![
            make_record(50, 2, 5, 5, UsnReason::FILE_CREATE, "first_life", 10),
            make_record(50, 2, 5, 5, UsnReason::FILE_DELETE, "first_life", 20),
            make_record(50, 4, 5, 5, UsnReason::FILE_CREATE, "second_life", 30),
            make_record(50, 4, 5, 5, UsnReason::FILE_DELETE, "second_life", 40),
            make_record(50, 6, 5, 5, UsnReason::FILE_CREATE, "third_life", 50),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved[0].full_path, ".\\first_life");
        assert_eq!(resolved[2].full_path, ".\\second_life");
        assert_eq!(resolved[4].full_path, ".\\third_life");
    }

    #[test]
    fn test_rewind_deep_path_reconstruction() {
        // Deep path: .\A\B\C\D\file.txt where all are created in journal
        let mut engine = RewindEngine::from_mft(vec![]);

        let records = vec![
            make_record(10, 1, 5, 5, UsnReason::FILE_CREATE, "A", 10),
            make_record(20, 1, 10, 1, UsnReason::FILE_CREATE, "B", 20),
            make_record(30, 1, 20, 1, UsnReason::FILE_CREATE, "C", 30),
            make_record(40, 1, 30, 1, UsnReason::FILE_CREATE, "D", 40),
            make_record(50, 1, 40, 1, UsnReason::FILE_CREATE, "file.txt", 50),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved[4].full_path, ".\\A\\B\\C\\D\\file.txt");
    }

    #[test]
    fn test_from_mft_seeding() {
        let engine = RewindEngine::from_mft(vec![
            (100, 1, "Users".into(), 5, 5),
            (200, 1, "admin".into(), 100, 1),
            (300, 1, "Desktop".into(), 200, 1),
        ]);
        assert_eq!(engine.lookup_len(), 3);
        let path = engine.resolve_path(&EntryKey::new(300, 1));
        assert_eq!(path, ".\\Users\\admin\\Desktop");
    }
}
