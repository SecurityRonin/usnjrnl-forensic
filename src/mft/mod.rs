//! MFT parsing for path resolution and correlation with USN Journal.
//!
//! Uses the `mft` crate for parsing $MFT entries. Extracts entry numbers,
//! sequence numbers, filenames, and parent references needed for the
//! Rewind engine and timestomping detection.

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::debug;
use mft::MftParser;
use mft::attribute::MftAttributeType;

use crate::rewind::{EntryKey, RewindEngine};

/// Parsed MFT entry with fields relevant to USN Journal correlation.
#[derive(Debug, Clone)]
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub filename: String,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub is_directory: bool,
    pub is_in_use: bool,
    /// $STANDARD_INFORMATION timestamps (user-modifiable).
    pub si_created: Option<DateTime<Utc>>,
    pub si_modified: Option<DateTime<Utc>>,
    pub si_mft_modified: Option<DateTime<Utc>>,
    pub si_accessed: Option<DateTime<Utc>>,
    /// $FILE_NAME timestamps (harder to modify, more trustworthy).
    pub fn_created: Option<DateTime<Utc>>,
    pub fn_modified: Option<DateTime<Utc>>,
    pub fn_mft_modified: Option<DateTime<Utc>>,
    pub fn_accessed: Option<DateTime<Utc>>,
    /// Full path resolved from MFT parent chain.
    pub full_path: String,
    /// File size from $DATA attribute.
    pub file_size: u64,
    /// Whether this entry has alternate data streams.
    pub has_ads: bool,
}

/// Parsed $MFT data for correlation.
pub struct MftData {
    /// All parsed entries.
    pub entries: Vec<MftEntry>,
    /// Map: entry_number -> index in entries vec (for current allocation).
    pub by_entry: HashMap<u64, usize>,
    /// Map: (entry, sequence) -> index (sequence-aware lookup).
    pub by_key: HashMap<EntryKey, usize>,
}

impl MftData {
    /// Parse raw $MFT data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut parser = MftParser::from_buffer(data.to_vec())?;

        // First pass: collect all raw MFT entries
        let raw_entries: Vec<_> = parser.iter_entries().collect();

        let mut entries = Vec::new();
        let mut by_entry = HashMap::new();
        let mut by_key = HashMap::new();

        for entry_result in raw_entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    debug!("Skipping invalid MFT entry: {}", e);
                    continue;
                }
            };

            let entry_number = entry.header.record_number;
            let sequence_number = entry.header.sequence;
            let is_in_use = entry.is_allocated();
            let is_directory = entry.is_dir();

            // SI timestamps
            let mut si_created = None;
            let mut si_modified = None;
            let mut si_mft_modified = None;
            let mut si_accessed = None;
            let mut has_ads = false;

            // Extract $STANDARD_INFORMATION timestamps
            for attr_result in entry.iter_attributes_matching(
                Some(vec![MftAttributeType::StandardInformation]),
            ) {
                if let Ok(attr) = attr_result {
                    if let Some(si) = attr.data.into_standard_info() {
                        si_created = Some(DateTime::<Utc>::from(si.created));
                        si_modified = Some(DateTime::<Utc>::from(si.modified));
                        si_mft_modified = Some(DateTime::<Utc>::from(si.mft_modified));
                        si_accessed = Some(DateTime::<Utc>::from(si.accessed));
                    }
                }
            }

            // Use find_best_name_attribute for filename and parent ref
            let best_name = match entry.find_best_name_attribute() {
                Some(name) => name,
                None => continue,
            };

            let best_filename = best_name.name.clone();
            let parent_entry = best_name.parent.entry;
            let parent_sequence = best_name.parent.sequence;
            let fn_created = Some(DateTime::<Utc>::from(best_name.created));
            let fn_modified = Some(DateTime::<Utc>::from(best_name.modified));
            let fn_mft_modified = Some(DateTime::<Utc>::from(best_name.mft_modified));
            let fn_accessed = Some(DateTime::<Utc>::from(best_name.accessed));

            // Check for ADS: look for $DATA attributes with non-empty names
            for attr_result in entry.iter_attributes_matching(
                Some(vec![MftAttributeType::DATA]),
            ) {
                if let Ok(attr) = attr_result {
                    if !attr.header.name.is_empty() {
                        has_ads = true;
                        break;
                    }
                }
            }

            // Resolve full path (parser is no longer borrowed by iter_entries)
            let full_path = parser
                .get_full_path_for_entry(&entry)
                .unwrap_or_default()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let idx = entries.len();
            let mft_entry = MftEntry {
                entry_number,
                sequence_number,
                filename: best_filename,
                parent_entry,
                parent_sequence,
                is_directory,
                is_in_use,
                si_created,
                si_modified,
                si_mft_modified,
                si_accessed,
                fn_created,
                fn_modified,
                fn_mft_modified,
                fn_accessed,
                full_path,
                file_size: 0,
                has_ads,
            };

            by_entry.insert(entry_number, idx);
            by_key.insert(EntryKey::new(entry_number, sequence_number), idx);
            entries.push(mft_entry);
        }

        Ok(Self {
            entries,
            by_entry,
            by_key,
        })
    }

    /// Seed a RewindEngine with the current MFT state.
    pub fn seed_rewind(&self) -> RewindEngine {
        let mft_iter = self.entries.iter().map(|e| {
            (
                e.entry_number,
                e.sequence_number,
                e.filename.clone(),
                e.parent_entry,
                e.parent_sequence,
            )
        });
        RewindEngine::from_mft(mft_iter)
    }

    /// Detect potential timestomping: $SI created before $FN created.
    pub fn detect_timestomping(&self) -> Vec<&MftEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let (Some(si_c), Some(fn_c)) = (e.si_created, e.fn_created) {
                    si_c < fn_c || {
                        if let Some(si_m) = e.si_modified {
                            si_m < fn_c
                        } else {
                            false
                        }
                    }
                } else {
                    false
                }
            })
            .collect()
    }

    /// Get entry by entry number (current allocation).
    pub fn get_by_entry(&self, entry_number: u64) -> Option<&MftEntry> {
        self.by_entry.get(&entry_number).map(|&idx| &self.entries[idx])
    }

    /// Get entry by (entry, sequence) pair.
    pub fn get_by_key(&self, key: &EntryKey) -> Option<&MftEntry> {
        self.by_key.get(key).map(|&idx| &self.entries[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mft_data_empty() {
        let result = MftData::parse(&[]);
        assert!(result.is_err() || result.unwrap().entries.is_empty());
    }

    #[test]
    fn test_entry_key_equality() {
        let k1 = EntryKey::new(100, 3);
        let k2 = EntryKey::new(100, 3);
        let k3 = EntryKey::new(100, 4);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }
}
