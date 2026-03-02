//! $MFTMirr comparison for integrity verification.
//!
//! The $MFTMirr contains a copy of the first 4 MFT entries ($MFT, $MFTMirr,
//! $LogFile, $Volume). Comparing these with the actual $MFT entries can
//! detect corruption or tampering.

use anyhow::Result;
use log::warn;

/// MFT entry size (standard).
const MFT_ENTRY_SIZE: usize = 1024;

/// Number of entries mirrored in $MFTMirr (first 4).
const MIRROR_ENTRY_COUNT: usize = 4;

/// Names of the mirrored system files.
const MIRROR_NAMES: [&str; 4] = ["$MFT", "$MFTMirr", "$LogFile", "$Volume"];

/// Result of comparing $MFT with $MFTMirr.
#[derive(Debug, Clone)]
pub struct MirrorComparison {
    /// Whether the mirror matches the MFT for each of the first 4 entries.
    pub matches: [bool; MIRROR_ENTRY_COUNT],
    /// Byte offsets where differences were found, per entry.
    pub diff_offsets: Vec<Vec<usize>>,
    /// Overall: true if all entries match.
    pub is_consistent: bool,
}

/// Compare $MFT data with $MFTMirr data.
///
/// Checks that the first 4 MFT entries in the mirror match those in the MFT.
/// Any discrepancy could indicate corruption or deliberate tampering.
pub fn compare_mft_mirror(mft_data: &[u8], mftmirr_data: &[u8]) -> Result<MirrorComparison> {
    let mut matches = [true; MIRROR_ENTRY_COUNT];
    let mut diff_offsets = vec![Vec::new(); MIRROR_ENTRY_COUNT];
    let mut is_consistent = true;

    for i in 0..MIRROR_ENTRY_COUNT {
        let mft_start = i * MFT_ENTRY_SIZE;
        let mft_end = mft_start + MFT_ENTRY_SIZE;
        let mirr_start = i * MFT_ENTRY_SIZE;
        let mirr_end = mirr_start + MFT_ENTRY_SIZE;

        if mft_end > mft_data.len() || mirr_end > mftmirr_data.len() {
            warn!(
                "Insufficient data for MFT mirror entry {} ({})",
                i, MIRROR_NAMES[i]
            );
            matches[i] = false;
            is_consistent = false;
            continue;
        }

        let mft_entry = &mft_data[mft_start..mft_end];
        let mirr_entry = &mftmirr_data[mirr_start..mirr_end];

        for (offset, (a, b)) in mft_entry.iter().zip(mirr_entry.iter()).enumerate() {
            if a != b {
                matches[i] = false;
                is_consistent = false;
                diff_offsets[i].push(offset);
            }
        }

        if !matches[i] {
            warn!(
                "$MFTMirr entry {} ({}) differs from $MFT at {} byte(s)",
                i,
                MIRROR_NAMES[i],
                diff_offsets[i].len()
            );
        }
    }

    Ok(MirrorComparison {
        matches,
        diff_offsets,
        is_consistent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_mirror() {
        let data = vec![0xAAu8; MFT_ENTRY_SIZE * MIRROR_ENTRY_COUNT];
        let result = compare_mft_mirror(&data, &data).unwrap();
        assert!(result.is_consistent);
        assert!(result.matches.iter().all(|&m| m));
    }

    #[test]
    fn test_different_mirror() {
        let mft = vec![0xAAu8; MFT_ENTRY_SIZE * MIRROR_ENTRY_COUNT];
        let mut mirr = mft.clone();
        mirr[0] = 0xBB; // Change first byte of first entry

        let result = compare_mft_mirror(&mft, &mirr).unwrap();
        assert!(!result.is_consistent);
        assert!(!result.matches[0]);
        assert!(result.matches[1]);
        assert!(result.matches[2]);
        assert!(result.matches[3]);
        assert_eq!(result.diff_offsets[0], vec![0]);
    }

    #[test]
    fn test_short_mirror_data() {
        let mft = vec![0xAAu8; MFT_ENTRY_SIZE * MIRROR_ENTRY_COUNT];
        let mirr = vec![0xAAu8; MFT_ENTRY_SIZE]; // Only 1 entry

        let result = compare_mft_mirror(&mft, &mirr).unwrap();
        assert!(!result.is_consistent);
        assert!(result.matches[0]); // First entry matches
        assert!(!result.matches[1]); // Rest are missing
    }
}
