//! $LogFile parser for gap detection and LSN correlation.
//!
//! The NTFS $LogFile records transaction log entries. By analyzing restart
//! areas and record pages, we can detect gaps that indicate journal clearing
//! or corruption.

pub mod usn_extractor;

use anyhow::Result;
use log::debug;

// ─── Constants ───────────────────────────────────────────────────────────────

/// NTFS $LogFile restart area signature "RSTR".
const RSTR_SIGNATURE: &[u8; 4] = b"RSTR";

/// NTFS $LogFile record page signature "RCRD".
const RCRD_SIGNATURE: &[u8; 4] = b"RCRD";

/// Default NTFS $LogFile page size.
const LOG_PAGE_SIZE: usize = 0x1000; // 4096 bytes

// ─── Parsed structures ──────────────────────────────────────────────────────

/// Parsed NTFS $LogFile restart area.
#[derive(Debug, Clone)]
pub struct RestartArea {
    pub offset: usize,
    pub current_lsn: u64,
    pub log_clients: u16,
    pub system_page_size: u32,
    pub log_page_size: u32,
}

/// Summary of $LogFile analysis.
#[derive(Debug, Clone)]
pub struct LogFileSummary {
    pub restart_areas: Vec<RestartArea>,
    pub record_page_count: usize,
    pub has_gaps: bool,
    pub highest_lsn: u64,
}

/// Parse NTFS $LogFile data.
///
/// Scans for restart areas (RSTR) and record pages (RCRD) to build
/// a summary. Detects gaps in the log sequence.
pub fn parse_logfile(data: &[u8]) -> Result<LogFileSummary> {
    let mut restart_areas = Vec::new();
    let mut record_page_count = 0;
    let mut highest_lsn: u64 = 0;
    let mut has_gaps = false;
    let mut last_page_had_rcrd = false;

    let page_count = data.len() / LOG_PAGE_SIZE;

    for page_idx in 0..page_count {
        let page_offset = page_idx * LOG_PAGE_SIZE;

        if page_offset + 4 > data.len() {
            break;
        }

        let sig = &data[page_offset..page_offset + 4];

        if sig == RSTR_SIGNATURE {
            if page_offset + 0x28 <= data.len() {
                let current_lsn = u64::from_le_bytes(
                    data[page_offset + 0x08..page_offset + 0x10]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
                let log_clients = u16::from_le_bytes(
                    data[page_offset + 0x10..page_offset + 0x12]
                        .try_into()
                        .unwrap_or([0; 2]),
                );
                let system_page_size = u32::from_le_bytes(
                    data[page_offset + 0x20..page_offset + 0x24]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                let log_page_size = u32::from_le_bytes(
                    data[page_offset + 0x24..page_offset + 0x28]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if current_lsn > highest_lsn {
                    highest_lsn = current_lsn;
                }

                restart_areas.push(RestartArea {
                    offset: page_offset,
                    current_lsn,
                    log_clients,
                    system_page_size,
                    log_page_size,
                });
            }
            last_page_had_rcrd = false;
        } else if sig == RCRD_SIGNATURE {
            record_page_count += 1;

            // Extract last_end_lsn from RCRD header (offset 0x18)
            if page_offset + 0x20 <= data.len() {
                let page_lsn = u64::from_le_bytes(
                    data[page_offset + 0x18..page_offset + 0x20]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
                if page_lsn > highest_lsn {
                    highest_lsn = page_lsn;
                }
            }

            last_page_had_rcrd = true;
        } else {
            // Neither RSTR nor RCRD - could be a gap
            if last_page_had_rcrd && page_idx > 2 {
                // If we had RCRD pages and now see something else, that's a gap
                let is_zeroed = data[page_offset..page_offset + 4] == [0, 0, 0, 0];
                if !is_zeroed {
                    has_gaps = true;
                    debug!("Gap detected at page {} (offset 0x{:x})", page_idx, page_offset);
                }
            }
            last_page_had_rcrd = false;
        }
    }

    Ok(LogFileSummary {
        restart_areas,
        record_page_count,
        has_gaps,
        highest_lsn,
    })
}

/// Correlate $LogFile LSN with USN Journal entries.
///
/// The USN (Update Sequence Number) in journal records corresponds to
/// byte offsets in the journal. $LogFile LSNs are separate but can help
/// detect if the journal was cleared (LSN continuity break).
pub fn detect_journal_clearing(logfile_summary: &LogFileSummary) -> bool {
    // Journal clearing indicators:
    // 1. Gaps in $LogFile record pages
    // 2. Very few restart areas (should have exactly 2 normally)
    // 3. LSN discontinuities

    if logfile_summary.has_gaps {
        return true;
    }

    if logfile_summary.restart_areas.len() != 2 {
        return logfile_summary.restart_areas.is_empty();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rstr_page(lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RSTR_SIGNATURE);
        page[0x08..0x10].copy_from_slice(&lsn.to_le_bytes());
        page[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // 1 client
        page[0x20..0x24].copy_from_slice(&4096u32.to_le_bytes());
        page[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        page
    }

    fn make_rcrd_page(lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&lsn.to_le_bytes());
        page
    }

    #[test]
    fn test_parse_logfile_with_restart_areas() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_rstr_page(1000));
        data.extend_from_slice(&make_rstr_page(2000));
        data.extend_from_slice(&make_rcrd_page(3000));

        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 2);
        assert_eq!(summary.record_page_count, 1);
        assert_eq!(summary.highest_lsn, 3000);
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_detect_journal_clearing_with_gaps() {
        let summary = LogFileSummary {
            restart_areas: vec![],
            record_page_count: 0,
            has_gaps: true,
            highest_lsn: 0,
        };
        assert!(detect_journal_clearing(&summary));
    }

    #[test]
    fn test_normal_logfile_no_clearing() {
        let summary = LogFileSummary {
            restart_areas: vec![
                RestartArea { offset: 0, current_lsn: 1000, log_clients: 1, system_page_size: 4096, log_page_size: 4096 },
                RestartArea { offset: 4096, current_lsn: 2000, log_clients: 1, system_page_size: 4096, log_page_size: 4096 },
            ],
            record_page_count: 100,
            has_gaps: false,
            highest_lsn: 5000,
        };
        assert!(!detect_journal_clearing(&summary));
    }
}
