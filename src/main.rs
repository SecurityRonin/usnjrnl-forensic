use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use usnjrnl::mft::MftData;
use usnjrnl::rewind::RewindEngine;
use usnjrnl::usn;

#[derive(Parser)]
#[command(
    name = "usnjrnl",
    about = "NTFS USN Journal parser with full path reconstruction via journal rewind",
    long_about = "Parses $UsnJrnl:$J with optional $MFT correlation to reconstruct full file paths.\n\
                  Implements the CyberCX 'Rewind' algorithm for complete path resolution even when\n\
                  MFT entries have been reallocated. Supports V2/V3/V4 records, timestomping\n\
                  detection, $MFTMirr integrity checks, and $LogFile gap analysis.",
    version
)]
struct Cli {
    /// Path to raw $UsnJrnl:$J file
    #[arg(short = 'j', long)]
    journal: PathBuf,

    /// Path to raw $MFT file (enables full path resolution and rewind)
    #[arg(short = 'm', long)]
    mft: Option<PathBuf>,

    /// Path to $MFTMirr file (enables integrity check)
    #[arg(long)]
    mftmirr: Option<PathBuf>,

    /// Path to $LogFile (enables gap detection)
    #[arg(long)]
    logfile: Option<PathBuf>,

    /// Output CSV file
    #[arg(long)]
    csv: Option<PathBuf>,

    /// Output JSON Lines file
    #[arg(long)]
    jsonl: Option<PathBuf>,

    /// Output SQLite database
    #[arg(long)]
    sqlite: Option<PathBuf>,

    /// Detect timestomping (requires --mft)
    #[arg(long)]
    detect_timestomping: bool,

    /// Show statistics summary
    #[arg(long, default_value_t = true)]
    stats: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // ─── Parse USN Journal ───────────────────────────────────────────────────

    eprintln!("[*] Reading $UsnJrnl:$J from {}", cli.journal.display());
    let usn_data = std::fs::read(&cli.journal)
        .with_context(|| format!("Failed to read journal: {}", cli.journal.display()))?;
    eprintln!("[*] Journal size: {} bytes ({:.1} MB)", usn_data.len(), usn_data.len() as f64 / 1_048_576.0);

    eprintln!("[*] Parsing USN records...");
    let records = usn::parse_usn_journal(&usn_data)
        .context("Failed to parse USN journal")?;
    eprintln!("[+] {} USN records parsed", records.len());

    // Print reason breakdown
    if cli.stats {
        print_reason_stats(&records);
    }

    // ─── Parse MFT (optional) ────────────────────────────────────────────────

    let mft_data = if let Some(ref mft_path) = cli.mft {
        eprintln!("[*] Reading $MFT from {}", mft_path.display());
        let raw = std::fs::read(mft_path)
            .with_context(|| format!("Failed to read MFT: {}", mft_path.display()))?;
        eprintln!("[*] MFT size: {} bytes ({:.1} MB)", raw.len(), raw.len() as f64 / 1_048_576.0);

        eprintln!("[*] Parsing $MFT...");
        let mft = MftData::parse(&raw).context("Failed to parse $MFT")?;
        eprintln!("[+] {} MFT entries parsed", mft.entries.len());

        // Timestomping detection
        if cli.detect_timestomping {
            let suspicious = mft.detect_timestomping();
            if suspicious.is_empty() {
                eprintln!("[+] No timestomping indicators detected");
            } else {
                eprintln!("[!] {} potential timestomping indicators:", suspicious.len());
                for entry in suspicious.iter().take(20) {
                    eprintln!(
                        "    Entry {} ({}): SI_Created={:?} < FN_Created={:?}",
                        entry.entry_number,
                        entry.full_path,
                        entry.si_created,
                        entry.fn_created
                    );
                }
                if suspicious.len() > 20 {
                    eprintln!("    ... and {} more", suspicious.len() - 20);
                }
            }
        }

        Some(mft)
    } else {
        None
    };

    // ─── MFTMirr integrity check ─────────────────────────────────────────────

    if let (Some(ref mft_path), Some(ref mirr_path)) = (&cli.mft, &cli.mftmirr) {
        eprintln!("[*] Checking $MFTMirr integrity...");
        let mft_raw = std::fs::read(mft_path)?;
        let mirr_raw = std::fs::read(mirr_path)
            .with_context(|| format!("Failed to read $MFTMirr: {}", mirr_path.display()))?;
        let comparison = usnjrnl::mftmirr::compare_mft_mirror(&mft_raw, &mirr_raw)?;
        if comparison.is_consistent {
            eprintln!("[+] $MFTMirr is consistent with $MFT");
        } else {
            eprintln!("[!] $MFTMirr INCONSISTENCY DETECTED:");
            for (i, matches) in comparison.matches.iter().enumerate() {
                let name = ["$MFT", "$MFTMirr", "$LogFile", "$Volume"][i];
                if !matches {
                    eprintln!(
                        "    Entry {} ({}): {} byte differences",
                        i,
                        name,
                        comparison.diff_offsets[i].len()
                    );
                }
            }
        }
    }

    // ─── LogFile analysis + USN extraction ──────────────────────────────────

    let logfile_usn_records = if let Some(ref logfile_path) = cli.logfile {
        eprintln!("[*] Analyzing $LogFile...");
        let log_raw = std::fs::read(logfile_path)
            .with_context(|| format!("Failed to read $LogFile: {}", logfile_path.display()))?;
        let summary = usnjrnl::logfile::parse_logfile(&log_raw)?;
        eprintln!(
            "[+] $LogFile: {} restart areas, {} record pages, highest LSN={}",
            summary.restart_areas.len(),
            summary.record_page_count,
            summary.highest_lsn
        );
        if summary.has_gaps {
            eprintln!("[!] GAPS DETECTED in $LogFile - possible journal clearing");
        }
        if usnjrnl::logfile::detect_journal_clearing(&summary) {
            eprintln!("[!] Evidence of journal clearing detected");
        }

        // Extract embedded USN records from $LogFile RCRD pages
        eprintln!("[*] Extracting USN records embedded in $LogFile...");
        let extracted = usnjrnl::logfile::usn_extractor::extract_usn_from_logfile(&log_raw);
        eprintln!("[+] {} USN records recovered from $LogFile", extracted.len());
        extracted
    } else {
        Vec::new()
    };

    // ─── Rewind: full path reconstruction ────────────────────────────────────

    eprintln!("[*] Running journal rewind for full path reconstruction...");
    let mut engine = if let Some(ref mft) = mft_data {
        eprintln!("[*] Seeding rewind engine with {} MFT entries", mft.entries.len());
        mft.seed_rewind()
    } else {
        eprintln!("[*] No MFT provided - paths will be reconstructed from journal only");
        RewindEngine::new()
    };

    let resolved = engine.rewind(&records);
    eprintln!("[+] {} records resolved with full paths", resolved.len());

    // Count unknown paths
    let unknown_count = resolved.iter().filter(|r| r.parent_path.contains("UNKNOWN")).count();
    if unknown_count > 0 {
        eprintln!(
            "[!] {} records with unresolvable parent paths ({:.1}%)",
            unknown_count,
            (unknown_count as f64 / resolved.len() as f64) * 100.0
        );
    } else {
        eprintln!("[+] All paths fully resolved (0 UNKNOWN)");
    }

    // ─── TriForce Correlation ───────────────────────────────────────────────

    if !logfile_usn_records.is_empty() || mft_data.is_some() {
        eprintln!("[*] Running TriForce correlation (MFT + LogFile + UsnJrnl)...");
        let correlation = usnjrnl::correlation::CorrelationEngine::new();
        let mft_entries_slice = mft_data.as_ref().map(|m| m.entries.as_slice()).unwrap_or(&[]);
        let report = correlation.generate_report(&records, &logfile_usn_records, mft_entries_slice);

        eprintln!("[+] TriForce Report:");
        eprintln!("    Unified timeline events: {}", report.timeline_event_count);
        eprintln!("    Ghost records (LogFile-only): {}", report.ghost_record_count);
        eprintln!("    MFT entry reuses detected: {}", report.entry_reuse_count);
        eprintln!("    Timestamp conflicts: {}", report.timestamp_conflict_count);

        if report.journal_clearing_suspected {
            eprintln!("[!] JOURNAL CLEARING SUSPECTED - ghost records found in $LogFile");
        }

        if report.ghost_record_count > 0 {
            let ghosts = correlation.find_ghost_records(&records, &logfile_usn_records);
            eprintln!("[!] Ghost records (evidence of cleared journal entries):");
            for ghost in ghosts.iter().take(20) {
                eprintln!(
                    "    LSN={} USN={} {} [{}] {}",
                    ghost.lsn,
                    ghost.record.usn,
                    ghost.record.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ghost.record.reason,
                    ghost.record.filename,
                );
            }
            if ghosts.len() > 20 {
                eprintln!("    ... and {} more ghost records", ghosts.len() - 20);
            }
        }
    }

    // ─── Output ──────────────────────────────────────────────────────────────

    let has_output = cli.csv.is_some() || cli.jsonl.is_some() || cli.sqlite.is_some();

    if let Some(ref csv_path) = cli.csv {
        eprintln!("[*] Writing CSV to {}", csv_path.display());
        let file = std::fs::File::create(csv_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl::output::csv_output::export_csv(&resolved, &mut writer)?;
        eprintln!("[+] CSV export complete");
    }

    if let Some(ref jsonl_path) = cli.jsonl {
        eprintln!("[*] Writing JSON Lines to {}", jsonl_path.display());
        let file = std::fs::File::create(jsonl_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl::output::json_output::export_jsonl(&resolved, &mut writer)?;
        eprintln!("[+] JSON Lines export complete");
    }

    if let Some(ref sqlite_path) = cli.sqlite {
        eprintln!("[*] Writing SQLite to {}", sqlite_path.display());
        let mft_entries = mft_data.as_ref().map(|m| m.entries.as_slice());
        usnjrnl::output::sqlite_output::export_sqlite(sqlite_path, &resolved, mft_entries)?;
        eprintln!("[+] SQLite export complete");
    }

    if !has_output {
        eprintln!("\n[*] No output format specified. Use --csv, --jsonl, or --sqlite.");
        eprintln!("[*] Example: usnjrnl -j $J -m $MFT --csv output.csv");
    }

    Ok(())
}

fn print_reason_stats(records: &[usn::UsnRecord]) {
    use std::collections::HashMap;

    let mut reason_counts: HashMap<&str, usize> = HashMap::new();
    let mut v2_count = 0usize;
    let mut v3_count = 0usize;

    for r in records {
        match r.major_version {
            2 => v2_count += 1,
            3 => v3_count += 1,
            _ => {}
        }

        if r.reason.contains(usn::UsnReason::FILE_CREATE) {
            *reason_counts.entry("FILE_CREATE").or_default() += 1;
        }
        if r.reason.contains(usn::UsnReason::FILE_DELETE) {
            *reason_counts.entry("FILE_DELETE").or_default() += 1;
        }
        if r.reason.contains(usn::UsnReason::RENAME_OLD_NAME) {
            *reason_counts.entry("RENAME").or_default() += 1;
        }
        if r.reason.contains(usn::UsnReason::DATA_OVERWRITE) {
            *reason_counts.entry("DATA_OVERWRITE").or_default() += 1;
        }
        if r.reason.contains(usn::UsnReason::DATA_EXTEND) {
            *reason_counts.entry("DATA_EXTEND").or_default() += 1;
        }
        if r.reason.contains(usn::UsnReason::SECURITY_CHANGE) {
            *reason_counts.entry("SECURITY_CHANGE").or_default() += 1;
        }
        if r.reason.contains(usn::UsnReason::BASIC_INFO_CHANGE) {
            *reason_counts.entry("BASIC_INFO_CHANGE").or_default() += 1;
        }
    }

    eprintln!("[*] Record versions: V2={}, V3={}", v2_count, v3_count);
    eprintln!("[*] Reason breakdown:");
    let mut sorted: Vec<_> = reason_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (reason, count) in sorted {
        eprintln!("    {}: {}", reason, count);
    }
}
