#[cfg(feature = "image")]
use std::collections::HashSet;
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

use usnjrnl_forensic::mft::MftData;
use usnjrnl_forensic::rewind::RewindEngine;
use usnjrnl_forensic::usn;

#[derive(Parser)]
#[command(
    name = "usnjrnl-forensic",
    about = "NTFS USN Journal parser with full path reconstruction via journal rewind",
    long_about = "Parses $UsnJrnl:$J with optional $MFT correlation to reconstruct full file paths.\n\
                  Implements the CyberCX 'Rewind' algorithm for complete path resolution even when\n\
                  MFT entries have been reallocated. Supports V2/V3/V4 records, timestomping\n\
                  detection, $MFTMirr integrity checks, and $LogFile gap analysis.\n\n\
                  Can directly open E01/raw disk images with --image (requires 'image' feature).",
    version
)]
struct Cli {
    /// Path to raw $UsnJrnl:$J file (not needed when using --image)
    #[arg(short = 'j', long, required_unless_present = "image")]
    journal: Option<PathBuf>,

    /// Path to raw $MFT file (enables full path resolution and rewind)
    #[arg(short = 'm', long)]
    mft: Option<PathBuf>,

    /// Path to $MFTMirr file (enables integrity check)
    #[arg(long)]
    mftmirr: Option<PathBuf>,

    /// Path to $LogFile (enables gap detection)
    #[arg(long)]
    logfile: Option<PathBuf>,

    /// Path to E01 or raw disk image (extracts all NTFS artifacts automatically)
    #[arg(short = 'i', long, conflicts_with_all = ["journal", "mft", "mftmirr", "logfile"])]
    image: Option<PathBuf>,

    /// Directory to save extracted artifacts when using --image (default: temp dir)
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Output CSV file
    #[arg(long)]
    csv: Option<PathBuf>,

    /// Output JSON Lines file
    #[arg(long)]
    jsonl: Option<PathBuf>,

    /// Output SQLite database
    #[arg(long)]
    sqlite: Option<PathBuf>,

    /// Output Sleuthkit body file (pipe-delimited, for mactime/log2timeline)
    #[arg(long)]
    body: Option<PathBuf>,

    /// Output TLN (5-field pipe-delimited timeline) file
    #[arg(long)]
    tln: Option<PathBuf>,

    /// Output XML file
    #[arg(long)]
    xml: Option<PathBuf>,

    /// Detect timestomping (requires --mft or --image)
    #[arg(long)]
    detect_timestomping: bool,

    /// Carve USN records and MFT entries from unallocated space (requires --image)
    #[arg(long)]
    carve_unallocated: bool,

    /// Show statistics summary
    #[arg(long, default_value_t = true)]
    stats: bool,
}

/// Resolved artifact paths — either from CLI flags or extracted from a disk image.
struct ArtifactPaths {
    journal: PathBuf,
    mft: Option<PathBuf>,
    mftmirr: Option<PathBuf>,
    logfile: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // ─── Validate CLI constraints ────────────────────────────────────────────

    if cli.output_dir.is_some() && cli.image.is_none() {
        bail!("--output-dir can only be used with --image");
    }

    if cli.carve_unallocated && cli.image.is_none() {
        bail!("--carve-unallocated can only be used with --image");
    }

    // ─── Resolve artifact paths ─────────────────────────────────────────────

    let (_temp_dir, artifacts) = resolve_artifacts(&cli)?;

    // ─── Parse USN Journal ───────────────────────────────────────────────────

    eprintln!(
        "[*] Reading $UsnJrnl:$J from {}",
        artifacts.journal.display()
    );
    let usn_data = std::fs::read(&artifacts.journal)
        .with_context(|| format!("Failed to read journal: {}", artifacts.journal.display()))?;
    eprintln!(
        "[*] Journal size: {} bytes ({:.1} MB)",
        usn_data.len(),
        usn_data.len() as f64 / 1_048_576.0
    );

    eprintln!("[*] Parsing USN records...");
    let records = usn::parse_usn_journal(&usn_data).context("Failed to parse USN journal")?;
    eprintln!("[+] {} USN records parsed", records.len());

    // Print reason breakdown
    if cli.stats {
        print_reason_stats(&records);
    }

    // ─── Parse MFT (optional) ────────────────────────────────────────────────

    let mft_data = if let Some(ref mft_path) = artifacts.mft {
        eprintln!("[*] Reading $MFT from {}", mft_path.display());
        let raw = std::fs::read(mft_path)
            .with_context(|| format!("Failed to read MFT: {}", mft_path.display()))?;
        eprintln!(
            "[*] MFT size: {} bytes ({:.1} MB)",
            raw.len(),
            raw.len() as f64 / 1_048_576.0
        );

        eprintln!("[*] Parsing $MFT...");
        let mft = MftData::parse(&raw).context("Failed to parse $MFT")?;
        eprintln!("[+] {} MFT entries parsed", mft.entries.len());

        // Timestomping detection
        if cli.detect_timestomping {
            let suspicious = mft.detect_timestomping();
            if suspicious.is_empty() {
                eprintln!("[+] No timestomping indicators detected");
            } else {
                eprintln!(
                    "[!] {} potential timestomping indicators:",
                    suspicious.len()
                );
                for entry in suspicious.iter().take(20) {
                    eprintln!(
                        "    Entry {} ({}): SI_Created={:?} < FN_Created={:?}",
                        entry.entry_number, entry.full_path, entry.si_created, entry.fn_created
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

    if let (Some(ref mft_path), Some(ref mirr_path)) = (&artifacts.mft, &artifacts.mftmirr) {
        eprintln!("[*] Checking $MFTMirr integrity...");
        let mft_raw = std::fs::read(mft_path)?;
        let mirr_raw = std::fs::read(mirr_path)
            .with_context(|| format!("Failed to read $MFTMirr: {}", mirr_path.display()))?;
        let comparison = usnjrnl_forensic::mftmirr::compare_mft_mirror(&mft_raw, &mirr_raw)?;
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

    let logfile_usn_records = if let Some(ref logfile_path) = artifacts.logfile {
        eprintln!("[*] Analyzing $LogFile...");
        let log_raw = std::fs::read(logfile_path)
            .with_context(|| format!("Failed to read $LogFile: {}", logfile_path.display()))?;
        let summary = usnjrnl_forensic::logfile::parse_logfile(&log_raw)?;
        eprintln!(
            "[+] $LogFile: {} restart areas, {} record pages, highest LSN={}",
            summary.restart_areas.len(),
            summary.record_page_count,
            summary.highest_lsn
        );
        if summary.has_gaps {
            eprintln!("[!] GAPS DETECTED in $LogFile - possible journal clearing");
        }
        if usnjrnl_forensic::logfile::detect_journal_clearing(&summary) {
            eprintln!("[!] Evidence of journal clearing detected");
        }

        // Extract embedded USN records from $LogFile RCRD pages
        eprintln!("[*] Extracting USN records embedded in $LogFile...");
        let extracted =
            usnjrnl_forensic::logfile::usn_extractor::extract_usn_from_logfile(&log_raw);
        eprintln!(
            "[+] {} USN records recovered from $LogFile",
            extracted.len()
        );
        extracted
    } else {
        Vec::new()
    };

    // ─── Unallocated space carving (optional) ─────────────────────────────────

    let mut records = records;
    let carved_mft_entries = if cli.carve_unallocated {
        if let Some(ref image_path) = cli.image {
            let carve_results = perform_carving(image_path, &records, mft_data.as_ref())?;

            eprintln!(
                "[+] Carved {} USN records from unallocated space",
                carve_results.usn_records.len()
            );
            eprintln!(
                "[+] Carved {} MFT entries from unallocated space",
                carve_results.mft_entries.len()
            );
            eprintln!(
                "[*] Carving stats: {:.1} MB scanned, {} chunks, {} USN dupes removed, {} MFT dupes removed",
                carve_results.stats.bytes_scanned as f64 / 1_048_576.0,
                carve_results.stats.chunks_processed,
                carve_results.stats.usn_duplicates_removed,
                carve_results.stats.mft_duplicates_removed,
            );

            // Merge carved USN records into the record list
            let carved_usn_count = carve_results.usn_records.len();
            records.extend(carve_results.usn_records.into_iter().map(|c| c.record));
            records.sort_by_key(|r| r.usn);

            if carved_usn_count > 0 {
                eprintln!(
                    "[+] Merged {} carved USN records into timeline ({} total)",
                    carved_usn_count,
                    records.len()
                );
            }

            carve_results.mft_entries
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // ─── Rewind: full path reconstruction ────────────────────────────────────

    eprintln!("[*] Running journal rewind for full path reconstruction...");
    let mut engine = if let Some(ref mft) = mft_data {
        eprintln!(
            "[*] Seeding rewind engine with {} MFT entries",
            mft.entries.len()
        );
        mft.seed_rewind()
    } else {
        eprintln!("[*] No MFT provided - paths will be reconstructed from journal only");
        RewindEngine::new()
    };

    // Seed rewind with carved MFT entries (won't overwrite allocated data)
    if !carved_mft_entries.is_empty() {
        eprintln!(
            "[*] Seeding rewind engine with {} carved MFT entries",
            carved_mft_entries.len()
        );
        engine.seed_from_carved(&carved_mft_entries);
    }

    let resolved = engine.rewind(&records);
    eprintln!("[+] {} records resolved with full paths", resolved.len());

    // Count unknown paths
    let unknown_count = resolved
        .iter()
        .filter(|r| r.parent_path.contains("UNKNOWN"))
        .count();
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
        let correlation = usnjrnl_forensic::correlation::CorrelationEngine::new();
        let mft_entries_slice = mft_data
            .as_ref()
            .map(|m| m.entries.as_slice())
            .unwrap_or(&[]);
        let report = correlation.generate_report(&records, &logfile_usn_records, mft_entries_slice);

        eprintln!("[+] TriForce Report:");
        eprintln!(
            "    Unified timeline events: {}",
            report.timeline_event_count
        );
        eprintln!(
            "    Ghost records (LogFile-only): {}",
            report.ghost_record_count
        );
        eprintln!(
            "    MFT entry reuses detected: {}",
            report.entry_reuse_count
        );
        eprintln!(
            "    Timestamp conflicts: {}",
            report.timestamp_conflict_count
        );

        if report.ghost_record_count > 0 {
            let ghosts = correlation.find_ghost_records(&records, &logfile_usn_records);

            eprintln!(
                "[+] {} ghost records found in $LogFile (not present in $UsnJrnl)",
                ghosts.len()
            );
            eprintln!("    Ghost records appear when $LogFile retains USN records that $UsnJrnl");
            eprintln!("    has cycled past (normal wrapping) or that were deliberately cleared.");
            if report.journal_clearing_suspected {
                eprintln!(
                    "[!] NOTE: $LogFile contains records OLDER than the oldest $UsnJrnl entry."
                );
                eprintln!(
                    "    This is consistent with journal wrapping or intentional journal clearing."
                );
                eprintln!("    Review ghost record timestamps and context to determine which.");
            }

            for ghost in ghosts.iter().take(20) {
                eprintln!(
                    "    LSN={} USN={} {} [{}] {}",
                    ghost.lsn,
                    ghost.record.usn,
                    ghost
                        .record
                        .timestamp
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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

    let has_output = cli.csv.is_some()
        || cli.jsonl.is_some()
        || cli.sqlite.is_some()
        || cli.body.is_some()
        || cli.tln.is_some()
        || cli.xml.is_some();

    if let Some(ref csv_path) = cli.csv {
        eprintln!("[*] Writing CSV to {}", csv_path.display());
        let file = std::fs::File::create(csv_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl_forensic::output::csv_output::export_csv(&resolved, &mut writer)?;
        eprintln!("[+] CSV export complete");
    }

    if let Some(ref jsonl_path) = cli.jsonl {
        eprintln!("[*] Writing JSON Lines to {}", jsonl_path.display());
        let file = std::fs::File::create(jsonl_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl_forensic::output::json_output::export_jsonl(&resolved, &mut writer)?;
        eprintln!("[+] JSON Lines export complete");
    }

    if let Some(ref sqlite_path) = cli.sqlite {
        eprintln!("[*] Writing SQLite to {}", sqlite_path.display());
        let mft_entries = mft_data.as_ref().map(|m| m.entries.as_slice());
        usnjrnl_forensic::output::sqlite_output::export_sqlite(
            sqlite_path,
            &resolved,
            mft_entries,
        )?;
        eprintln!("[+] SQLite export complete");
    }

    if let Some(ref body_path) = cli.body {
        eprintln!("[*] Writing Sleuthkit body file to {}", body_path.display());
        let file = std::fs::File::create(body_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl_forensic::output::body_output::export_body(&resolved, &mut writer)?;
        eprintln!("[+] Body file export complete");
    }

    if let Some(ref tln_path) = cli.tln {
        eprintln!("[*] Writing TLN to {}", tln_path.display());
        let file = std::fs::File::create(tln_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl_forensic::output::tln_output::export_tln(&resolved, &mut writer)?;
        eprintln!("[+] TLN export complete");
    }

    if let Some(ref xml_path) = cli.xml {
        eprintln!("[*] Writing XML to {}", xml_path.display());
        let file = std::fs::File::create(xml_path)?;
        let mut writer = BufWriter::new(file);
        usnjrnl_forensic::output::xml_output::export_xml(&resolved, &mut writer)?;
        eprintln!("[+] XML export complete");
    }

    if !has_output {
        eprintln!("\n[*] No output format specified. Use --csv, --jsonl, --sqlite, --body, --tln, or --xml.");
        eprintln!("[*] Example: usnjrnl-forensic -j $J -m $MFT --csv output.csv");
        eprintln!("[*] Example: usnjrnl-forensic --image evidence.E01 --csv output.csv");
    }

    Ok(())
}

/// Resolve artifact paths: either from direct CLI flags or by extracting from a disk image.
///
/// Returns an optional `TempDir` handle (kept alive to prevent cleanup when using a temp dir)
/// and the resolved paths.
fn resolve_artifacts(cli: &Cli) -> Result<(Option<tempfile::TempDir>, ArtifactPaths)> {
    if let Some(ref image_path) = cli.image {
        resolve_from_image(image_path, cli.output_dir.as_deref())
    } else {
        // Direct artifact mode — journal is guaranteed present by clap's required_unless_present
        Ok((
            None,
            ArtifactPaths {
                journal: cli.journal.clone().unwrap(),
                mft: cli.mft.clone(),
                mftmirr: cli.mftmirr.clone(),
                logfile: cli.logfile.clone(),
            },
        ))
    }
}

/// Extract NTFS artifacts from a disk image and return their paths.
#[cfg(feature = "image")]
fn resolve_from_image(
    image_path: &std::path::Path,
    output_dir: Option<&std::path::Path>,
) -> Result<(Option<tempfile::TempDir>, ArtifactPaths)> {
    eprintln!("[*] Opening disk image: {}", image_path.display());

    let format = usnjrnl_forensic::image::ImageFormat::detect(image_path)
        .with_context(|| format!("Failed to read image: {}", image_path.display()))?;
    eprintln!("[*] Detected format: {:?}", format);

    // Determine output directory: user-specified or temp
    let (temp_dir, extract_dir) = if let Some(dir) = output_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create output dir: {}", dir.display()))?;
        eprintln!("[*] Extracting artifacts to {}", dir.display());
        (None, dir.to_path_buf())
    } else {
        let td = tempfile::TempDir::new().context("Failed to create temp directory")?;
        eprintln!("[*] Extracting artifacts to {}", td.path().display());
        let path = td.path().to_path_buf();
        (Some(td), path)
    };

    let extracted = usnjrnl_forensic::image::extract_artifacts(image_path, &extract_dir)
        .context("Failed to extract NTFS artifacts from disk image")?;

    eprintln!("[+] Extracted $MFT:      {}", extracted.mft.display());
    eprintln!("[+] Extracted $MFTMirr:  {}", extracted.mftmirr.display());
    eprintln!("[+] Extracted $LogFile:  {}", extracted.logfile.display());
    eprintln!("[+] Extracted $UsnJrnl:  {}", extracted.usnjrnl.display());

    Ok((
        temp_dir,
        ArtifactPaths {
            journal: extracted.usnjrnl,
            mft: Some(extracted.mft),
            mftmirr: Some(extracted.mftmirr),
            logfile: Some(extracted.logfile),
        },
    ))
}

/// Stub when the `image` feature is not enabled — gives a clear compile-time-safe error.
#[cfg(not(feature = "image"))]
fn resolve_from_image(
    _image_path: &std::path::Path,
    _output_dir: Option<&std::path::Path>,
) -> Result<(Option<tempfile::TempDir>, ArtifactPaths)> {
    bail!(
        "Disk image support requires the 'image' feature.\n\
         Rebuild with: cargo build --release --features image"
    );
}

/// Scan unallocated space in a disk image for carved USN records and MFT entries.
///
/// Re-opens the image, finds the NTFS partition, builds deduplication sets from
/// the already-parsed allocated records, and runs the carving scanner.
#[cfg(feature = "image")]
fn perform_carving(
    image_path: &std::path::Path,
    allocated_records: &[usn::UsnRecord],
    mft_data: Option<&MftData>,
) -> Result<usnjrnl_forensic::image::unallocated::UnallocatedScanResults> {
    eprintln!("[*] Scanning unallocated space for carved records...");

    // Build deduplication sets from allocated artifacts
    let known_usn: HashSet<i64> = allocated_records.iter().map(|r| r.usn).collect();
    let known_mft: HashSet<(u64, u16)> = mft_data
        .map(|m| {
            m.entries
                .iter()
                .map(|e| (e.entry_number, e.sequence_number))
                .collect()
        })
        .unwrap_or_default();

    eprintln!(
        "[*] Dedup sets: {} known USN offsets, {} known MFT entries",
        known_usn.len(),
        known_mft.len()
    );

    // Re-open the image and find the NTFS partition
    let mut reader = ewf::EwfReader::open(image_path)
        .map_err(|e| anyhow::anyhow!("Failed to re-open image for carving: {e}"))?;
    let partition = usnjrnl_forensic::image::find_ntfs_partition(&mut reader)?;

    eprintln!(
        "[*] Scanning partition: offset={}, size={:.1} MB",
        partition.offset,
        partition.size as f64 / 1_048_576.0
    );

    usnjrnl_forensic::image::unallocated::scan_for_unallocated(
        &mut reader,
        partition.offset,
        partition.size,
        &known_usn,
        &known_mft,
        0, // default chunk size
    )
    .context("Failed to scan unallocated space")
}

/// Stub when the `image` feature is not enabled.
#[cfg(not(feature = "image"))]
fn perform_carving(
    _image_path: &std::path::Path,
    _allocated_records: &[usn::UsnRecord],
    _mft_data: Option<&MftData>,
) -> Result<usnjrnl_forensic::image::unallocated::UnallocatedScanResults> {
    bail!(
        "Unallocated carving requires the 'image' feature.\n\
         Rebuild with: cargo build --release --features image"
    );
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

    eprintln!("[*] Record versions: V2={v2_count}, V3={v3_count}");
    eprintln!("[*] Reason breakdown:");
    let mut sorted: Vec<_> = reason_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (reason, count) in sorted {
        eprintln!("    {reason}: {count}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_accepts_body_flag() {
        let cli = Cli::try_parse_from(["usnjrnl", "-j", "test.bin", "--body", "out.body"]).unwrap();
        assert_eq!(cli.body, Some(PathBuf::from("out.body")));
    }

    #[test]
    fn test_cli_accepts_tln_flag() {
        let cli = Cli::try_parse_from(["usnjrnl", "-j", "test.bin", "--tln", "out.tln"]).unwrap();
        assert_eq!(cli.tln, Some(PathBuf::from("out.tln")));
    }

    #[test]
    fn test_cli_accepts_xml_flag() {
        let cli = Cli::try_parse_from(["usnjrnl", "-j", "test.bin", "--xml", "out.xml"]).unwrap();
        assert_eq!(cli.xml, Some(PathBuf::from("out.xml")));
    }

    #[test]
    fn test_cli_all_output_formats_simultaneously() {
        let cli = Cli::try_parse_from([
            "usnjrnl", "-j", "test.bin", "--csv", "a.csv", "--jsonl", "a.jsonl", "--sqlite",
            "a.db", "--body", "a.body", "--tln", "a.tln", "--xml", "a.xml",
        ])
        .unwrap();
        assert!(cli.csv.is_some());
        assert!(cli.jsonl.is_some());
        assert!(cli.sqlite.is_some());
        assert!(cli.body.is_some());
        assert!(cli.tln.is_some());
        assert!(cli.xml.is_some());
    }

    #[test]
    fn test_cli_no_output_formats_is_valid() {
        let cli = Cli::try_parse_from(["usnjrnl", "-j", "test.bin"]).unwrap();
        assert!(cli.body.is_none());
        assert!(cli.tln.is_none());
        assert!(cli.xml.is_none());
    }

    // ─── --image CLI tests ──────────────────────────────────────────────────

    #[test]
    fn test_cli_accepts_image_flag() {
        let cli = Cli::try_parse_from(["usnjrnl", "--image", "evidence.E01", "--csv", "out.csv"])
            .unwrap();
        assert_eq!(cli.image, Some(PathBuf::from("evidence.E01")));
        assert!(cli.journal.is_none());
    }

    #[test]
    fn test_cli_image_short_flag() {
        let cli =
            Cli::try_parse_from(["usnjrnl", "-i", "evidence.E01", "--csv", "out.csv"]).unwrap();
        assert_eq!(cli.image, Some(PathBuf::from("evidence.E01")));
    }

    #[test]
    fn test_cli_image_with_output_dir() {
        let cli = Cli::try_parse_from([
            "usnjrnl",
            "--image",
            "evidence.E01",
            "--output-dir",
            "/tmp/artifacts",
            "--csv",
            "out.csv",
        ])
        .unwrap();
        assert_eq!(cli.image, Some(PathBuf::from("evidence.E01")));
        assert_eq!(cli.output_dir, Some(PathBuf::from("/tmp/artifacts")));
    }

    #[test]
    fn test_cli_image_conflicts_with_journal() {
        let result =
            Cli::try_parse_from(["usnjrnl", "--image", "evidence.E01", "-j", "journal.bin"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_image_conflicts_with_mft() {
        let result = Cli::try_parse_from(["usnjrnl", "--image", "evidence.E01", "-m", "mft.bin"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_output_dir_parses_with_journal() {
        // --output-dir parses successfully with --journal (runtime validation rejects it)
        let cli = Cli::try_parse_from([
            "usnjrnl",
            "-j",
            "test.bin",
            "--output-dir",
            "/tmp/artifacts",
        ])
        .unwrap();
        // Validation would reject at runtime: --output-dir requires --image
        assert!(cli.output_dir.is_some());
        assert!(cli.image.is_none());
    }

    #[test]
    fn test_cli_requires_journal_or_image() {
        let result = Cli::try_parse_from(["usnjrnl", "--csv", "out.csv"]);
        assert!(result.is_err());
    }

    // ─── --carve-unallocated CLI tests ──────────────────────────────────────

    #[test]
    fn test_cli_accepts_carve_unallocated_with_image() {
        let cli = Cli::try_parse_from([
            "usnjrnl",
            "--image",
            "evidence.E01",
            "--carve-unallocated",
            "--csv",
            "out.csv",
        ])
        .unwrap();
        assert!(cli.carve_unallocated);
        assert!(cli.image.is_some());
    }

    #[test]
    fn test_cli_carve_unallocated_defaults_false() {
        let cli = Cli::try_parse_from(["usnjrnl", "-j", "test.bin", "--csv", "out.csv"]).unwrap();
        assert!(!cli.carve_unallocated);
    }
}
