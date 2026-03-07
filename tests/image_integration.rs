//! Integration tests for E01 disk image extraction.
//!
//! These tests require the `image` feature and real forensic test images.
//! They are gated with `#[ignore]` and only run when explicitly requested:
//!
//!   cargo test --features image --test image_integration -- --ignored

#![cfg(feature = "image")]

use std::collections::HashSet;
use std::path::Path;
use usnjrnl_forensic::analysis::{
    detect_journal_clearing, detect_ransomware_patterns, detect_secure_deletion,
    detect_timestomping,
};
use usnjrnl_forensic::image::extract_artifacts;
use usnjrnl_forensic::image::unallocated::scan_for_unallocated;
use usnjrnl_forensic::output::report::{build_report_data, export_report, ReportInput};
use usnjrnl_forensic::rewind::RecordSource;
use usnjrnl_forensic::triage::{queries::builtin_questions, run_triage};

/// Test E01 extraction against the Szechuan Sauce CTF desktop image.
/// Image: 20200918_0417_DESKTOP-SDN1RPT.E01 (from DESKTOP-E01.zip)
#[test]
#[ignore]
fn extract_artifacts_from_szechuan_sauce_e01() {
    let image_path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !image_path.exists() {
        panic!(
            "Test image not found at {}. Download DESKTOP-E01.zip from dfirmadness.com.",
            image_path.display()
        );
    }

    let output_dir = tempfile::tempdir().unwrap();
    let result = extract_artifacts(image_path, output_dir.path());

    match &result {
        Ok(artifacts) => {
            // $MFT must exist and be non-empty
            assert!(artifacts.mft.exists(), "$MFT not extracted");
            assert!(
                std::fs::metadata(&artifacts.mft).unwrap().len() > 0,
                "$MFT is empty"
            );

            // $MFTMirr must exist and be non-empty
            assert!(artifacts.mftmirr.exists(), "$MFTMirr not extracted");
            assert!(
                std::fs::metadata(&artifacts.mftmirr).unwrap().len() > 0,
                "$MFTMirr is empty"
            );

            // $LogFile must exist and be non-empty
            assert!(artifacts.logfile.exists(), "$LogFile not extracted");
            assert!(
                std::fs::metadata(&artifacts.logfile).unwrap().len() > 0,
                "$LogFile is empty"
            );

            // $UsnJrnl:$J must exist and be non-empty
            assert!(artifacts.usnjrnl.exists(), "$UsnJrnl:$J not extracted");
            assert!(
                std::fs::metadata(&artifacts.usnjrnl).unwrap().len() > 0,
                "$UsnJrnl:$J is empty"
            );

            // Print sizes for forensic validation
            eprintln!("Extracted artifacts:");
            eprintln!(
                "  $MFT:        {} bytes",
                std::fs::metadata(&artifacts.mft).unwrap().len()
            );
            eprintln!(
                "  $MFTMirr:    {} bytes",
                std::fs::metadata(&artifacts.mftmirr).unwrap().len()
            );
            eprintln!(
                "  $LogFile:    {} bytes",
                std::fs::metadata(&artifacts.logfile).unwrap().len()
            );
            eprintln!(
                "  $UsnJrnl:$J: {} bytes",
                std::fs::metadata(&artifacts.usnjrnl).unwrap().len()
            );
        }
        Err(e) => {
            panic!("extract_artifacts failed: {:#}", e);
        }
    }
}

/// End-to-end: extract from E01 then parse with usnjrnl-forensic's own parser.
#[test]
#[ignore]
fn extracted_artifacts_are_valid_for_parsing() {
    let image_path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !image_path.exists() {
        return; // Skip if test image not available
    }

    let output_dir = tempfile::tempdir().unwrap();
    let artifacts = extract_artifacts(image_path, output_dir.path())
        .expect("Failed to extract artifacts from E01");

    // Parse the extracted $UsnJrnl:$J
    let journal_data = std::fs::read(&artifacts.usnjrnl).unwrap();
    let records = usnjrnl_forensic::usn::parse_usn_journal(&journal_data)
        .expect("Failed to parse extracted $UsnJrnl:$J");
    assert!(
        !records.is_empty(),
        "No USN records parsed from extracted $UsnJrnl:$J"
    );
    eprintln!(
        "Parsed {} USN records from extracted $UsnJrnl:$J",
        records.len()
    );

    // Parse the extracted $MFT
    let mft_data = usnjrnl_forensic::mft::MftData::parse(&std::fs::read(&artifacts.mft).unwrap())
        .expect("Failed to parse extracted $MFT");
    eprintln!("Parsed MFT from extracted $MFT successfully");

    // Parse the extracted $LogFile
    let logfile_data = std::fs::read(&artifacts.logfile).unwrap();
    let logfile_summary = usnjrnl_forensic::logfile::parse_logfile(&logfile_data)
        .expect("Failed to parse extracted $LogFile");
    eprintln!(
        "Parsed LogFile: {} restart areas from extracted $LogFile",
        logfile_summary.restart_areas.len()
    );

    // Do full rewind path resolution
    let mut engine = mft_data.seed_rewind();
    let resolved_records = engine.rewind(&records);
    let with_path = resolved_records
        .iter()
        .filter(|r| !r.full_path.is_empty())
        .count();
    eprintln!(
        "Path resolution: {}/{} ({:.1}%)",
        with_path,
        resolved_records.len(),
        100.0 * with_path as f64 / resolved_records.len().max(1) as f64
    );
    assert!(
        with_path > 0,
        "Rewind algorithm resolved 0 paths from extracted artifacts"
    );
}

// ─── Unallocated carving E2E tests ──────────────────────────────────────────

/// Helper: run unallocated carving against an E01 image and return stats.
/// Extracts allocated artifacts first, builds dedup sets, then scans.
fn run_carving_e2e(image_path: &Path) {
    let output_dir = tempfile::tempdir().unwrap();
    let artifacts =
        extract_artifacts(image_path, output_dir.path()).expect("Failed to extract artifacts");

    // Parse allocated $UsnJrnl to build known USN offset set
    let journal_data = std::fs::read(&artifacts.usnjrnl).unwrap();
    let records =
        usnjrnl_forensic::usn::parse_usn_journal(&journal_data).expect("Failed to parse $UsnJrnl");
    let known_usn: HashSet<i64> = records.iter().map(|r| r.usn).collect();

    // Parse allocated $MFT to build known (entry, seq) set
    let mft_raw = std::fs::read(&artifacts.mft).unwrap();
    let mft_data = usnjrnl_forensic::mft::MftData::parse(&mft_raw).expect("Failed to parse $MFT");
    let known_mft: HashSet<(u64, u16)> = mft_data
        .entries
        .iter()
        .map(|e| (e.entry_number, e.sequence_number))
        .collect();

    // Find NTFS partition for scanning
    let mut reader = ewf::EwfReader::open(image_path).expect("Failed to open EWF image");
    let partition = usnjrnl_forensic::image::find_ntfs_partition(&mut reader)
        .expect("Failed to find NTFS partition");

    eprintln!(
        "Image: {} | Partition: offset={}, size={:.1} MB",
        image_path.display(),
        partition.offset,
        partition.size as f64 / 1_048_576.0
    );
    eprintln!(
        "  Allocated: {} USN records, {} MFT entries",
        known_usn.len(),
        known_mft.len()
    );

    // Scan for carved records
    let result = scan_for_unallocated(
        &mut reader,
        partition.offset,
        partition.size,
        &known_usn,
        &known_mft,
        0, // default chunk size
    )
    .expect("Unallocated scan failed");

    eprintln!(
        "  Carved: {} USN records, {} MFT entries",
        result.usn_records.len(),
        result.mft_entries.len()
    );
    eprintln!(
        "  Deduped: {} USN, {} MFT removed as already in allocated artifacts",
        result.stats.usn_duplicates_removed, result.stats.mft_duplicates_removed
    );
    eprintln!(
        "  Scanned: {:.1} MB in {} chunks",
        result.stats.bytes_scanned as f64 / 1_048_576.0,
        result.stats.chunks_processed
    );

    // Validate carved records have sane fields
    for rec in &result.usn_records {
        assert!(
            !rec.record.filename.is_empty(),
            "Carved USN record has empty filename"
        );
    }
    for entry in &result.mft_entries {
        assert!(
            !entry.filename.is_empty(),
            "Carved MFT entry has empty filename"
        );
        assert!(
            entry.sequence_number > 0,
            "Carved MFT entry has zero sequence"
        );
    }
}

#[test]
#[ignore]
fn carve_unallocated_szechuan_sauce() {
    let path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !path.exists() {
        return;
    }
    run_carving_e2e(path);
}

#[test]
#[ignore]
fn carve_unallocated_pc_mus() {
    let path = Path::new("tests/data/PC-MUS-001.E01");
    if !path.exists() {
        return;
    }
    run_carving_e2e(path);
}

#[test]
#[ignore]
fn carve_unallocated_max_powers() {
    let path = Path::new("tests/data/MaxPowersCDrive.E01");
    if !path.exists() {
        return;
    }
    run_carving_e2e(path);
}

// ─── Full report pipeline E2E ────────────────────────────────────────────────

/// End-to-end: extract → parse → rewind → carve → triage → report HTML.
///
/// Exercises the ENTIRE --report pipeline against the Szechuan Sauce CTF image
/// with carving enabled, verifying that:
/// - Triage questions produce real hits
/// - Carved records are tagged with source "carved"
/// - Ghost records (if any) are tagged with source "ghost"
/// - The HTML report is valid and contains expected data
#[test]
#[ignore]
fn e2e_full_report_pipeline_szechuan_sauce() {
    let image_path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !image_path.exists() {
        return;
    }

    // ── Extract ──────────────────────────────────────────────────────────
    let output_dir = tempfile::tempdir().unwrap();
    let artifacts = extract_artifacts(image_path, output_dir.path())
        .expect("Failed to extract artifacts from E01");

    // ── Parse ────────────────────────────────────────────────────────────
    let journal_data = std::fs::read(&artifacts.usnjrnl).unwrap();
    let mut records = usnjrnl_forensic::usn::parse_usn_journal(&journal_data)
        .expect("Failed to parse $UsnJrnl:$J");
    let mft_data = usnjrnl_forensic::mft::MftData::parse(&std::fs::read(&artifacts.mft).unwrap())
        .expect("Failed to parse $MFT");
    let logfile_data = std::fs::read(&artifacts.logfile).unwrap();

    eprintln!(
        "[e2e] Parsed: {} USN records, {} MFT entries",
        records.len(),
        mft_data.entries.len()
    );

    // ── Carve unallocated ────────────────────────────────────────────────
    let known_usn: HashSet<i64> = records.iter().map(|r| r.usn).collect();
    let known_mft: HashSet<(u64, u16)> = mft_data
        .entries
        .iter()
        .map(|e| (e.entry_number, e.sequence_number))
        .collect();

    let mut reader = ewf::EwfReader::open(image_path).expect("Failed to open EWF image");
    let partition = usnjrnl_forensic::image::find_ntfs_partition(&mut reader)
        .expect("Failed to find NTFS partition");

    let carve_results = scan_for_unallocated(
        &mut reader,
        partition.offset,
        partition.size,
        &known_usn,
        &known_mft,
        0,
    )
    .expect("Carving failed");

    let carved_usn_count = carve_results.usn_records.len();
    let carved_mft_count = carve_results.mft_entries.len();
    let carved_usn_offsets: HashSet<i64> = carve_results
        .usn_records
        .iter()
        .map(|c| c.record.usn)
        .collect();

    eprintln!(
        "[e2e] Carved: {} USN records, {} MFT entries",
        carved_usn_count, carved_mft_count
    );

    // Merge carved USN records
    records.extend(carve_results.usn_records.into_iter().map(|c| c.record));
    records.sort_by_key(|r| r.usn);

    // ── Rewind ───────────────────────────────────────────────────────────
    let mut engine = mft_data.seed_rewind();
    engine.seed_from_carved(&carve_results.mft_entries);
    let mut resolved = engine.rewind(&records);

    eprintln!("[e2e] Resolved: {} records with full paths", resolved.len());

    // Tag carved records
    let mut carved_tagged = 0usize;
    for r in resolved.iter_mut() {
        if carved_usn_offsets.contains(&r.record.usn) {
            r.source = RecordSource::Carved;
            carved_tagged += 1;
        }
    }
    eprintln!("[e2e] Tagged {} records as carved", carved_tagged);

    // ── Correlation (ghost records) ──────────────────────────────────────
    let correlation = usnjrnl_forensic::correlation::CorrelationEngine::new();
    let logfile_usn_records =
        usnjrnl_forensic::logfile::usn_extractor::extract_usn_from_logfile(&logfile_data);
    let ghost_records = correlation.find_ghost_records(&records, &logfile_usn_records);

    // Add ghost records to resolved list
    for ghost in &ghost_records {
        resolved.push(usnjrnl_forensic::rewind::ResolvedRecord {
            full_path: format!(".\\{}", ghost.record.filename),
            parent_path: ".".to_string(),
            record: ghost.record.clone(),
            source: RecordSource::Ghost,
        });
    }
    eprintln!("[e2e] Ghost records: {}", ghost_records.len());

    // ── Analysis detections ──────────────────────────────────────────────
    let timestomping = detect_timestomping(&records);
    let secure_deletion = detect_secure_deletion(&records);
    let ransomware = detect_ransomware_patterns(&records);
    let journal_clearing = detect_journal_clearing(&records);

    // ── Triage ───────────────────────────────────────────────────────────
    let questions = builtin_questions();
    let triage_results = run_triage(&questions, &resolved);

    eprintln!("[e2e] Triage results:");
    for tr in &triage_results {
        eprintln!("  {:30} {:>5} hits  [{}]", tr.id, tr.hit_count, tr.category);
    }

    // Szechuan Sauce is a compromised system — we expect SOME triage hits
    let total_hits: usize = triage_results.iter().map(|r| r.hit_count).sum();
    assert!(
        total_hits > 0,
        "Szechuan Sauce CTF should produce triage hits"
    );

    // At minimum, execution_evidence (prefetch) should have hits
    let exec = triage_results
        .iter()
        .find(|r| r.id == "execution_evidence")
        .unwrap();
    assert!(
        exec.has_hits,
        "Szechuan Sauce should have prefetch-based execution evidence"
    );

    // If we carved anything, recovered_evidence should have hits
    if carved_tagged > 0 || !ghost_records.is_empty() {
        let recovered = triage_results
            .iter()
            .find(|r| r.id == "recovered_evidence")
            .unwrap();
        assert!(
            recovered.has_hits,
            "recovered_evidence should match carved/ghost records"
        );
        eprintln!(
            "[e2e] recovered_evidence: {} hits (carved={}, ghosts={})",
            recovered.hit_count,
            carved_tagged,
            ghost_records.len()
        );
    }

    // ── Build report ─────────────────────────────────────────────────────
    let input = ReportInput {
        image_name: "20200918_0417_DESKTOP-SDN1RPT.E01",
        resolved: &resolved,
        mft_data: Some(&mft_data),
        timestomping: &timestomping,
        secure_deletion: &secure_deletion,
        ransomware: &ransomware,
        journal_clearing: &journal_clearing,
        ghost_records: &ghost_records,
        carved_usn_count,
        carved_mft_count,
        carving_bytes_scanned: carve_results.stats.bytes_scanned,
        carving_chunks: carve_results.stats.chunks_processed,
        carving_usn_dupes: carve_results.stats.usn_duplicates_removed as u64,
        carving_mft_dupes: carve_results.stats.mft_duplicates_removed as u64,
    };
    let data = build_report_data(&input, &questions);

    // Verify report data integrity
    assert_eq!(data.meta.record_count, resolved.len());
    assert_eq!(data.records.len(), resolved.len());
    assert_eq!(data.triage.len(), 12, "all 12 triage questions in report");
    assert_eq!(data.ghost_records.len(), ghost_records.len());

    // Verify source diversity: should have at least allocated records
    let allocated_count = data
        .records
        .iter()
        .filter(|r| r.source == "allocated")
        .count();
    assert!(allocated_count > 0, "should have allocated records");

    if carved_tagged > 0 {
        let carved_count = data.records.iter().filter(|r| r.source == "carved").count();
        assert!(carved_count > 0, "should have carved records in report");
        eprintln!(
            "[e2e] Report source breakdown: {} allocated, {} carved, {} ghost",
            allocated_count,
            carved_count,
            data.records.iter().filter(|r| r.source == "ghost").count()
        );
    }

    // ── Export HTML ──────────────────────────────────────────────────────
    let mut buf = Vec::new();
    export_report(&data, &mut buf).unwrap();
    let html = String::from_utf8(buf).unwrap();

    assert!(html.contains("<!DOCTYPE html>"), "valid HTML document");
    assert!(html.contains("DESKTOP-SDN1RPT"), "image name in report");
    assert!(html.contains("Story"), "Story tab present");
    assert!(html.contains("Explore"), "Explore tab present");
    assert!(html.contains("What Happened"), "triage category present");
    assert!(
        html.contains("execution_evidence"),
        "triage question in data"
    );

    // Write report to temp file for manual inspection
    let report_path = output_dir.path().join("triage_report.html");
    std::fs::write(&report_path, &html).unwrap();
    eprintln!(
        "[e2e] Report written to {} ({:.1} KB)",
        report_path.display(),
        html.len() as f64 / 1024.0
    );

    eprintln!("[e2e] PASS: Full report pipeline verified");
}
