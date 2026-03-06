# Rapid Triage Report — Design Document

## Summary

Add a `--report triage.html` flag to `usnjrnl-forensic` that generates a self-contained HTML triage report. The report has two tabs: a **Story** tab that answers forensic investigation questions with one-click evidence, and an **Explore** tab that provides a full timeline workbench. Designed for live demos to non-technical audiences (startup incubators) using the Szechuan Sauce CTF as the showcase case.

## Goals

- One command, one file, complete incident triage
- Non-technical audience understands value in 30 seconds (stat cards + sparkline)
- CTF questions answered automatically by generic forensic queries
- Self-contained HTML — no server, no runtime, opens in any browser
- Showcase all headline features: Rewind paths, QuadLink ghost records, carving, anti-forensics detection

## Non-Goals

- Not a replacement for analyst-grade tools (Autopsy, X-Ways)
- Not a hosted web app (no server infrastructure)
- No real-time streaming (batch report generation only)
- `--serve` mode (local web server for richer interaction) is a future enhancement, out of scope for v1

## CLI Interface

```bash
# Generate triage report from E01 image
usnjrnl-forensic --image evidence.E01 --carve-unallocated --report triage.html

# Generate alongside other outputs
usnjrnl-forensic --image evidence.E01 --carve-unallocated --report triage.html --csv timeline.csv --sqlite analysis.db

# From pre-extracted artifacts
usnjrnl-forensic -j $J -m $MFT --logfile $LogFile --mftmirr $MFTMirr --report triage.html
```

`--report` is a new output flag, parallel to `--csv`, `--jsonl`, etc. It runs after all analysis phases complete and consumes their outputs.

## Data Pipeline

```
main.rs pipeline outputs
    |
    +-- records: Vec<ResolvedRecord>      (resolved USN records with full paths)
    +-- mft_data: Option<MftData>         (MFT entries with SI/FN timestamps)
    +-- detections: Detections            (timestomping, sdelete, ransomware, clearing)
    +-- ghost_records: Vec<UsnRecord>     (from $LogFile correlation)
    +-- carving_stats: CarvingStats       (bytes scanned, records found, dupes removed)
    +-- quadlink_summary: QuadLinkReport  (correlation results)
    |
    v
report::generate_report()
    |
    +-- Build ReportData struct from all pipeline outputs
    +-- Run triage queries -> pre-answered question cards
    +-- Serialize ReportData to JSON
    +-- Inject into template.html at {{DATA}} placeholder
    +-- Write self-contained HTML file
```

## Data Shape (embedded JSON)

```json
{
  "meta": {
    "tool_version": "0.4.0",
    "image_name": "20200918_DESKTOP-SDN1RPT.E01",
    "generated_at": "2026-03-07T12:00:00Z",
    "record_count": 43463,
    "carved_usn_count": 1247,
    "carved_mft_count": 89,
    "ghost_record_count": 771,
    "alert_count": 3,
    "time_range": { "start": "2020-09-19T00:30:00Z", "end": "2020-09-19T03:00:00Z" }
  },
  "records": [
    {
      "timestamp": "2020-09-19T02:15:03.123Z",
      "usn": 22120200,
      "mft_entry": 88432,
      "mft_sequence": 1,
      "parent_entry": 342,
      "parent_sequence": 1,
      "full_path": ".\\Windows\\System32\\coreupdate.exe",
      "parent_path": ".\\Windows\\System32",
      "filename": "coreupdate.exe",
      "extension": "exe",
      "reasons": ["FILE_CREATE"],
      "file_attributes": ["ARCHIVE", "HIDDEN"],
      "source": "allocated"
    }
  ],
  "mft_timestamps": [
    {
      "entry": 88432,
      "filename": "coreupdate.exe",
      "si_created": "2020-09-19T02:15:03Z",
      "si_modified": "2020-09-19T02:15:03Z",
      "fn_created": "2020-09-19T02:15:03Z",
      "fn_modified": "2020-09-19T02:15:03Z"
    }
  ],
  "detections": {
    "timestomping": [
      {
        "filename": "coreupdate.exe",
        "mft_entry": 88432,
        "confidence": 0.7,
        "detail": "SI_Created predates journal FILE_CREATE"
      }
    ],
    "secure_deletion": [],
    "ransomware": [],
    "journal_clearing": { "detected": false, "confidence": 0.0 }
  },
  "ghost_records": [
    { "timestamp": "...", "usn": 12345, "filename": "...", "reasons": ["..."] }
  ],
  "carving_stats": {
    "bytes_scanned": 15447000000,
    "chunks_processed": 3700,
    "usn_carved": 1247,
    "mft_carved": 89,
    "usn_dupes_removed": 312,
    "mft_dupes_removed": 45
  },
  "triage": [
    {
      "id": "malware_deployed",
      "category": "Breach & Malware",
      "question": "Was malware or suspicious software deployed?",
      "has_hits": true,
      "hit_count": 4,
      "record_indices": [1203, 1204, 1205, 1206]
    }
  ]
}
```

Size budget: Szechuan Sauce = 43K records * ~200 bytes = ~8.5MB JSON + ~50KB HTML/CSS/JS. Total ~9MB. Browsers handle this without issue.

## File Structure

```
src/
  output/
    report.rs            # ReportData struct, JSON serialization, HTML injection
  triage/
    mod.rs               # TriageQuestion, TriageQuery, run_queries()
    queries.rs           # builtin_questions() — generic forensic query definitions
report/
  template.html          # Self-contained HTML with inline CSS + JS
                         # Embedded at compile time via include_str!
```

## Triage Queries (Story Tab Brain)

Generic forensic queries that work on any NTFS image:

| Question | Query Logic |
|----------|-------------|
| Was malware deployed? | EXEs/DLLs/SCRs created in System32, Temp, AppData dirs |
| Were sensitive files accessed? | DOCX/XLSX/PDF/TXT/CSV with DATA_EXTEND or CLOSE, excluding Windows/ProgramData |
| Was data stolen? | Same as above, filtered to user profile dirs (Documents, Desktop) |
| How did the attacker move laterally? | rdpclip.exe, tstheme.exe, mstsc.exe creation events |
| How was persistence established? | Files created in Run key paths, startup folders, services dirs, scheduled task dirs |
| Was evidence of anti-forensics found? | Directly from existing detection modules (timestomping, sdelete, clearing) |
| What did carving recover? | Summary of carved USN records, carved MFT entries, ghost records |

Queries are defined as `TriageQuery` structs with filename patterns, extension filters, reason flag masks, path include/exclude patterns, and optional time windows. They run against the resolved records in Rust and produce pre-answered question cards with matching record indices.

## UI Design

### Theme

Dark forensic tool aesthetic.

- Background: #0d1117, Surface: #161b22, Border: #30363d
- Text: #e6edf3, Muted: #7d8590
- Accent blue: #58a6ff, Alert red: #f85149, Warning yellow: #d29922, Success green: #3fb950
- Carved purple: #bc8cff, Ghost cyan: #79c0ff

Typography: system monospace stack (ui-monospace, SFMono-Regular, Menlo, Consolas).

### Header

- Tool name + "RAPID TRIAGE REPORT"
- Image filename and time range
- Four stat cards: total records, carved records, ghost records, alerts
- Tab switcher: [Story] [Explore]

### Story Tab

Vertically scrolling cards, one per triage question. Grouped by category (Breach & Malware, Data Theft, Lateral Movement, Anti-Forensics, Recovered Evidence).

Card states:
- **Collapsed**: Question + YES/NO/INFO badge + match count
- **Expanded**: Evidence summary + top 5 matching records in mini-table
- **Linked**: "Explore all N records" button switches to Explore tab with pre-applied filters

Cards with hits get colored left border: red (threats), purple (carved evidence), blue (informational). Empty cards show "No indicators found" in muted text.

### Explore Tab

Three-panel layout:

1. **Left sidebar** — Filters: time range slider, text search (filename + path), reason flag checkboxes, source toggles (allocated/carved/ghost), "detections only" toggle
2. **Main area** — Activity sparkline (canvas, 1-minute buckets, clickable to zoom) + scrollable data table with fixed header. Columns: Timestamp, Source (colored pill), Filename, Full Path, Reasons, MFT Entry
3. **Bottom panel** — Record detail on row click: all fields, MFT timestamps if available, detection badges

### Cross-Tab Links

Story tab evidence cards have "View in Explore" links that switch tabs and apply filters. Explore tab's sparkline click zooms the time range. This is the bridge between narrative and evidence.

### Performance

43K records in a JS array. `Array.filter()` runs in <5ms. Table shows 500 rows max with pagination. Sparkline rendered to canvas on load. No framework needed — vanilla JS with CSS grid.

## Implementation Approach

The HTML template (`report/template.html`) is a single file containing:
- Inline CSS (dark theme, responsive layout, card components)
- Inline JS (tab switching, filtering, table rendering, sparkline, detail panel)
- A `{{DATA}}` placeholder replaced by the Rust report generator with the serialized JSON

The Rust side (`src/output/report.rs`) builds `ReportData` from the pipeline outputs, runs triage queries, serializes to JSON, reads the template via `include_str!`, replaces the placeholder, and writes the output file.

No build toolchain. No npm. No bundler. Just a Rust binary and an HTML template.
