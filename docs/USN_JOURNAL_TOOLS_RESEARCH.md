# Comprehensive USN Journal Tools Research

> Compiled: 2026-03-02 | Goal: Make our `usnjrnl` tool the most comprehensive in the world

---

## Table of Contents

1. [Python Tools](#1-python-tools)
2. [Rust Tools](#2-rust-tools)
3. [C/C++ Tools](#3-cc-tools)
4. [Go Tools](#4-go-tools)
5. [.NET/C# Tools](#5-netc-tools)
6. [AutoIt Tools (Joakim Schicht Suite)](#6-autoit-tools-joakim-schicht-suite)
7. [PowerShell Tools](#7-powershell-tools)
8. [EnScript Tools (EnCase)](#8-enscript-tools-encase)
9. [Endpoint/Platform Tools](#9-endpointplatform-tools)
10. [Commercial/Proprietary Tools](#10-commercialproprietary-tools)
11. [Academic Papers & Research](#11-academic-papers--research)
12. [Feature Gap Analysis](#12-feature-gap-analysis---opportunities-for-our-tool)

---

## 1. Python Tools

### 1.1 USN-Journal-Parser (PoorBillionaire/usnparser)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/PoorBillionaire/USN-Journal-Parser |
| **PyPI** | https://pypi.org/project/usnparser/ |
| **Author** | Adam Witt |
| **Version** | 4.1.6 |
| **License** | Apache Software License |

**Key Features:**
- Parses `$UsnJrnl:$J` files
- Multiple output formats: default text, CSV, body file, TLN timeline, verbose JSON
- Quick parse mode for large journals (`-q`)
- Supports `USN_RECORD_V2`

**Limitations:** No V3/V4 support, no MFT cross-reference for path reconstruction, no carving

**Unique:** Most widely-used Python USN parser, available on PyPI

---

### 1.2 parseusn.py (superponible/DFIR)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/superponible/DFIR/blob/master/parseusn.py |
| **Author** | Dave Lassalle (@superponible) |

**Key Features:**
- Cross-platform, not memory intensive
- Multiple output: CSV, tab, body, TLN, l2ttln
- Optional MFT file input (`-m`) for full path resolution
- `USN_RECORD_V2`

**Limitations:** No V3/V4, no carving

**Unique:** MFT path resolution built-in, used as basis for Autopsy plugin

---

### 1.3 CyberCX usnjrnl_rewind

| Field | Value |
|-------|-------|
| **URL** | https://github.com/CyberCX-DFIR/usnjrnl_rewind |
| **Author** | Yogesh Khatri (CyberCX) |
| **Version** | 0.4 |

**Key Features:**
- Full path builder for USN Journal entries
- Reads journal records from last to earliest ("rewinding")
- Handles reused/recycled MFT entries correctly
- Outputs corrected USN Journal CSV + SQLite database
- Requires MFTECmd CSV output as input

**Limitations:** Depends on MFTECmd for initial parsing, proof of concept

**Unique:** ONLY tool that correctly reconstructs deleted file paths when MFT entries are reused. Reverse-chronological processing algorithm.

---

### 1.4 OTORIO UsnExtractor

| Field | Value |
|-------|-------|
| **URL** | https://github.com/otoriocyber/UsnExtractor |
| **Author** | Daniel Lubel (OTORIO IR Team) |
| **License** | GPL-3.0 |

**Key Features:**
- Extracts `$UsnJrnl` from live NTFS volumes
- Extracts only actual data (skips sparse/zero regions)
- Python reimplementation of Joakim Schicht's ExtractUsnJrnl

**Limitations:** Extraction only, no parsing

**Unique:** Efficient extraction avoiding sparse data bloat

---

### 1.5 dfir_ntfs (msuhanov)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/msuhanov/dfir_ntfs |
| **Author** | Maxim Suhanov |
| **License** | GPL v3 |

**Key Features:**
- Parses `$MFT`, `$UsnJrnl:$J`, and `$LogFile`
- Supports `USN_RECORD_V2`, `V3`, AND `V4` (rare!)
- Supports `$LogFile` versions 1.1 and 2.0
- Parses volumes, volume images, volume shadow copies
- FAT12/16/32/exFAT support
- VSC mounting via FUSE
- MACE timestamp notation

**Limitations:** Python performance

**Unique:** ONE OF FEW tools supporting `USN_RECORD_V4`. Comprehensive multi-artifact parser.

---

### 1.6 USN Record Carver (PoorBillionaire/usncarve)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/PoorBillionaire/USN-Record-Carver |
| **PyPI** | https://pypi.org/project/usncarve/ |

**Key Features:**
- Carves USN journal records from arbitrary binary data
- Outputs carved records in binary for further parsing
- Targets unallocated space where rotated journal records persist

**Limitations:** Only raw/dd input, carving only (no parsing)

**Unique:** Dedicated USN carving tool, companion to usnparser

---

### 1.7 ntfs_parse (NTFSparse)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/NTFSparse/ntfs_parse |

**Key Features:**
- NTFS parser with linking capabilities between MFT, LogFile, and UsnJrnl
- Research project exploring artifact combination
- Standalone parsers: mftparse.py, logfileparse.py

**Unique:** Explicit focus on LINKING/correlating all three NTFS journal artifacts

---

### 1.8 Plaso/log2timeline (usnjrnl parser)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/log2timeline/plaso |

**Key Features:**
- `NTFSUsnJrnlParser` class for parsing `$UsnJrnl:$J`
- Integrates into super-timeline with 100+ other parsers
- Supports `USN_RECORD_V2`
- Processes raw disk images via dfVFS

**Unique:** Integrates USN data into unified super-timeline with all other artifacts

---

### 1.9 Volatility USN Parser Plugin

| Field | Value |
|-------|-------|
| **URL** | https://github.com/tomspencer/volatility (usnparser directory) |

**Key Features:**
- Parses USN journal records FROM MEMORY DUMPS
- Body file output for timeline creation
- Strict mode for reducing corrupt entries
- Timestamp validation (`--checktime`)
- Unicode filename support

**Unique:** ONLY tool that extracts USN records from volatile memory. Can find records from removed external drives.

---

## 2. Rust Tools

### 2.1 usnrs (Airbus CERT)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/airbus-cert/usnrs |
| **Crate** | https://crates.io/crates/usnrs |
| **Author** | Airbus CERT |

**Key Features:**
- CLI binary (`usnrs-cli`) + library
- Handles both sparse and non-sparse journal files
- Body file output (v3.X) for mactime
- MFT-based full path reconstruction
- Checks for reallocated MFT entries to prevent false paths
- `USN_RECORD_V2`

**Limitations:** V2 only, no carving

**Unique:** Handles sparse vs. compact extraction differences. From Airbus CERT.

---

### 2.2 usn-journal-rs (wangfu91)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/wangfu91/usn-journal-rs |
| **Crate** | https://crates.io/crates/usn-journal-rs |

**Key Features:**
- Library for NTFS/ReFS USN change journal
- MFT enumeration as Rust iterators
- Safe, ergonomic API

**Limitations:** Windows-only, library only

**Unique:** ReFS support in Rust

---

### 2.3 usn-parser-rs (wangfu91)

| Field | Value |
|-------|-------|
| **URL** | https://crates.io/crates/usn-parser |

**Key Features:**
- CLI for NTFS/ReFS USN Change Journal
- Real-time monitoring
- MFT search capability
- Historical USN journal reading

**Limitations:** Windows-only, requires admin

**Unique:** Rust port of UsnParser (.NET), more performant

---

### 2.4 ntfs-reader

| Field | Value |
|-------|-------|
| **URL** | https://crates.io/crates/ntfs-reader |

**Key Features:** Read MFT and USN journal

---

### 2.5 ntfs-usn

| Field | Value |
|-------|-------|
| **URL** | https://crates.io/crates/ntfs-usn |

**Key Features:** Easy manipulation of NTFS USN journals on Windows

---

## 3. C/C++ Tools

### 3.1 ntfstool (thewhiteninja)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/thewhiteninja/ntfstool |

**Key Features:**
- Parse and analyze USN journal with **custom rules**
- Rule-based detection of suspicious programs/actions (e.g., LSASS dumps)
- USN dump to CSV/JSON/raw
- MFT dump with Zone.Identifier parsing
- Deleted file recovery, Bitlocker decryption
- Interactive shell
- Statistical overview (% deleted, created, etc.)

**Unique:** CUSTOM RULE ENGINE for USN analysis. Zone.Identifier integration.

---

### 3.2 ntfs-journal-viewer (mgeeky)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/mgeeky/ntfs-journal-viewer |
| **Author** | Mariusz B. (2012) |

**Key Features:**
- Simple NTFS Journal dumping utility
- Search by filename, timestamp, or specific USN
- Timestamp wildcards

---

### 3.3 ntfs-linker (Stroz Friedberg)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/strozfriedberg/ntfs-linker |
| **Author** | Stroz Friedberg (Aon) |

**Key Features:**
- Links `$MFT`, `$LogFile`, and `$UsnJrnl` into unified timeline
- Processes Volume Shadow Copies with deduplication
- Discovers `$UsnJrnl` entries embedded in `$LogFile`
- Three output reports: events.txt, log.txt, usn.txt (TSV)
- SQLite database output

**Unique:** BEST tool for correlating all three NTFS artifacts. Finds USN entries inside `$LogFile`. VSC deduplication.

---

### 3.4 The Sleuth Kit (TSK)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/sleuthkit/sleuthkit |

**Key Features:**
- `fls`/`icat`/`istat` for extracting `$UsnJrnl:$J` from disk images
- Foundation library used by many other tools

**Unique:** Industry-standard forensic library

---

## 4. Go Tools

### 4.1 go-ntfs (Velocidex)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/Velocidex/go-ntfs |

**Key Features:**
- `ParseUSN` function returning channel of `USN_RECORD`
- Full NTFS parser including MFT, VSS catalogs
- Powers Velociraptor

---

### 4.2 forensicanalysis/fslib

| Field | Value |
|-------|-------|
| **URL** | https://github.com/forensicanalysis/fslib |

**Key Features:** io/fs implementation of NTFS in Go

---

## 5. .NET/C# Tools

### 5.1 MFTECmd (Eric Zimmerman)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/EricZimmerman/MFTECmd |
| **Author** | Eric Zimmerman (Kroll) |

**Key Features:**
- Parses `$MFT`, `$UsnJrnl:$J`, `$LogFile`, `$Secure:$SDS`
- Full path reconstruction when `$MFT` provided
- CSV output for Timeline Explorer
- Supports `USN_RECORD_V2` and `V3`
- Used with KAPE for automated collection

**Unique:** GOLD STANDARD for DFIR USN parsing. Most widely recommended.

---

### 5.2 UsnParser (wangfu91)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/wangfu91/UsnParser |
| **License** | MIT |

**Key Features:**
- Monitor real-time USN journal changes
- Read historical entries
- Search Master File Table
- **NTFS AND ReFS support**
- Three commands: monitor, read, search

**Unique:** One of FEW tools supporting ReFS USN journals.

---

## 6. AutoIt Tools (Joakim Schicht Suite)

### 6.1 UsnJrnl2Csv

| Field | Value |
|-------|-------|
| **URL** | https://github.com/jschicht/UsnJrnl2Csv |

**Key Features:**
- `USN_RECORD_V2` and `V3` support
- Brute-force scan mode for carving records from any data
- CSV output, MySQL import

**Unique:** Brute-force record detection in arbitrary data

---

### 6.2 ExtractUsnJrnl

| Field | Value |
|-------|-------|
| **URL** | https://github.com/jschicht/ExtractUsnJrnl |

**Key Features:**
- Extracts only actual data (compact extraction)
- VSS, physical drives, mounted/unmounted volumes

**Unique:** "Why extract 20GB when you need 200MB?"

---

### 6.3 UsnJrnlCarver

| Field | Value |
|-------|-------|
| **URL** | https://github.com/jschicht/UsnJrnlCarver |

**Key Features:** Carves USN pages from unallocated space

---

## 7. PowerShell Tools

### 7.1 PowerForensics

| Field | Value |
|-------|-------|
| **URL** | https://powerforensics.readthedocs.io/ |

**Key Features:**
- `Get-ForensicUsnJrnl`: Parses `$UsnJrnl:$J`
- `Get-ForensicUsnJrnlInformation`: Parses `$UsnJrnl:$Max`

---

### 7.2 Get-UsnJrnlInfo

| Field | Value |
|-------|-------|
| **URL** | https://github.com/evild3ad/Get-UsnJrnlInfo |

**Key Features:** Gets UsnJrnl Information from extracted `$Max` file

---

## 8. EnScript Tools (EnCase)

### 8.1 FCNS_UsnJrnl (Forensicist/Kazamiya)

| Field | Value |
|-------|-------|
| **URL** | https://www.kazamiya.net/en/node/58 |

**Key Features:**
- Carves USN records from `$UsnJrnl:$J`, `$LogFile`, `pagefile.sys`, and unallocated clusters
- "Integrate output records" deduplication option

**Unique:** Multi-source carving (journal + logfile + pagefile + unallocated)

---

## 9. Endpoint/Platform Tools

### 9.1 Velociraptor

| Field | Value |
|-------|-------|
| **URL** | https://docs.velociraptor.app/ |

**Key Features:**
- `parse_usn()`: Parse from device, image, or file
- `watch_usn()`: Real-time event-driven monitoring
- `Windows.Forensics.Usn`: Built-in artifact with filtering
- `Windows.Carving.USN`: YARA-based carving from raw disk
- `Windows.Forensics.LocalHashes.Usn`: Real-time hashing via USN monitoring
- Full path reconstruction, VSS support

**Unique:** REAL-TIME USN monitoring. Endpoint-scale deployment. YARA-based carving.

---

### 9.2 DFIR ORC (ANSSI)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/DFIR-ORC/dfir-orc |

**Key Features:**
- `USNInfo`: Collects USN journal
- `NTFSInfo`: Collects NTFS metadata
- `NTFSUtil`: USN journal inspection

**Unique:** Enterprise-grade from French ANSSI. 8 years of development.

---

### 9.3 KAPE (Eric Zimmerman/Kroll)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/EricZimmerman/KapeFiles |

**Key Features:**
- Automated collection + processing via MFTECmd module
- Community-contributed targets/modules

---

## 10. Commercial/Proprietary Tools

### 10.1 TZWorks JP (Windows Journal Parser)

| Field | Value |
|-------|-------|
| **URL** | https://tzworks.com/prototype_page.php?proto_id=5 |
| **Platforms** | Windows, Linux, macOS |

**Key Features:**
- Raw structure parsing (no Windows API)
- Three input sources: extracted file, dd image, mounted partition
- Full path reconstruction with MFT
- Unallocated cluster scanning (carving)
- Volume Shadow Copy support
- Slack space scanning
- CSV and XML output

**Unique:** CROSS-PLATFORM commercial. MOST ADVANCED carving (unalloc + slack + VSS).

---

### 10.2 X-Ways Forensics

Built-in `$UsnJrnl` and `$LogFile` parsing. Lightweight, fast, affordable commercial suite.

### 10.3 EnCase Forensic

Robust NTFS parsing, court-admissible. EnScript extensibility.

### 10.4 FTK (Forensic Toolkit)

Database-driven fast searching. FTK Imager for raw MFT access.

### 10.5 OSForensics

Built-in `$UsnJrnl` viewer with search, timeline integration.

### 10.6 ArtiFast (ForenSafe)

USN Journal extraction/analysis, 2,995+ artifact types, timeline view.

### 10.7 Magnet AXIOM

Windows forensics including USN journal, cross-source correlation.

---

### 10.8 NTFS Journal Viewer (E5h)

| Field | Value |
|-------|-------|
| **URL** | https://e5hforensics.com/index.php/downloads/software/ntfs-journal-viewer/ |

Free, portable, fast parsing (hundreds of thousands of records in seconds).

---

### 10.9 NTFS Log Tracker (blueangel)

| Field | Value |
|-------|-------|
| **URL** | https://sites.google.com/site/forensicnote/ntfs-log-tracker |

**Key Features:**
- Parses `$LogFile` AND `$UsnJrnl:$J`
- Carves from: unallocated, file slack, pagefile.sys, memory dump, VSS
- **Timestamp manipulation detection** (pattern-based)
- `$LogFile` v2.0 (Win10) support

**Unique:** TIMESTAMP MANIPULATION DETECTION built-in.

---

### 10.10 USN Analytics (Forensicist/4n6ist)

| Field | Value |
|-------|-------|
| **URL** | https://www.kazamiya.net/en/usn_analytics |
| **GitHub** | https://github.com/4n6ist/usn_analytics |

**Key Features:**
- Groups related records by file ID
- Path reconstruction from parent IDs
- Program execution history from prefetch events
- File open history from LNK/ObjectID events
- Potential indicator list from suspicious extensions/filenames

**Unique:** MOST INTELLIGENT ANALYSIS. Auto-generates execution history, file open history, and IOC lists.

---

### 10.11 bulk_extractor-rec (Forensicist/4n6ist)

| Field | Value |
|-------|-------|
| **URL** | https://github.com/4n6ist/bulk_extractor-rec |

High-speed multi-threaded carving (100-300 MB/sec) with ntfsusn scanner.

---

### 10.12 Autopsy Parse_USNJ Plugin

| Field | Value |
|-------|-------|
| **URL** | https://github.com/markmckinnon/Autopsy-Plugins |

Integrates USN parsing into Autopsy GUI via SQLite.

---

## 11. Academic Papers & Research

| Paper | Year | Key Finding |
|-------|------|-------------|
| "Determining removal of forensic artefacts using the USN change journal" (Lees) | 2013 | USN patterns detect CCleaner, InPrivate browsing, artifact removal |
| "Forensic analysis of ReFS journaling" | 2021 | ReFS uses `USN_RECORD_V3`, different structures from NTFS |
| "Anti-anti-forensic method using NTFS transactions + ML" | Various | ML identifies data wiping tools from NTFS traces |
| "NTFS Data Tracker" (blueangel) | 2021 | File data history from `$LogFile` |
| "Windows Forensic Analysis of Ransomware" (IEEE) | 2024 | USN journal in ransomware detection |

---

## 12. Feature Gap Analysis - Opportunities for Our Tool

### What NO existing tool fully delivers:

| Gap | Opportunity |
|-----|-------------|
| **USN_RECORD_V4** | Only dfir_ntfs (Python) claims V4. No Rust tool supports it. |
| **ReFS USN Journal** | Only UsnParser (.NET) and usn-journal-rs (Rust lib). Massive gap. |
| **Full MFT+LogFile+UsnJrnl correlation** | Only ntfs-linker (C++) does this. No Rust tool does it. |
| **Automated timestomping detection** | NTFS Log Tracker has basic detection. No tool does comprehensive correlation-based detection. |
| **ML/behavioral analysis** | USN Analytics does basic behavioral analysis. No tool applies ML. |
| **Cross-platform Rust offline parser** | No Rust tool parses extracted `$J` on Linux/macOS with MFT correlation. |
| **USN carving in Rust** | No Rust tool carves from unallocated space. |
| **Anti-forensics detection suite** | No tool comprehensively detects secure deletion, CCleaner, journal clearing patterns. |
| **All output formats** | No single tool: CSV + JSON + body + TLN + SQLite + XML. |
| **E01/EWF image support** | Few tools process forensic images directly. No Rust tool does. |
| **Ransomware pattern detection** | No tool auto-detects ransomware patterns from USN data. |
| **Prefetch/LNK/execution correlation** | Only USN Analytics. Not in any Rust/Go tool. |
| **Rewind path reconstruction** | Only CyberCX usnjrnl_rewind handles reused MFT entries. |
| **Memory dump USN extraction** | Only Volatility plugin. |

### To be the MOST COMPREHENSIVE tool, ours should support:

1. All record versions: V2, V3, V4
2. Both NTFS and ReFS
3. MFT cross-reference for full path reconstruction
4. Rewind algorithm for reused MFT entries (a la CyberCX)
5. USN record carving from unallocated/slack/pagefile
6. MFT + LogFile + UsnJrnl correlation
7. Timestomping/anti-forensics detection
8. Ransomware pattern detection
9. Behavioral analysis (prefetch, LNK, execution history)
10. All output formats (CSV, JSON, JSONL, body, TLN, SQLite, XML)
11. E01/EWF/raw image input support
12. Cross-platform (Windows, Linux, macOS)
13. Real-time monitoring mode (Windows)
14. Custom rule engine (like ntfstool)
15. High-performance multi-threaded processing

---

## Sources

- [USN-Journal-Parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
- [parseusn.py](https://github.com/superponible/DFIR/blob/master/parseusn.py)
- [CyberCX usnjrnl_rewind](https://github.com/CyberCX-DFIR/usnjrnl_rewind)
- [OTORIO UsnExtractor](https://github.com/otoriocyber/UsnExtractor)
- [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs)
- [USN Record Carver](https://github.com/PoorBillionaire/USN-Record-Carver)
- [ntfs_parse](https://github.com/NTFSparse/ntfs_parse)
- [Plaso](https://github.com/log2timeline/plaso)
- [usnrs](https://github.com/airbus-cert/usnrs)
- [usn-journal-rs](https://github.com/wangfu91/usn-journal-rs)
- [usn-parser-rs](https://github.com/wangfu91/usn-parser-rs)
- [ntfstool](https://github.com/thewhiteninja/ntfstool)
- [ntfs-journal-viewer](https://github.com/mgeeky/ntfs-journal-viewer)
- [ntfs-linker](https://github.com/strozfriedberg/ntfs-linker)
- [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit)
- [go-ntfs](https://github.com/Velocidex/go-ntfs)
- [forensicanalysis/fslib](https://github.com/forensicanalysis/fslib)
- [MFTECmd](https://github.com/EricZimmerman/MFTECmd)
- [UsnParser](https://github.com/wangfu91/UsnParser)
- [UsnJrnl2Csv](https://github.com/jschicht/UsnJrnl2Csv)
- [ExtractUsnJrnl](https://github.com/jschicht/ExtractUsnJrnl)
- [UsnJrnlCarver](https://github.com/jschicht/UsnJrnlCarver)
- [PowerForensics](https://powerforensics.readthedocs.io/)
- [Get-UsnJrnlInfo](https://github.com/evild3ad/Get-UsnJrnlInfo)
- [FCNS_UsnJrnl](https://www.kazamiya.net/en/node/58)
- [USN Analytics](https://www.kazamiya.net/en/usn_analytics)
- [bulk_extractor-rec](https://github.com/4n6ist/bulk_extractor-rec)
- [Velociraptor](https://docs.velociraptor.app/)
- [DFIR ORC](https://github.com/DFIR-ORC/dfir-orc)
- [KAPE](https://github.com/EricZimmerman/KapeFiles)
- [TZWorks JP](https://tzworks.com/prototype_page.php?proto_id=5)
- [NTFS Journal Viewer (E5h)](https://e5hforensics.com/index.php/downloads/software/ntfs-journal-viewer/)
- [NTFS Log Tracker](https://sites.google.com/site/forensicnote/ntfs-log-tracker)
- [Autopsy Plugins](https://github.com/markmckinnon/Autopsy-Plugins)
- [OSForensics](https://www.osforensics.com/usnjrnl-viewer.html)
- [ArtiFast](https://forensafe.com/)
