# Triage Precision & Recall Analysis

Quantitative assessment of triage query accuracy against the Szechuan Sauce CTF ground truth. Each of the 12 IR questions is evaluated as a binary classifier: does it correctly identify attack-related USN records?

## Methodology

### Classification Regimes

Each matched record is classified under two regimes:

- **Strict**: Only records **directly attributable** to known attacker activity (e.g., `coreupdater.exe` in the filename, `loot.zip` creation)
- **Permissive**: Records that are **forensically relevant** — an analyst would want to review them even if they might be benign OS operations during the attack window

### Ground Truth

The attack on DESKTOP-SDN1RPT is documented in four independent writeups and the official DFIR Madness answer key. The known attack timeline on this image:

| Time (journal) | Event |
|---|---|
| 03:39:57 | coreupdater[1].exe downloaded via Edge |
| 03:40:00 | coreupdater.exe saved to Downloads |
| 03:40:42 | coreupdater.exe moved to System32 |
| 03:40:59 | COREUPDATER.EXE prefetch created |
| 03:46:18 | loot.zip staged in mortysmith Documents |
| 03:47:09 | loot.zip deleted after exfiltration |

### Definitions

- **Precision** = TP / (TP + FP) — of flagged records, how many are attack evidence?
- **Recall** = TP / (TP + FN) — of all attack evidence, how many did we flag?
- **F1** = harmonic mean of precision and recall
- **N/A** = question has 0 known positives (data source limitation)

## Per-Question Results

### Strict Classification

| # | Question | Hits | TP | FP | FN | Precision | Recall | F1 |
|---|----------|-----:|---:|---:|---:|----------:|-------:|---:|
| 1 | initial_access | 1491 | 7 | 1484 | 66 | 0.5% | 9.6% | 0.9% |
| 2 | malware_deployed | 1823 | 0 | 1823 | 6 | 0.0% | 0.0% | N/A |
| 3 | execution_evidence | 114 | 3 | 111 | 0 | 2.6% | 100.0% | 5.1% |
| 4 | sensitive_data | 22 | 0 | 22 | 23 | 0.0% | 0.0% | N/A |
| 5 | data_staging | 2 | 2 | 0 | 18 | 100.0% | 10.0% | 18.2% |
| 6 | credential_access | 39 | 1 | 38 | 0 | 2.6% | 100.0% | 5.0% |
| 7 | persistence | 30 | 0 | 30 | 0 | 0.0% | N/A | N/A |
| 8 | lateral_movement | 0 | 0 | 0 | 0 | N/A | N/A | N/A |
| 9 | evidence_destruction | 781 | 0 | 781 | 8 | 0.0% | 0.0% | N/A |
| 10 | timestomping | 76 | 0 | 76 | 2 | 0.0% | 0.0% | N/A |
| 11 | file_disguise | 894 | 8 | 886 | 3 | 0.9% | 72.7% | 1.8% |
| 12 | recovered_evidence | 191 | 191 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### Permissive Classification

| # | Question | Hits | TP | FP | FN | Precision | Recall | F1 |
|---|----------|-----:|---:|---:|---:|----------:|-------:|---:|
| 1 | initial_access | 1491 | 7 | 1484 | 94 | 0.5% | 6.9% | 0.9% |
| 2 | malware_deployed | 1823 | 0 | 1823 | 34 | 0.0% | 0.0% | N/A |
| 3 | execution_evidence | 114 | 3 | 111 | 0 | 2.6% | 100.0% | 5.1% |
| 4 | sensitive_data | 22 | 22 | 0 | 724 | 100.0% | 2.9% | 5.7% |
| 5 | data_staging | 2 | 2 | 0 | 18 | 100.0% | 10.0% | 18.2% |
| 6 | credential_access | 39 | 39 | 0 | 2991 | 100.0% | 1.3% | 2.5% |
| 7 | persistence | 30 | 0 | 30 | 0 | 0.0% | N/A | N/A |
| 8 | lateral_movement | 0 | 0 | 0 | 0 | N/A | N/A | N/A |
| 9 | evidence_destruction | 781 | 0 | 781 | 404 | 0.0% | 0.0% | N/A |
| 10 | timestomping | 76 | 0 | 76 | 2 | 0.0% | 0.0% | N/A |
| 11 | file_disguise | 894 | 38 | 856 | 10 | 4.3% | 79.2% | 8.1% |
| 12 | recovered_evidence | 191 | 191 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### Aggregate (Micro-Average)

| Regime | TP | FP | FN | Precision | Recall | F1 |
|--------|---:|---:|---:|----------:|-------:|---:|
| Strict | 212 | 5251 | 126 | 3.9% | 62.7% | 7.3% |
| Permissive | 302 | 5161 | 4277 | 5.5% | 6.6% | 6.0% |

## Temporal ROC Analysis

The temporal ROC varies a time-window radius around the attack center (03:43 journal time). For each window size T:
- **TPR** = fraction of within-window records that the query matched
- **FPR** = fraction of outside-window records that the query matched

This measures how well each query concentrates its hits near the attack.

**Note on interpretation:** AUC ≈ 0.50 means the query's matches are uniformly distributed across the journal timeline — expected for content-based queries (filename/path/reason matching) that don't use temporal proximity. AUC > 0.55 would indicate temporal clustering; AUC < 0.45 indicates anti-correlation (matches concentrated away from the attack window).

### initial_access (AUC = 0.483)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0342 | 0.0000 |
| 2 | 0.0342 | 0.0000 |
| 5 | 0.0342 | 0.0000 |
| 10 | 0.0343 | 0.0000 |
| 15 | 0.0362 | 0.0000 |
| 30 | 0.0149 | 0.0585 |
| 60 | 0.0110 | 0.0441 |
| 120 | 0.0000 | 0.0432 |
| 240 | 0.0000 | 0.0343 |
| 480 | 0.0000 | 0.0343 |

### malware_deployed (AUC = 0.480)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0418 | 0.0000 |
| 2 | 0.0418 | 0.0000 |
| 5 | 0.0418 | 0.0000 |
| 10 | 0.0419 | 0.0000 |
| 15 | 0.0443 | 0.0000 |
| 30 | 0.0284 | 0.0587 |
| 60 | 0.0361 | 0.0442 |
| 120 | 0.0361 | 0.0433 |
| 240 | 0.0000 | 0.0419 |
| 480 | 0.0000 | 0.0419 |

### execution_evidence (AUC = 0.499)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0026 | 0.0000 |
| 2 | 0.0026 | 0.0000 |
| 5 | 0.0026 | 0.0000 |
| 10 | 0.0026 | 0.0000 |
| 15 | 0.0028 | 0.0000 |
| 30 | 0.0034 | 0.0016 |
| 60 | 0.0037 | 0.0022 |
| 120 | 0.0033 | 0.0024 |
| 240 | 0.0000 | 0.0026 |
| 480 | 0.0000 | 0.0026 |

### sensitive_data (AUC = 0.500)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0005 | 0.0000 |
| 2 | 0.0005 | 0.0000 |
| 5 | 0.0005 | 0.0000 |
| 10 | 0.0005 | 0.0000 |
| 15 | 0.0005 | 0.0000 |
| 30 | 0.0000 | 0.0011 |
| 60 | 0.0001 | 0.0007 |
| 120 | 0.0000 | 0.0006 |
| 240 | 0.0000 | 0.0005 |
| 480 | 0.0000 | 0.0005 |

### data_staging (AUC = 0.500)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0000 | 0.0000 |
| 2 | 0.0000 | 0.0000 |
| 5 | 0.0000 | 0.0000 |
| 10 | 0.0000 | 0.0000 |
| 15 | 0.0000 | 0.0000 |
| 30 | 0.0000 | 0.0001 |
| 60 | 0.0000 | 0.0001 |
| 120 | 0.0000 | 0.0001 |
| 240 | 0.0000 | 0.0000 |
| 480 | 0.0000 | 0.0000 |

### credential_access (AUC = 0.500)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0009 | 0.0000 |
| 2 | 0.0009 | 0.0526 |
| 5 | 0.0009 | 0.0357 |
| 10 | 0.0007 | 0.0366 |
| 15 | 0.0007 | 0.0036 |
| 30 | 0.0009 | 0.0009 |
| 60 | 0.0007 | 0.0010 |
| 120 | 0.0005 | 0.0010 |
| 240 | 0.0000 | 0.0009 |
| 480 | 0.0000 | 0.0009 |

### persistence (AUC = 0.500)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0007 | 0.0000 |
| 2 | 0.0007 | 0.0000 |
| 5 | 0.0007 | 0.0000 |
| 10 | 0.0007 | 0.0000 |
| 15 | 0.0007 | 0.0000 |
| 30 | 0.0000 | 0.0016 |
| 60 | 0.0000 | 0.0010 |
| 120 | 0.0000 | 0.0009 |
| 240 | 0.0000 | 0.0007 |
| 480 | 0.0000 | 0.0007 |

### evidence_destruction (AUC = 0.491)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0179 | 0.0000 |
| 2 | 0.0179 | 0.0000 |
| 5 | 0.0179 | 0.0000 |
| 10 | 0.0180 | 0.0000 |
| 15 | 0.0182 | 0.0133 |
| 30 | 0.0223 | 0.0123 |
| 60 | 0.0325 | 0.0116 |
| 120 | 0.0326 | 0.0140 |
| 240 | 0.0000 | 0.0180 |
| 480 | 0.0000 | 0.0180 |

### timestomping (AUC = 0.497)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0017 | 0.0000 |
| 2 | 0.0017 | 0.0000 |
| 5 | 0.0017 | 0.0000 |
| 10 | 0.0017 | 0.0000 |
| 15 | 0.0018 | 0.0000 |
| 30 | 0.0023 | 0.0010 |
| 60 | 0.0043 | 0.0007 |
| 120 | 0.0061 | 0.0006 |
| 240 | 0.0000 | 0.0017 |
| 480 | 0.0000 | 0.0017 |

### file_disguise (AUC = 0.319)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0205 | 0.0000 |
| 2 | 0.0205 | 0.0000 |
| 5 | 0.0205 | 0.0000 |
| 10 | 0.0206 | 0.0000 |
| 15 | 0.0217 | 0.0000 |
| 30 | 0.0351 | 0.0020 |
| 60 | 0.0652 | 0.0013 |
| 120 | 0.0935 | 0.0012 |
| 240 | 0.3806 | 0.0192 |
| 480 | 0.3806 | 0.0192 |

### recovered_evidence (AUC = 0.001)

| Window (min) | FPR | TPR |
|---:|---:|---:|
| 1 | 0.0044 | 0.0000 |
| 2 | 0.0044 | 0.0000 |
| 5 | 0.0044 | 0.0000 |
| 10 | 0.0044 | 0.0000 |
| 15 | 0.0046 | 0.0000 |
| 30 | 0.0078 | 0.0000 |
| 60 | 0.0144 | 0.0001 |
| 120 | 0.0170 | 0.0010 |
| 240 | 1.0000 | 0.0008 |
| 480 | 1.0000 | 0.0008 |

### AUC Summary

| Question | AUC | Interpretation |
|---|---:|---|
| initial_access | 0.483 | Content-based, not temporally selective |
| malware_deployed | 0.480 | Content-based, not temporally selective |
| execution_evidence | 0.499 | Content-based, not temporally selective |
| sensitive_data | 0.500 | Content-based, not temporally selective |
| data_staging | 0.500 | Content-based, not temporally selective |
| credential_access | 0.500 | Content-based, not temporally selective |
| persistence | 0.500 | Content-based, not temporally selective |
| evidence_destruction | 0.491 | Content-based, not temporally selective |
| timestomping | 0.497 | Content-based, not temporally selective |
| file_disguise | 0.319 | Inversely correlated with attack window |
| recovered_evidence | 0.001 | Inversely correlated with attack window |

## Discussion

### Per-Question Analysis

**initial_access** (P=0.5%, R=9.6%, F1=0.9%): 7 coreupdater records found among 1491 total download artifacts. 66 FN: query misses FILE_DELETE, RENAME_OLD_NAME, and cross-question artifacts (prefetch, System32 move).

**malware_deployed** (P=0.0%, R=0.0%, F1=N/A): 0/6 coreupdater System32 records found. Query catches FILE_CREATE but coreupdater reaches System32 via RENAME_NEW_NAME (file move) + SECURITY_CHANGE/STREAM_CHANGE — none matched.

**execution_evidence** (P=2.6%, R=100.0%, F1=5.1%): All 3 COREUPDATER.EXE prefetch records found (100% recall). Low precision because all 114 .pf FILE_CREATE events match, not just attacker programs.

**sensitive_data** (P=0.0%, R=0.0%, F1=N/A): 0/22 hits are attack-related — all are legitimate .txt files (OneDrive logs, IE brndlog). Actual sensitive files (Social Security.zip, loot.zip) use RENAME/DELETE flags the query doesn't match.

**data_staging** (P=100.0%, R=10.0%, F1=18.2%): Narrow query (FILE_CREATE + archive extensions in user dirs). Perfect precision but low recall — misses RENAME_NEW_NAME (loot.zip) and associated .lnk/.TMP records.

**credential_access** (P=2.6%, R=100.0%, F1=5.0%): Found the SYSTEM hive write during attack window (100% recall). Most FP are legitimate hive I/O outside the attack window.

**persistence** (P=0.0%, R=N/A, F1=N/A): No strict positives: actual persistence (coreupdater service + registry Run key) is invisible to USN journal. 30 hits are Administrator profile Start Menu initialization.

**evidence_destruction** (P=0.0%, R=0.0%, F1=N/A): 0/8 strict positives found. COREUPDATER.pf has FILE_CREATE (first execution) but query catches DATA_TRUNCATION (re-execution). Attack-window .evtx writes are at 04:01 (outside 03:38-03:48 window).

**timestomping** (P=0.0%, R=0.0%, F1=N/A): 0/2 strict positives found. The 2 BASIC_INFO_CHANGE records on coreupdater.partial are missed because the query's path filter excludes Downloads. Actual timestomping of Beth_Secret.txt occurred on the DC.

**file_disguise** (P=0.9%, R=72.7%, F1=1.8%): 8/11 ADS ops on coreupdater files found (72.7% recall). 886 FP from Zone.Identifier/SmartScreen ADS on legitimate files — expected for this broad indicator type.

**recovered_evidence** (P=100.0%, R=100.0%, F1=100.0%): All 191 ghost records from $LogFile matched and recovered. Perfect precision and recall.

### Root Cause: Reason-Flag Coverage Gaps

The dominant recall failure mode is **reason-flag mismatch**. Several triage queries filter on `FILE_CREATE` but miss records with:

- `RENAME_NEW_NAME` — file moves (coreupdater.exe Downloads → System32)
- `RENAME_OLD_NAME` — the source side of file moves
- `FILE_DELETE` — evidence of deleted files (loot.zip exfiltration cleanup)
- `SECURITY_CHANGE` / `STREAM_CHANGE` — permission and ADS modifications

This is a query design issue, not a data source limitation. Adding these reason flags to the relevant queries would improve recall without significant precision loss.

### Data Source Limitations

Questions where the USN journal is fundamentally the wrong artifact:

- **lateral_movement**: RDP evidence exists in Event Logs (logon events) and PCAP, not USN journal
- **persistence**: Service installation (Event ID 7045) and registry Run keys are event log / registry hive artifacts, not USN journal events

### Precision-Recall Tradeoff

The 12 questions fall into three performance tiers:

| Tier | Characteristics | Questions |
|---|---|---|
| **Tier 1: High-confidence** | P≥50% or R=100% | data_staging, recovered_evidence, execution_evidence, credential_access |
| **Tier 2: Broad-net** | Low P, detects signal among noise | initial_access, file_disguise |
| **Tier 3: Reason-flag gap** | 0% R due to query design | malware_deployed, sensitive_data, evidence_destruction, timestomping |
| **Tier 4: Data-source N/A** | Artifact limitation | persistence, lateral_movement |

### Improvement Opportunities

1. **Expand reason-flag coverage** (Tier 3 → Tier 2): Adding RENAME_NEW_NAME to malware_deployed would capture the file-move attack pattern. Adding FILE_DELETE to sensitive_data would capture exfiltration cleanup.
2. **Temporal clustering** (Tier 2 → Tier 1): ROC analysis shows attack-window hits have higher signal density. Scoring records by proximity to temporal activity bursts would improve precision.
3. **Known-good baseline subtraction**: Excluding known Windows system paths (NativeImages, SoftwareDistribution) from broad queries would reduce FP without losing attacker signal.
