use anyhow::Result;
use rusqlite::Connection;

use crate::rewind::ResolvedRecord;
use crate::mft::MftEntry;

/// Export resolved USN records and MFT data to an SQLite database.
///
/// Creates tables: USNJRNL_FullPaths, MFT (if MFT data provided).
/// Compatible with CyberCX usnjrnl_rewind output format.
pub fn export_sqlite(
    path: &std::path::Path,
    usn_records: &[ResolvedRecord],
    mft_entries: Option<&[MftEntry]>,
) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    // Create USN Journal table
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS USNJRNL_FullPaths (
            UpdateTimestamp TEXT,
            UpdateSequenceNumber INTEGER,
            EntryNumber INTEGER,
            SequenceNumber INTEGER,
            ParentEntryNumber INTEGER,
            ParentSequenceNumber INTEGER,
            ParentPath TEXT,
            FileName TEXT,
            Extension TEXT,
            FileAttributes TEXT,
            UpdateReasons TEXT,
            SourceInfo INTEGER,
            SecurityId INTEGER,
            MajorVersion INTEGER
        )",
    )?;

    // Insert USN records
    let mut stmt = conn.prepare(
        "INSERT INTO USNJRNL_FullPaths VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
    )?;

    conn.execute_batch("BEGIN TRANSACTION")?;
    for resolved in usn_records {
        let r = &resolved.record;
        let extension = r
            .filename
            .rsplit('.')
            .next()
            .filter(|ext| ext.len() < r.filename.len())
            .unwrap_or("");

        stmt.execute(rusqlite::params![
            r.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            r.usn,
            r.mft_entry as i64,
            r.mft_sequence as i64,
            r.parent_mft_entry as i64,
            r.parent_mft_sequence as i64,
            resolved.parent_path,
            r.filename,
            extension,
            r.file_attributes.to_string(),
            r.reason.to_string(),
            r.source_info as i64,
            r.security_id as i64,
            r.major_version as i64,
        ])?;
    }
    conn.execute_batch("COMMIT")?;

    // Create MFT table if data provided
    if let Some(entries) = mft_entries {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS MFT (
                EntryNumber INTEGER,
                SequenceNumber INTEGER,
                InUse INTEGER,
                ParentEntryNumber INTEGER,
                ParentSequenceNumber INTEGER,
                ParentPath TEXT,
                FileName TEXT,
                IsDirectory INTEGER,
                HasAds INTEGER,
                FileSize INTEGER,
                SI_Created TEXT,
                SI_Modified TEXT,
                SI_MFTModified TEXT,
                SI_Accessed TEXT,
                FN_Created TEXT,
                FN_Modified TEXT,
                FN_MFTModified TEXT,
                FN_Accessed TEXT,
                FullPath TEXT
            )",
        )?;

        let mut mft_stmt = conn.prepare(
            "INSERT INTO MFT VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        )?;

        conn.execute_batch("BEGIN TRANSACTION")?;
        for entry in entries {
            let fmt = |dt: &Option<chrono::DateTime<chrono::Utc>>| -> String {
                dt.map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
                    .unwrap_or_default()
            };

            mft_stmt.execute(rusqlite::params![
                entry.entry_number as i64,
                entry.sequence_number as i64,
                entry.is_in_use as i64,
                entry.parent_entry as i64,
                entry.parent_sequence as i64,
                "", // ParentPath - resolved separately
                entry.filename,
                entry.is_directory as i64,
                entry.has_ads as i64,
                entry.file_size as i64,
                fmt(&entry.si_created),
                fmt(&entry.si_modified),
                fmt(&entry.si_mft_modified),
                fmt(&entry.si_accessed),
                fmt(&entry.fn_created),
                fmt(&entry.fn_modified),
                fmt(&entry.fn_mft_modified),
                fmt(&entry.fn_accessed),
                entry.full_path,
            ])?;
        }
        conn.execute_batch("COMMIT")?;
    }

    // Create indexes for common queries
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_usn_entry ON USNJRNL_FullPaths(EntryNumber, SequenceNumber);
         CREATE INDEX IF NOT EXISTS idx_usn_parent ON USNJRNL_FullPaths(ParentEntryNumber, ParentSequenceNumber);
         CREATE INDEX IF NOT EXISTS idx_usn_timestamp ON USNJRNL_FullPaths(UpdateTimestamp);
         CREATE INDEX IF NOT EXISTS idx_usn_reasons ON USNJRNL_FullPaths(UpdateReasons);
         CREATE INDEX IF NOT EXISTS idx_usn_filename ON USNJRNL_FullPaths(FileName);"
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{UsnRecord, UsnReason, FileAttributes};
    use crate::rewind::ResolvedRecord;
    use chrono::DateTime;

    #[test]
    fn test_sqlite_export() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.sqlite");

        let record = UsnRecord {
            mft_entry: 100,
            mft_sequence: 3,
            parent_mft_entry: 50,
            parent_mft_sequence: 1,
            usn: 12345,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason: UsnReason::FILE_CREATE,
            filename: "test.exe".into(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };
        let resolved = vec![ResolvedRecord {
            record,
            full_path: ".\\temp\\test.exe".into(),
            parent_path: ".\\temp".into(),
        }];

        export_sqlite(&db_path, &resolved, None).unwrap();

        // Verify data was written
        let conn = Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM USNJRNL_FullPaths", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        let filename: String = conn
            .query_row("SELECT FileName FROM USNJRNL_FullPaths", [], |row| row.get(0))
            .unwrap();
        assert_eq!(filename, "test.exe");
    }
}
