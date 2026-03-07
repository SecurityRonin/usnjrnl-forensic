use anyhow::Result;
use rusqlite::Connection;

use crate::mft::MftEntry;
use crate::rewind::ResolvedRecord;

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
            r.timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
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
    use crate::rewind::ResolvedRecord;
    use crate::usn::{FileAttributes, UsnReason, UsnRecord};
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
            source: crate::rewind::RecordSource::Allocated,
        }];

        export_sqlite(&db_path, &resolved, None).unwrap();

        // Verify data was written
        let conn = Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM USNJRNL_FullPaths", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        let filename: String = conn
            .query_row("SELECT FileName FROM USNJRNL_FullPaths", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(filename, "test.exe");
    }

    #[test]
    fn test_sqlite_export_with_mft_entries() {
        use crate::mft::MftEntry;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_mft.sqlite");

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
            source: crate::rewind::RecordSource::Allocated,
        }];

        let mft_entries = vec![
            MftEntry {
                entry_number: 100,
                sequence_number: 3,
                filename: "test.exe".into(),
                parent_entry: 50,
                parent_sequence: 1,
                is_directory: false,
                is_in_use: true,
                si_created: Some(DateTime::from_timestamp(1700000000, 0).unwrap()),
                si_modified: Some(DateTime::from_timestamp(1700000100, 0).unwrap()),
                si_mft_modified: Some(DateTime::from_timestamp(1700000100, 0).unwrap()),
                si_accessed: Some(DateTime::from_timestamp(1700000200, 0).unwrap()),
                fn_created: Some(DateTime::from_timestamp(1700000000, 0).unwrap()),
                fn_modified: Some(DateTime::from_timestamp(1700000100, 0).unwrap()),
                fn_mft_modified: Some(DateTime::from_timestamp(1700000100, 0).unwrap()),
                fn_accessed: Some(DateTime::from_timestamp(1700000200, 0).unwrap()),
                full_path: ".\\temp\\test.exe".into(),
                file_size: 65536,
                has_ads: false,
            },
            MftEntry {
                entry_number: 50,
                sequence_number: 1,
                filename: "temp".into(),
                parent_entry: 5,
                parent_sequence: 5,
                is_directory: true,
                is_in_use: true,
                si_created: None,
                si_modified: None,
                si_mft_modified: None,
                si_accessed: None,
                fn_created: None,
                fn_modified: None,
                fn_mft_modified: None,
                fn_accessed: None,
                full_path: ".\\temp".into(),
                file_size: 0,
                has_ads: true,
            },
        ];

        export_sqlite(&db_path, &resolved, Some(&mft_entries)).unwrap();

        // Verify USN data
        let conn = Connection::open(&db_path).unwrap();
        let usn_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM USNJRNL_FullPaths", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(usn_count, 1);

        // Verify MFT data
        let mft_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM MFT", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mft_count, 2);

        let mft_filename: String = conn
            .query_row(
                "SELECT FileName FROM MFT WHERE EntryNumber = 100",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mft_filename, "test.exe");

        let mft_is_dir: i64 = conn
            .query_row(
                "SELECT IsDirectory FROM MFT WHERE EntryNumber = 50",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mft_is_dir, 1);

        let mft_has_ads: i64 = conn
            .query_row("SELECT HasAds FROM MFT WHERE EntryNumber = 50", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(mft_has_ads, 1);
    }

    #[test]
    fn test_sqlite_export_empty_records() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_empty.sqlite");

        export_sqlite(&db_path, &[], None).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM USNJRNL_FullPaths", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_sqlite_extension_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_ext.sqlite");

        let record = UsnRecord {
            mft_entry: 100,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 100,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason: UsnReason::FILE_CREATE,
            filename: "noextension".into(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        };
        let resolved = vec![ResolvedRecord {
            record,
            full_path: ".\\noextension".into(),
            parent_path: ".".into(),
            source: crate::rewind::RecordSource::Allocated,
        }];

        export_sqlite(&db_path, &resolved, None).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let ext: String = conn
            .query_row("SELECT Extension FROM USNJRNL_FullPaths", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            ext, "",
            "File without extension should have empty Extension"
        );
    }
}
