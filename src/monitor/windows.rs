//! Live USN Journal source via Windows `FSCTL_READ_USN_JOURNAL`.
//!
//! This module is only compiled on Windows (`cfg(target_os = "windows")`).

use anyhow::{Context, Result};

use super::JournalSource;

// ─── Win32 constants ────────────────────────────────────────────────────────

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900F4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x000900BB;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
const GENERIC_READ: u32 = 0x80000000;

// ─── Win32 FFI ──────────────────────────────────────────────────────────────

#[allow(non_snake_case)]
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const std::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *const std::ffi::c_void,
    ) -> isize;

    fn DeviceIoControl(
        hDevice: isize,
        dwIoControlCode: u32,
        lpInBuffer: *const u8,
        nInBufferSize: u32,
        lpOutBuffer: *mut u8,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *const std::ffi::c_void,
    ) -> i32;

    fn CloseHandle(hObject: isize) -> i32;
}

// ─── FSCTL structures ───────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadUsnJournalData {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_journal_id: u64,
    min_major_version: u16,
    max_major_version: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsnJournalDataV2 {
    usn_journal_id: u64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
    min_supported_major_version: u16,
    max_supported_major_version: u16,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn open_volume(drive_letter: char) -> Result<isize> {
    let path = format!("\\\\.\\{}:", drive_letter);
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null(),
        )
    };

    if handle == -1 {
        anyhow::bail!(
            "failed to open volume \\\\.\\{}: (run as Administrator)",
            drive_letter
        );
    }

    Ok(handle)
}

fn query_journal(handle: isize) -> Result<UsnJournalDataV2> {
    let mut journal_data = UsnJournalDataV2 {
        usn_journal_id: 0,
        first_usn: 0,
        next_usn: 0,
        lowest_valid_usn: 0,
        max_usn: 0,
        maximum_size: 0,
        allocation_delta: 0,
        min_supported_major_version: 0,
        max_supported_major_version: 0,
    };
    let mut bytes_returned: u32 = 0;

    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            &mut journal_data as *mut _ as *mut u8,
            std::mem::size_of::<UsnJournalDataV2>() as u32,
            &mut bytes_returned,
            std::ptr::null(),
        )
    };

    if ok == 0 {
        anyhow::bail!("FSCTL_QUERY_USN_JOURNAL failed");
    }

    Ok(journal_data)
}

// ─── WindowsJournalSource ───────────────────────────────────────────────────

/// Live journal source that reads from a Windows volume via FSCTL.
///
/// Requires Administrator privileges. Open with a drive letter:
/// ```no_run
/// let source = WindowsJournalSource::open('C').unwrap();
/// ```
pub struct WindowsJournalSource {
    handle: isize,
    journal_id: u64,
}

impl WindowsJournalSource {
    /// Open the USN journal on the given drive letter (e.g. `'C'`).
    pub fn open(drive_letter: char) -> Result<Self> {
        let handle = open_volume(drive_letter)?;
        let journal = query_journal(handle).context("failed to query USN journal")?;

        Ok(Self {
            handle,
            journal_id: journal.usn_journal_id,
        })
    }
}

impl Drop for WindowsJournalSource {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl JournalSource for WindowsJournalSource {
    fn read_from_usn(&mut self, start_usn: i64, buffer: &mut [u8]) -> Result<usize> {
        let input = ReadUsnJournalData {
            start_usn,
            reason_mask: 0xFFFF_FFFF,
            return_only_on_close: 0,
            timeout: 0,
            bytes_to_wait_for: 0,
            usn_journal_id: self.journal_id,
            min_major_version: 2,
            max_major_version: 3,
        };

        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                FSCTL_READ_USN_JOURNAL,
                &input as *const _ as *const u8,
                std::mem::size_of::<ReadUsnJournalData>() as u32,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut bytes_returned,
                std::ptr::null(),
            )
        };

        if ok == 0 {
            anyhow::bail!("FSCTL_READ_USN_JOURNAL failed");
        }

        // First 8 bytes of output are the next USN, followed by record data.
        let total = bytes_returned as usize;
        if total <= 8 {
            return Ok(0);
        }

        buffer.copy_within(8..total, 0);
        Ok(total - 8)
    }

    fn current_journal_id(&self) -> Result<u64> {
        Ok(self.journal_id)
    }
}
