use std::io::{Read, Seek, SeekFrom};

use anyhow::Result;

use super::record::{UsnRecord, parse_usn_record_v2, parse_usn_record_v3};
use super::reason::UsnReason;

const BUF_SIZE: usize = 64 * 1024; // 64KB read buffer

/// Streaming iterator over USN records from a reader.
///
/// For multi-GB journals where loading everything into memory is impractical.
pub struct UsnJournalReader<R: Read + Seek> {
    reader: R,
    buf: Vec<u8>,
    buf_len: usize,
    buf_offset: usize,
    stream_pos: u64,
    total_size: u64,
    done: bool,
}

impl<R: Read + Seek> UsnJournalReader<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let total_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        Ok(Self {
            reader,
            buf: vec![0u8; BUF_SIZE],
            buf_len: 0,
            buf_offset: 0,
            stream_pos: 0,
            total_size,
            done: false,
        })
    }

    fn fill_buffer(&mut self) -> Result<bool> {
        if self.stream_pos >= self.total_size {
            self.done = true;
            return Ok(false);
        }

        // Move unconsumed data to front
        if self.buf_offset > 0 && self.buf_offset < self.buf_len {
            let remaining = self.buf_len - self.buf_offset;
            self.buf.copy_within(self.buf_offset..self.buf_len, 0);
            self.buf_len = remaining;
        } else {
            self.buf_len = 0;
        }
        self.buf_offset = 0;

        // Read more data
        let space = BUF_SIZE - self.buf_len;
        if space > 0 {
            let n = self.reader.read(&mut self.buf[self.buf_len..self.buf_len + space])?;
            if n == 0 {
                self.done = true;
                return Ok(self.buf_len > 0);
            }
            self.buf_len += n;
            self.stream_pos += n as u64;
        }

        Ok(true)
    }

    fn skip_zeros(&mut self) -> Result<bool> {
        loop {
            while self.buf_offset + 8 <= self.buf_len {
                let chunk = &self.buf[self.buf_offset..self.buf_offset + 8];
                if chunk != [0, 0, 0, 0, 0, 0, 0, 0] {
                    return Ok(true);
                }
                self.buf_offset += 8;
            }
            if !self.fill_buffer()? {
                return Ok(false);
            }
            if self.buf_len == 0 {
                return Ok(false);
            }
        }
    }
}

impl<R: Read + Seek> Iterator for UsnJournalReader<R> {
    type Item = Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Ensure we have data
        if self.buf_offset >= self.buf_len {
            match self.fill_buffer() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(e) => return Some(Err(e)),
            }
        }

        // Skip zero-filled regions
        match self.skip_zeros() {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => return Some(Err(e)),
        }

        // Need at least 8 bytes for record length + version
        if self.buf_offset + 8 > self.buf_len {
            match self.fill_buffer() {
                Ok(true) if self.buf_offset + 8 <= self.buf_len => {}
                _ => return None,
            }
        }

        let record_len = u32::from_le_bytes([
            self.buf[self.buf_offset],
            self.buf[self.buf_offset + 1],
            self.buf[self.buf_offset + 2],
            self.buf[self.buf_offset + 3],
        ]) as usize;

        if record_len < 8 || record_len > 65536 {
            self.buf_offset += 8;
            return self.next();
        }

        // Ensure we have the full record in buffer
        if self.buf_offset + record_len > self.buf_len {
            match self.fill_buffer() {
                Ok(true) if self.buf_offset + record_len <= self.buf_len => {}
                _ => {
                    self.buf_offset += 8;
                    return self.next();
                }
            }
        }

        let version = u16::from_le_bytes([
            self.buf[self.buf_offset + 4],
            self.buf[self.buf_offset + 5],
        ]);

        let record_data = &self.buf[self.buf_offset..self.buf_offset + record_len];
        let aligned = (record_len + 7) & !7;
        self.buf_offset += aligned;

        match version {
            2 => {
                match parse_usn_record_v2(record_data) {
                    Ok(r) if r.reason == UsnReason::CLOSE => self.next(),
                    Ok(r) => Some(Ok(r)),
                    Err(_) => self.next(),
                }
            }
            3 => {
                match parse_usn_record_v3(record_data) {
                    Ok(r) if r.reason == UsnReason::CLOSE => self.next(),
                    Ok(r) => Some(Ok(r)),
                    Err(_) => self.next(),
                }
            }
            _ => self.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_v2_record_bytes(entry: u64, seq: u16, parent: u64, parent_seq: u16, reason: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        let file_ref = entry | ((seq as u64) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        let parent_ref = parent | ((parent_seq as u64) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&100i64.to_le_bytes());
        let ts: i64 = 133500480000000000;
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_streaming_reader_basic() {
        let r = build_v2_record_bytes(100, 1, 5, 5, 0x100, "test.txt");
        let cursor = Cursor::new(r);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "test.txt");
    }

    #[test]
    fn test_streaming_reader_skips_zeros() {
        let mut data = vec![0u8; 4096];
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "found.txt"));
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "found.txt");
    }

    #[test]
    fn test_streaming_reader_multiple() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "a.txt"));
        data.extend_from_slice(&build_v2_record_bytes(200, 1, 100, 1, 0x200, "b.txt"));
        data.extend_from_slice(&build_v2_record_bytes(300, 1, 100, 1, 0x100, "c.txt"));
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 3);
    }
}
