use bitflags::bitflags;

bitflags! {
    /// Windows file attributes from USN records.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileAttributes: u32 {
        const READONLY            = 0x0000_0001;
        const HIDDEN              = 0x0000_0002;
        const SYSTEM              = 0x0000_0004;
        const DIRECTORY           = 0x0000_0010;
        const ARCHIVE             = 0x0000_0020;
        const DEVICE              = 0x0000_0040;
        const NORMAL              = 0x0000_0080;
        const TEMPORARY           = 0x0000_0100;
        const SPARSE_FILE         = 0x0000_0200;
        const REPARSE_POINT       = 0x0000_0400;
        const COMPRESSED          = 0x0000_0800;
        const OFFLINE             = 0x0000_1000;
        const NOT_CONTENT_INDEXED = 0x0000_2000;
        const ENCRYPTED           = 0x0000_4000;
        const INTEGRITY_STREAM    = 0x0000_8000;
        const VIRTUAL             = 0x0001_0000;
        const NO_SCRUB_DATA       = 0x0002_0000;
    }
}

impl std::fmt::Display for FileAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.iter_names().map(|(name, _)| name).collect();
        if names.is_empty() {
            write!(f, "0x{:x}", self.bits())
        } else {
            write!(f, "{}", names.join("|"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_attribute() {
        let a = FileAttributes::DIRECTORY;
        assert!(a.contains(FileAttributes::DIRECTORY));
        assert_eq!(a.to_string(), "DIRECTORY");
    }

    #[test]
    fn test_combined_attributes() {
        let a = FileAttributes::HIDDEN | FileAttributes::SYSTEM | FileAttributes::ARCHIVE;
        let s = a.to_string();
        assert!(s.contains("HIDDEN"));
        assert!(s.contains("SYSTEM"));
        assert!(s.contains("ARCHIVE"));
    }

    #[test]
    fn test_empty_attributes() {
        let a = FileAttributes::from_bits_retain(0);
        assert_eq!(a.to_string(), "0x0");
    }
}
