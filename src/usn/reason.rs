use bitflags::bitflags;

bitflags! {
    /// USN Journal reason flags indicating what operation triggered the journal entry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UsnReason: u32 {
        const DATA_OVERWRITE        = 0x0000_0001;
        const DATA_EXTEND           = 0x0000_0002;
        const DATA_TRUNCATION       = 0x0000_0004;
        const NAMED_DATA_OVERWRITE  = 0x0000_0010;
        const NAMED_DATA_EXTEND     = 0x0000_0020;
        const NAMED_DATA_TRUNCATION = 0x0000_0040;
        const FILE_CREATE           = 0x0000_0100;
        const FILE_DELETE           = 0x0000_0200;
        const EA_CHANGE             = 0x0000_0400;
        const SECURITY_CHANGE       = 0x0000_0800;
        const RENAME_OLD_NAME       = 0x0000_1000;
        const RENAME_NEW_NAME       = 0x0000_2000;
        const INDEXABLE_CHANGE      = 0x0000_4000;
        const BASIC_INFO_CHANGE     = 0x0000_8000;
        const HARD_LINK_CHANGE      = 0x0001_0000;
        const COMPRESSION_CHANGE    = 0x0002_0000;
        const ENCRYPTION_CHANGE     = 0x0004_0000;
        const OBJECT_ID_CHANGE      = 0x0008_0000;
        const REPARSE_POINT_CHANGE  = 0x0010_0000;
        const STREAM_CHANGE         = 0x0020_0000;
        const TRANSACTED_CHANGE     = 0x0040_0000;
        const INTEGRITY_CHANGE      = 0x0080_0000;
        const CLOSE                 = 0x8000_0000;
    }
}

impl std::fmt::Display for UsnReason {
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
    fn test_single_reason_display() {
        assert_eq!(UsnReason::FILE_CREATE.to_string(), "FILE_CREATE");
    }

    #[test]
    fn test_multiple_reasons_display() {
        let r = UsnReason::FILE_CREATE | UsnReason::CLOSE;
        let s = r.to_string();
        assert!(s.contains("FILE_CREATE"));
        assert!(s.contains("CLOSE"));
    }

    #[test]
    fn test_unknown_bits_display() {
        let r = UsnReason::from_bits_retain(0);
        assert_eq!(r.to_string(), "0x0");
    }

    #[test]
    fn test_rename_flags() {
        let r = UsnReason::RENAME_OLD_NAME | UsnReason::RENAME_NEW_NAME;
        let s = r.to_string();
        assert!(s.contains("RENAME_OLD_NAME"));
        assert!(s.contains("RENAME_NEW_NAME"));
    }
}
