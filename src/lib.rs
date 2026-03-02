//! NTFS USN Journal parser with full path reconstruction via journal rewind.
//!
//! Implements the CyberCX "Rewind" algorithm for complete path resolution,
//! even when MFT entries have been reallocated. Also provides direct binary
//! parsing of $UsnJrnl:$J (V2/V3/V4), $MFT correlation, $MFTMirr comparison,
//! and $LogFile gap detection.

pub mod usn;
pub mod mft;
pub mod rewind;
pub mod logfile;
pub mod mftmirr;
pub mod output;
pub mod analysis;
pub mod correlation;
pub mod rules;
pub mod refs;
pub mod monitor;
