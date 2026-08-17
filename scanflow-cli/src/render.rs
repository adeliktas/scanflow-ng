//! Pretty-printing helpers for structured scanflow results.
//!
//! The scanflow library returns structured data ([`ScanResult`], [`MatchDisplay`],
//! [`OffsetMatch`]); this module turns those into human-readable text for the
//! REPL and the subcommand CLI. Keeping rendering here (out of the library and
//! out of the REPL loop) makes it reusable and testable.

use memflow::prelude::v1::*;

use scanflow::MatchDisplay;
use scanflow::OffsetMatch;
use scanflow::ScanResult;

/// Maximum number of rows to print by default before truncating.
pub const MAX_PRINT: usize = 16;

/// Print a scan result summary + truncated match list.
pub fn print_scan_result(res: &ScanResult, max: usize) {
    let n = res.matches.len();
    println!("Matches found: {}", n);
    if n > max {
        println!("Printing first {} of {}", max, n);
    }
    for &addr in res.matches.iter().take(max) {
        println!("{:x}", addr);
    }
}

/// Print a list of [`MatchDisplay`] rows (address + typed value).
pub fn print_match_displays(rows: &[MatchDisplay], total_matches: usize) {
    println!("Matches found: {}", total_matches);
    let cap = rows.len().min(MAX_PRINT);
    if total_matches > MAX_PRINT {
        println!("Printing first {}", MAX_PRINT);
    }
    for row in rows.iter().take(cap) {
        println!("{:x}: {}", row.address, row.value);
    }
}

/// Print offset-scan matches: the pointer chain followed by the target.
pub fn print_offset_matches(matches: &[OffsetMatch], max: usize) {
    println!("Matches found: {}", matches.len());
    if matches.len() > max {
        println!("Printing first {} of {}", max, matches.len());
    }
    for m in matches.iter().take(max) {
        for (start, off) in &m.chain {
            print!("{:x} + ({}) => ", start, off);
        }
        println!("{:x}", m.target);
    }
}

/// Format a raw byte buffer as a hexdump (address + bytes), for `read_memory`.
pub fn print_hexdump(base: Address, data: &[u8], bytes_per_line: usize) {
    let bytes_per_line = if bytes_per_line == 0 { 16 } else { bytes_per_line };
    for (i, chunk) in data.chunks(bytes_per_line).enumerate() {
        let addr = base + (i * bytes_per_line) as umem;
        print!("{:x}: ", addr);
        for b in chunk {
            print!("{:02x} ", b);
        }
        println!();
    }
}

/// Print a module list (name, base, size).
pub fn print_modules(modules: &[ModuleInfo]) {
    for m in modules {
        println!("{:x}\t{:x}\t{}", m.base, m.size, m.name);
    }
}