//! IDA-style byte-pattern signature scanning.
//!
//! Replaces the previous hand-rolled naive / Boyer-Moore-like implementations
//! in the CLI with a single [`memchr`]-backed matcher that is both faster and
//! battle-tested.
//!
//! Strategy: signatures are sequences of literal bytes and wildcards. We pick
//! the first literal byte as an *anchor*, use [`memchr`] (SIMD on x86_64 /
//! aarch64) to find candidate offsets where that anchor byte appears, then
//! verify the full masked pattern at each candidate. This is dramatically
//! faster than a naive O(n·m) scan when the anchor byte is rare in memory,
//! which is the common case for code signatures.

use memflow::prelude::v1::*;
use std::time::Instant;

/// A parsed byte signature: `Some(b)` = literal byte, `None` = wildcard.
pub type Pattern = Vec<Option<u8>>;

/// Parse an IDA-style signature string into a [`Pattern`].
///
/// Tokens are whitespace-separated. Each token is either:
/// - `?` or `??` for a wildcard byte, or
/// - exactly two hex digits (case-insensitive) for a literal byte.
///
/// Returns `None` if any token is malformed or the pattern is empty.
pub fn parse_pattern(input: &str) -> Option<Pattern> {
    let mut pattern: Pattern = Vec::new();
    for token in input.split_whitespace() {
        if token == "?" || token == "??" {
            pattern.push(None);
        } else if token.len() == 2 {
            let byte = u8::from_str_radix(token, 16).ok()?;
            pattern.push(Some(byte));
        } else {
            return None;
        }
    }
    if pattern.is_empty() {
        return None;
    }
    Some(pattern)
}

/// Compile a [`Pattern`] into a form optimized for repeated scanning.
pub struct CompiledPattern {
    /// Full pattern (Some = literal, None = wildcard).
    pattern: Pattern,
    /// Index of the first literal byte used as the memchr anchor.
    anchor: usize,
    /// (byte offset, expected byte) for every literal byte. Used for the
    /// final verification step after memchr finds an anchor candidate.
    literals: Vec<(usize, u8)>,
}

impl CompiledPattern {
    pub fn new(pattern: Pattern) -> Option<Self> {
        if pattern.is_empty() {
            return None;
        }
        let anchor = pattern
            .iter()
            .position(|b| b.is_some())
            // An all-wildcard pattern is technically valid but matches
            // everywhere; we still support it (anchor falls back to 0 and we
            // step by 1 with full verification).
            .unwrap_or(0);
        let literals = pattern
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.map(|v| (i, v)))
            .collect();
        Some(Self {
            pattern,
            anchor,
            literals,
        })
    }

    pub fn len(&self) -> usize {
        self.pattern.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }

    /// Find all match start addresses of this pattern inside `buf`, where
    /// `buf[0]` corresponds to `base_addr`.
    pub fn find_matches(&self, buf: &[u8], base_addr: Address) -> Vec<Address> {
        let mut matches = Vec::new();
        let pat_len = self.pattern.len();
        if buf.len() < pat_len {
            return matches;
        }

        let anchor = self.anchor;
        let anchor_byte = self.pattern[anchor];

        match anchor_byte {
            Some(byte) => {
                // memchr finds occurrences of the anchor byte; each candidate
                // pattern start is `pos - anchor`.
                let search_end = buf.len() - pat_len + anchor + 1;
                let mut from = 0;
                while from < search_end {
                    let found = match memchr::memchr(byte, &buf[from..search_end]) {
                        Some(p) => from + p,
                        None => break,
                    };
                    if found >= anchor {
                        let start = found - anchor;
                        if start + pat_len <= buf.len() && self.matches_at(buf, start) {
                            matches.push(base_addr + start as umem);
                        }
                    }
                    from = found + 1;
                }
            }
            None => {
                // All-wildcard pattern: match at every position (rare/edge case).
                for start in 0..=(buf.len() - pat_len) {
                    matches.push(base_addr + start as umem);
                }
            }
        }
        matches
    }

    /// Verify the full pattern against `buf` starting at `start`.
    #[inline]
    fn matches_at(&self, buf: &[u8], start: usize) -> bool {
        // Only check literal bytes; wildcards always pass.
        for (off, byte) in &self.literals {
            if buf[start + off] != *byte {
                return false;
            }
        }
        true
    }
}

/// Scan a single memory range buffer for a compiled pattern.
pub fn scan_range(
    view: &mut impl MemoryView,
    base: Address,
    size: umem,
    pattern: &CompiledPattern,
) -> Result<Vec<Address>> {
    let pat_len = pattern.len();
    if (size as usize) < pat_len {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    view.read_raw_into(base, &mut buf).data_part()?;
    Ok(pattern.find_matches(&buf, base))
}

/// Convenience: scan a set of memory ranges and report timing.
pub fn scan_ranges(
    view: &mut impl MemoryView,
    ranges: &[MemoryRange],
    pattern: &CompiledPattern,
) -> (Vec<Address>, std::time::Duration) {
    let start = Instant::now();
    let mut matches = Vec::new();
    for &CTup3(base, size, _) in ranges {
        if let Ok(found) = scan_range(view, base, size, pattern) {
            matches.extend(found);
        }
    }
    (matches, start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> CompiledPattern {
        CompiledPattern::new(parse_pattern(s).unwrap()).unwrap()
    }

    #[test]
    fn parses_literals_and_wildcards() {
        let pat = parse_pattern("4D 85 C0 ? ?? 4D").unwrap();
        assert_eq!(pat, vec![Some(0x4D), Some(0x85), Some(0xC0), None, None, Some(0x4D)]);
    }

    #[test]
    fn rejects_bad_tokens() {
        assert!(parse_pattern("").is_none());
        assert!(parse_pattern("4D 8").is_none()); // length != 2
        assert!(parse_pattern("4D ZZ").is_none()); // non-hex
        assert!(parse_pattern("? ? ?").is_some()); // all-wildcard is allowed at parse time
    }

    #[test]
    fn finds_literal_match() {
        let cp = p("AA BB");
        let buf = [0x00, 0xAA, 0xBB, 0xAA, 0xBB, 0x00];
        let m = cp.find_matches(&buf, Address::from(0x1000u64));
        assert_eq!(m, vec![Address::from(0x1001u64), Address::from(0x1003u64)]);
    }

    #[test]
    fn finds_with_wildcards() {
        let cp = p("AA ?? CC");
        let buf = [0xAA, 0x01, 0xCC, 0xAA, 0x02, 0xCC, 0xAA, 0x03, 0xDD];
        let m = cp.find_matches(&buf, Address::NULL);
        assert_eq!(m, vec![Address::from(0u64), Address::from(3u64)]);
    }

    #[test]
    fn no_false_positives_on_partial_match() {
        let cp = p("AA BB CC");
        let buf = [0xAA, 0xBB, 0xDD, 0xAA, 0xBB, 0xCC];
        let m = cp.find_matches(&buf, Address::NULL);
        assert_eq!(m, vec![Address::from(3u64)]);
    }

    #[test]
    fn pattern_too_long_for_buf() {
        let cp = p("AA BB CC DD EE");
        let buf = [0xAA, 0xBB];
        let m = cp.find_matches(&buf, Address::NULL);
        assert!(m.is_empty());
    }

    #[test]
    fn anchor_at_nonzero_offset() {
        // Wildcards first, then literal anchor — memchr still finds it.
        let cp = p("?? ?? AA");
        let buf = [0x01, 0x02, 0xAA, 0x03, 0x04, 0xAA];
        let m = cp.find_matches(&buf, Address::NULL);
        assert_eq!(m, vec![Address::from(0u64), Address::from(3u64)]);
    }
}