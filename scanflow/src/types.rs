//! Value type registry and structured scan results.
//!
//! This module centralizes the table of scannable value types (`str`, `i32`,
//! `u64`, `f32`, ...) and their parse/print functions. It also defines the
//! structured result types returned by [`crate::session::Session`] so that
//! frontends (CLI, MCP, ...) can render results however they like without the
//! library forcing `println!`s.

use std::convert::TryInto;

/// Function that formats a raw byte buffer as a typed value string.
pub type PrintFn = fn(&[u8]) -> Option<String>;
/// Function that parses a textual value into a raw byte buffer.
pub type ParseFn = fn(&str) -> Option<Box<[u8]>>;

/// A scannable value type descriptor.
///
/// Fields:
/// - `name`: identifier used on the CLI / MCP (e.g. `"i64"`).
/// - `size`: fixed byte size, if any. `None` for variable-length types
///   (`str`, `str_utf16`) whose size must be supplied per-call.
/// - `print`: formats bytes -> human-readable string.
/// - `parse`: parses text -> bytes.
pub struct ValueType {
    pub name: &'static str,
    pub size: Option<usize>,
    pub print: PrintFn,
    pub parse: ParseFn,
}

/// Table of all built-in scannable value types, in the same order and with the
/// same implementations as the original `scanflow-cli` `TYPES` table.
pub const VALUE_TYPES: &[ValueType] = &[
    ValueType {
        name: "str",
        size: None,
        print: |buf| Some(String::from_utf8_lossy(buf).into_owned()),
        parse: |value| Some(Box::from(value.as_bytes())),
    },
    ValueType {
        name: "str_utf16",
        size: None,
        print: |buf| {
            let mut vec = vec![];
            for w in buf.chunks_exact(2) {
                let s = u16::from_ne_bytes(w.try_into().unwrap());
                vec.push(s);
            }
            Some(String::from_utf16_lossy(&vec))
        },
        parse: |value| {
            let mut out = vec![];
            for v in value.encode_utf16() {
                out.extend(v.to_ne_bytes().iter().copied());
            }
            Some(out.into_boxed_slice())
        },
    },
    ValueType {
        name: "i128",
        size: Some(16),
        print: |buf| Some(format!("{}", i128::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<i128>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "i64",
        size: Some(8),
        print: |buf| Some(format!("{}", i64::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<i64>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "i32",
        size: Some(4),
        print: |buf| Some(format!("{}", i32::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<i32>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "i16",
        size: Some(2),
        print: |buf| Some(format!("{}", i16::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<i16>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "i8",
        size: Some(1),
        print: |buf| Some(format!("{}", i8::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<i8>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "u128",
        size: Some(16),
        print: |buf| Some(format!("{}", u128::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<u128>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "u64",
        size: Some(8),
        print: |buf| Some(format!("{}", u64::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<u64>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "u32",
        size: Some(4),
        print: |buf| Some(format!("{}", u32::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<u32>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "u16",
        size: Some(2),
        print: |buf| Some(format!("{}", u16::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<u16>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "u8",
        size: Some(1),
        print: |buf| Some(format!("{}", u8::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<u8>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "f64",
        size: Some(8),
        print: |buf| Some(format!("{}", f64::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<f64>().ok()?.to_ne_bytes())),
    },
    ValueType {
        name: "f32",
        size: Some(4),
        print: |buf| Some(format!("{}", f32::from_ne_bytes(buf.try_into().ok()?))),
        parse: |value| Some(Box::from(value.parse::<f32>().ok()?.to_ne_bytes())),
    },
];

/// Look up a value type by name.
pub fn find_type(name: &str) -> Option<&'static ValueType> {
    VALUE_TYPES.iter().find(|t| t.name == name)
}

/// Format a raw byte buffer as the given type. Returns `None` on type mismatch
/// or wrong buffer length.
pub fn print_value(buf: &[u8], typename: &str) -> Option<String> {
    find_type(typename).and_then(|t| (t.print)(buf))
}

/// Parse a textual value into bytes.
///
/// If `opt_typename` is `Some`, the value is parsed as that type (used for
/// filtering). If `None`, `input` must start with the type name followed by the
/// value, e.g. `"i64 42"`.
///
/// Returns `(bytes, type_name)`.
pub fn parse_input(input: &str, opt_typename: &Option<String>) -> Option<(Box<[u8]>, String)> {
    let (typename, value) = if let Some(t) = opt_typename {
        (t.as_str(), input)
    } else {
        let mut words = input.splitn(2, ' ');
        (words.next()?, words.next()?)
    };

    let b = (find_type(typename)?.parse)(value)?;
    Some((b, typename.to_string()))
}

/// Structured result of a scan operation.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    /// All matched addresses (not truncated — caller decides how many to show).
    pub matches: Vec<memflow::types::Address>,
    /// Whether this was an initial scan (`true`) or a filter pass (`false`).
    pub is_initial_scan: bool,
}

impl ScanResult {
    pub fn count(&self) -> usize {
        self.matches.len()
    }
}

/// A formatted match, as read back from memory.
#[derive(Debug, Clone)]
pub struct MatchDisplay {
    pub address: memflow::types::Address,
    pub value: String,
}

/// One entry of an offset-scan result: the target address together with the
/// pointer chain that leads to it.
#[derive(Debug, Clone)]
pub struct OffsetMatch {
    /// Final matched address (the value-scan hit).
    pub target: memflow::types::Address,
    /// Chain of `(address, offset)` pairs, outermost first.
    pub chain: Vec<(memflow::types::Address, isize)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_print_roundtrip_i64() {
        let (bytes, ty) = parse_input("i64 42", &None).unwrap();
        assert_eq!(ty, "i64");
        assert_eq!(bytes.len(), 8);
        let s = print_value(&bytes, "i64").unwrap();
        assert_eq!(s, "42");
    }

    #[test]
    fn parse_with_implicit_type() {
        let (bytes, ty) = parse_input("123", &Some("i32".to_string())).unwrap();
        assert_eq!(ty, "i32");
        assert_eq!(bytes.len(), 4);
        assert_eq!(print_value(&bytes, "i32").unwrap(), "123");
    }

    #[test]
    fn unknown_type_is_none() {
        assert!(parse_input("notatype 1", &None).is_none());
        assert!(find_type("notatype").is_none());
    }

    #[test]
    fn str_utf16_roundtrip() {
        let (bytes, ty) = parse_input("str_utf16 hi", &None).unwrap();
        assert_eq!(ty, "str_utf16");
        assert_eq!(bytes.len(), 4); // 2 code units * 2 bytes
        let s = print_value(&bytes, "str_utf16").unwrap();
        assert_eq!(s, "hi");
    }

    #[test]
    fn all_types_have_unique_names() {
        let mut names: Vec<&str> = VALUE_TYPES.iter().map(|t| t.name).collect();
        names.sort();
        let n = names.len();
        names.dedup();
        assert_eq!(names.len(), n, "duplicate value type names in table");
    }
}