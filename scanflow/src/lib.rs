//! # scanflow memory scanning library
//!
//! scanflow is a memory scanning library built for use with memflow - a versatile memory
//! introspection library. scanflow provides many ways to find data in memory. The typical workflow
//! looks like so:
//!
//! 1. Find wanted memory address using [`ValueScanner`] (or the typed [`Session::scan_value`]).
//!
//! 2. Find global variables that indirectly reference the match with [`PointerMap`]
//!    (via [`Session::offset_scan`]).
//!
//! 3. Create unique code signature that references one of the global variables with
//!    [`Sigmaker`] (via [`Session::sigmaker`]).
//!
//! The recommended entry point for new code is the [`Session`] struct, which provides a
//! typed, IO-free API over all scanners. It returns structured results ([`types::ScanResult`],
//! [`types::OffsetMatch`], ...) so that frontends (CLI, MCP server, ...) can format output
//! however they like.
//!
//! It may be worth trying out `scanflow-cli` - a command line interface built specifically
//! around this library, and `scanflow-mcp` - an MCP server exposing the same capabilities to
//! AI agents.

pub mod disasm;
pub mod error;
pub mod pbar;
pub mod pointer_map;
pub mod session;
pub mod sig_scan;
pub mod sigmaker;
pub mod types;
pub mod value_scanner;

pub use session::{Funcs, Session, WriteTarget};
pub use types::{MatchDisplay, OffsetMatch, ScanResult, ValueType, VALUE_TYPES};
