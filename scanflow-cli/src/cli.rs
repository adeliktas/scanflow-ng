//! clap 4 argument definitions for `scanflow-cli`.
//!
//! Global connection options (`-c`, `-o`, `-p`, `-e`, `-v`) mirror the
//! original CLI. The [`Subcommand`] enum enumerates the one-shot operations
//! plus the `repl` (default) interactive mode.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};
use memflow::prelude::v1::*;

#[derive(Parser, Debug)]
#[command(
    name = "scanflow-cli",
    version,
    author,
    about = "memory scanner frontend CLI",
    long_about = "scanflow memory scanner CLI. Without a subcommand, drops into an interactive REPL."
)]
pub struct Cli {
    /// Increase verbosity (-v error, -vv warn, -vvv info, -vvvv debug, -vvvvv trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Connector chain entries (can be repeated). E.g. `-c qemu_procfs`.
    #[arg(short = 'c', long = "connector", action = ArgAction::Append, global = true)]
    pub connector: Vec<String>,

    /// OS chain entries (can be repeated). E.g. `-o win32`.
    #[arg(short = 'o', long = "os", action = ArgAction::Append, global = true)]
    pub os: Vec<String>,

    /// Elevate privileges via sudo before running (unix only).
    #[arg(short = 'e', long = "elevate", global = true)]
    pub elevate: bool,

    /// Target process name (required in OS mode; ignored in connector/view mode).
    #[arg(short = 'p', long = "program", global = true)]
    pub program: Option<String>,

    /// Attach to a specific process by PID instead of by name (OS mode).
    /// Use this when multiple processes share the same `--program` name.
    #[arg(short = 'P', long = "pid", global = true)]
    pub pid: Option<u32>,

    /// REPL history file. Defaults to `~/.scanflow_history`.
    #[arg(long = "history-file", global = true)]
    pub history_file: Option<PathBuf>,

    #[command(subcommand)]
    pub subcommand: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Drop into the interactive REPL (default when no subcommand is given).
    Repl,

    /// First-pass value scan: `scan {type} {value}`.
    Scan {
        /// Value type: str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64.
        type_name: String,
        /// The value to scan for.
        value: String,
    },

    /// Filter existing matches against a new value (requires a prior scan).
    Filter {
        /// New value to filter by.
        value: String,
    },

    /// Scan memory for an IDA-style byte pattern (space-separated hex / `?`).
    Sig {
        /// Pattern, e.g. `4D 85 C0 ? ? ? 4D 8B 40 ?`.
        pattern: String,
    },

    /// Read raw bytes at an address and print a hexdump.
    Read {
        /// Hex address, e.g. `0x7ff12345` or `7ff12345`.
        #[arg(value_parser = parse_address)]
        addr: Address,
        /// Number of bytes to read.
        #[arg(default_value_t = 64)]
        len: usize,
    },

    /// Write a value to one or all matches (single write).
    Write {
        /// Match index to write to. Mutually exclusive with --all.
        #[arg(conflicts_with = "all")]
        idx: Option<usize>,
        /// Write to all matches.
        #[arg(long = "all")]
        all: bool,
        /// Value to write (parsed with the current type).
        value: String,
    },

    /// Print the current matches as typed values.
    Print,

    /// Reset all session state (matches, pointer map, type).
    Reset,

    /// List loaded modules in the target process (process mode only).
    Modules,

    /// Build the pointer map (process mode only).
    PointerMap,

    /// Find global variables referenced by code (process mode only).
    Globals {
        /// Restrict the search to a single module. Omit for all modules.
        module: Option<String>,
    },

    /// Generate IDA-style code signatures for a global address (process mode only).
    Sigmaker {
        #[arg(value_parser = parse_address)]
        addr: Address,
    },

    /// Scan for pointer chains to the current matches (process mode only).
    OffsetScan {
        /// Use disassembler-found globals (`y`) or the whole pointer map (`n`).
        #[arg(long = "use-disasm", action = ArgAction::SetTrue)]
        use_disasm: bool,
        #[arg(long = "lrange")]
        lrange: usize,
        #[arg(long = "urange")]
        urange: usize,
        #[arg(long = "max-depth")]
        max_depth: usize,
        /// Optional hex filter address.
        #[arg(long = "filter", value_parser = parse_address_optional)]
        filter: Option<Address>,
    },
}

/// Parse a hex address. Accepts `0x...`, bare hex, or decimal.
pub fn parse_address(input: &str) -> std::result::Result<Address, String> {
    let s = input.trim().trim_start_matches("0x");
    u64::from_str_radix(s, 16)
        .or_else(|_| input.trim().parse::<u64>())
        .map(Address::from)
        .map_err(|e| format!("invalid address `{}`: {}", input, e))
}

pub fn parse_address_optional(input: &str) -> std::result::Result<Option<Address>, String> {
    if input.is_empty() {
        return Ok(None);
    }
    parse_address(input).map(Some)
}

/// Verbosity count -> log::Level.
pub fn log_level(verbose: u8) -> log::Level {
    match verbose {
        0 => log::Level::Error,
        1 => log::Level::Warn,
        2 => log::Level::Info,
        3 => log::Level::Debug,
        _ => log::Level::Trace,
    }
}
