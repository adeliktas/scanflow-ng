//! One-shot subcommand handlers (the non-REPL CLI mode).
//!
//! Each handler takes a [`scanflow::Session`] and performs a single action,
//! rendering the result via [`crate::render`]. Used when the user invokes
//! `scanflow-cli scan ...`, `scanflow-cli sig ...`, etc. instead of dropping
//! into the REPL.

use std::time::Instant;

use memflow::prelude::v1::*;

use scanflow::session::WriteTarget;
use scanflow::Session;

use crate::cli::Command;
use crate::render;

/// Dispatch a subcommand against a full process session.
pub fn dispatch_process<T>(session: &mut Session<T>, sub: Command) -> Result<()>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    match sub {
        Command::Repl => unreachable!("repl is handled before dispatch"),
        Command::Scan { type_name, value } => {
            let res = session.scan_value(&type_name, &value)?;
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        Command::Filter { value } => {
            let res = session.filter_value(&value)?;
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        Command::Sig { pattern } => {
            let start = Instant::now();
            let res = session.sig_scan(&pattern)?;
            println!(
                "Found {} matches in {:.2}ms",
                res.count(),
                start.elapsed().as_secs_f64() * 1000.0
            );
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        Command::Read { addr, len } => {
            let data = session.read_memory(addr, len)?;
            render::print_hexdump(addr, &data, 16);
            Ok(())
        }
        Command::Write { idx, all, value } => {
            let target = if all {
                WriteTarget::All
            } else {
                WriteTarget::One(idx.ok_or(ErrorKind::InvalidArgument)?)
            };
            let n = session.write_value(target, &value)?;
            println!(
                "Write done ({} location{})",
                n,
                if n == 1 { "" } else { "s" }
            );
            Ok(())
        }
        Command::Print => {
            let rows = session.read_matches(render::MAX_PRINT)?;
            render::print_match_displays(&rows, session.matches().len());
            Ok(())
        }
        Command::Reset => {
            session.reset();
            Ok(())
        }
        Command::Modules => {
            let mods = session.list_modules()?;
            render::print_modules(&mods);
            Ok(())
        }
        Command::PointerMap => {
            let start = Instant::now();
            session.build_pointer_map()?;
            println!(
                "Pointer map built in {:.2}ms",
                start.elapsed().as_secs_f64() * 1000.0
            );
            Ok(())
        }
        Command::Globals { module } => {
            let start = Instant::now();
            let n = session.collect_globals(module.as_deref())?;
            println!(
                "Global variable references found: {:x} in {:.2}ms",
                n,
                start.elapsed().as_secs_f64() * 1000.0
            );
            Ok(())
        }
        Command::Sigmaker { addr } => {
            let sigs = session.sigmaker(addr)?;
            println!("Found signatures:");
            for sig in &sigs {
                println!("{}", sig);
            }
            Ok(())
        }
        Command::OffsetScan {
            use_disasm,
            lrange,
            urange,
            max_depth,
            filter,
        } => {
            let start = Instant::now();
            let matches = session.offset_scan(use_disasm, lrange, urange, max_depth, filter)?;
            println!(
                "Matches found: {} in {:.2}ms",
                matches.len(),
                start.elapsed().as_secs_f64() * 1000.0
            );
            render::print_offset_matches(&matches, render::MAX_PRINT);
            Ok(())
        }
    }
}

/// Dispatch a subcommand against a view-only session (no process commands).
pub fn dispatch_view<T>(session: &mut Session<T>, sub: Command) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    match sub {
        Command::Repl => unreachable!("repl is handled before dispatch"),
        Command::Scan { type_name, value } => {
            let res = session.scan_value(&type_name, &value)?;
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        Command::Filter { value } => {
            let res = session.filter_value(&value)?;
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        Command::Sig { pattern } => {
            let start = Instant::now();
            let res = session.sig_scan(&pattern)?;
            println!(
                "Found {} matches in {:.2}ms",
                res.count(),
                start.elapsed().as_secs_f64() * 1000.0
            );
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        Command::Read { addr, len } => {
            let data = session.read_memory(addr, len)?;
            render::print_hexdump(addr, &data, 16);
            Ok(())
        }
        Command::Write { idx, all, value } => {
            let target = if all {
                WriteTarget::All
            } else {
                WriteTarget::One(idx.ok_or(ErrorKind::InvalidArgument)?)
            };
            let n = session.write_value(target, &value)?;
            println!(
                "Write done ({} location{})",
                n,
                if n == 1 { "" } else { "s" }
            );
            Ok(())
        }
        Command::Print => {
            let rows = session.read_matches(render::MAX_PRINT)?;
            render::print_match_displays(&rows, session.matches().len());
            Ok(())
        }
        Command::Reset => {
            session.reset();
            Ok(())
        }
        // Process-only commands are rejected in view mode:
        Command::Modules
        | Command::PointerMap
        | Command::Globals { .. }
        | Command::Sigmaker { .. }
        | Command::OffsetScan { .. } => Err(ErrorKind::InvalidArgument.into()),
    }
}
