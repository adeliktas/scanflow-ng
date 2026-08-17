//! Interactive REPL frontend, built on [`rustyline`].
//!
//! Provides up/down arrow command history (persisted to `~/.scanflow_history`
//! by default, overridable via `--history-file`), line editing, and a short
//! help system. All scanning work is delegated to [`scanflow::Session`]; this
//! module only parses input and renders output.
//!
//! Two entry points mirror the two session kinds:
//! - [`run_process`] for `T: Process + MemoryView + Clone` (full command set),
//! - [`run_view`] for `T: MemoryView + Clone` (view-only subset).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use memflow::prelude::v1::*;

use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{Completer, Editor, Helper, Highlighter, Hinter, Validator};

use scanflow::session::WriteTarget;
use scanflow::Session;

use crate::render;

/// A simple command-name completer for the REPL.
#[derive(Completer, Helper, Highlighter, Hinter, Validator)]
struct ReplHelper;

/// Entry point for the full process-mode REPL.
pub fn run_process<T>(session: Session<T>) -> Result<()>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    run_loop_process(session, default_history_path())
}

/// Entry point for the view-mode REPL (no process-only commands).
pub fn run_view<T>(session: Session<T>) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    run_loop_view(session, default_history_path())
}

/// Entry point with an explicit history file path (used by `--history-file`).
pub fn run_process_with_history<T>(session: Session<T>, history: PathBuf) -> Result<()>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    run_loop_process(session, history)
}

pub fn run_view_with_history<T>(session: Session<T>, history: PathBuf) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    run_loop_view(session, history)
}

fn default_history_path() -> PathBuf {
    let mut p = dirs_or_home();
    p.push(".scanflow_history");
    p
}

fn dirs_or_home() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h);
    }
    PathBuf::from(".")
}

fn run_loop_process<T>(mut session: Session<T>, history: PathBuf) -> Result<()>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    let mut rl = new_editor()?;
    let _ = rl.load_history(&history);
    loop {
        let prompt = build_prompt(&session);
        let line = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(line);
        let (cmd, args) = split_cmd(line);
        match handle_process_cmd(&mut session, cmd, args)? {
            Handled::Quit => break,
            Handled::Continue => {}
            Handled::Fallthrough => {
                handle_view_cmd(&mut session, cmd, args)?;
            }
        }
    }
    let _ = rl.save_history(&history);
    Ok(())
}

fn run_loop_view<T>(mut session: Session<T>, history: PathBuf) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    let mut rl = new_editor()?;
    let _ = rl.load_history(&history);
    loop {
        let prompt = build_prompt(&session);
        let line = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(line);
        let (cmd, args) = split_cmd(line);
        // View mode: no builtin quit/help path through process handler; check
        // builtins directly, then the shared view command handler.
        match handle_builtin(&mut session, cmd, args, false) {
            Handled::Quit => break,
            Handled::Continue => {}
            Handled::Fallthrough => {
                handle_view_cmd(&mut session, cmd, args)?;
            }
        }
    }
    let _ = rl.save_history(&history);
    Ok(())
}

fn new_editor() -> Result<Editor<ReplHelper, DefaultHistory>> {
    let mut rl = Editor::new().map_err(|_| ErrorKind::UnableToReadFile)?;
    rl.set_helper(Some(ReplHelper));
    Ok(rl)
}

/// Result of a process-only command dispatch.
enum Handled {
    /// Command was recognized and handled (process-only path).
    Continue,
    /// Caller should fall through to the shared view-command handler.
    #[allow(dead_code)]
    Fallthrough,
    /// Quit the REPL.
    Quit,
}

fn build_prompt<T>(session: &Session<T>) -> String
where
    T: MemoryView,
{
    let mut p = String::new();
    if let Some(t) = session.typename() {
        p.push('[');
        p.push_str(t);
        p.push_str("] ");
    }
    p.push_str("scanflow@");
    p.push_str(session.target_name());
    p.push_str(" >> ");
    p
}

fn split_cmd(line: &str) -> (&str, &str) {
    let mut toks = line.splitn(2, ' ');
    (toks.next().unwrap_or(""), toks.next().unwrap_or(""))
}

/// Built-in commands + help. Returns true if `cmd` is a built-in
/// (quit/help/handled here); false to let the caller try scan input.
fn handle_builtin<T>(session: &mut Session<T>, cmd: &str, args: &str, is_process: bool) -> Handled
where
    T: MemoryView,
{
    match cmd {
        "quit" | "q" => return Handled::Quit,
        "help" | "h" => {
            print_help(args, is_process);
            return Handled::Continue;
        }
        _ => {}
    }
    let _ = session;
    Handled::Fallthrough
}

/// View-capable commands shared by both process and view REPLs. Also handles
/// the "anything not a command is a scan input" fallback.
fn handle_view_cmd<T>(session: &mut Session<T>, cmd: &str, args: &str) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    match cmd {
        "reset" | "r" => {
            session.reset();
            Ok(())
        }
        "reinterpret" | "ri" => {
            let mut split = args.split_whitespace();
            let type_name = match split.next() {
                Some(t) => t,
                None => return Err(ErrorKind::InvalidArgument.into()),
            };
            let len = split.next().and_then(|s| s.parse::<usize>().ok());
            session.set_type(type_name, len)
        }
        "add" | "a" => {
            let addr =
                u64::from_str_radix(args.trim(), 16).map_err(|_| ErrorKind::InvalidArgument)?;
            session.add_match(addr.into());
            Ok(())
        }
        "remove" | "rm" => {
            let idx = args
                .trim()
                .parse::<usize>()
                .map_err(|_| ErrorKind::InvalidArgument)?;
            session.remove_match(idx)
        }
        "print" | "p" => {
            let rows = session.read_matches(render::MAX_PRINT)?;
            render::print_match_displays(&rows, session.matches().len());
            Ok(())
        }
        "write" | "wr" => handle_write(session, args),
        "sig" | "sg" => {
            let start = Instant::now();
            let res = session.sig_scan(args)?;
            let dur = start.elapsed();
            println!(
                "Found {} matches in {:.2}ms",
                res.count(),
                dur.as_secs_f64() * 1000.0
            );
            render::print_scan_result(&res, render::MAX_PRINT);
            Ok(())
        }
        _ => {
            // Not a command: interpret as a scan/filter input.
            handle_scan_input(session, cmd, args)
        }
    }
}

/// Process-only commands (pointer_map, globals, sigmaker, offset_scan).
/// Returns `Handled::Continue` if it recognized the command, else
/// `Handled::Fallthrough` so the caller tries the shared view handler.
fn handle_process_cmd<T>(session: &mut Session<T>, cmd: &str, args: &str) -> Result<Handled>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    let h = handle_builtin(session, cmd, args, true);
    match h {
        Handled::Quit => return Ok(Handled::Quit),
        Handled::Continue => return Ok(Handled::Continue),
        Handled::Fallthrough => {}
    }

    match cmd {
        "pointer_map" | "pm" => {
            let start = Instant::now();
            session.build_pointer_map()?;
            println!(
                "Pointer map built in {:.2}ms",
                start.elapsed().as_secs_f64() * 1000.0
            );
            Ok(Handled::Continue)
        }
        "globals" | "g" => {
            let start = Instant::now();
            let module = if args.trim().is_empty() {
                None
            } else {
                Some(args.trim())
            };
            let n = session.collect_globals(module)?;
            println!(
                "Global variable references found: {:x} in {:.2}ms",
                n,
                start.elapsed().as_secs_f64() * 1000.0
            );
            Ok(Handled::Continue)
        }
        "sigmaker" | "s" => {
            let addr =
                u64::from_str_radix(args.trim(), 16).map_err(|_| ErrorKind::InvalidArgument)?;
            let sigs = session.sigmaker(addr.into())?;
            println!("Found signatures:");
            for sig in &sigs {
                println!("{}", sig);
            }
            Ok(Handled::Continue)
        }
        "offset_scan" | "os" => {
            handle_offset_scan(session, args)?;
            Ok(Handled::Continue)
        }
        _ => Ok(Handled::Fallthrough),
    }
}

fn handle_offset_scan<T>(session: &mut Session<T>, args: &str) -> Result<()>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    let mut it = args.split_whitespace();
    let use_di = it.next().ok_or(ErrorKind::InvalidArgument)?;
    let use_disasm = use_di == "y";
    let lrange: usize = it
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(ErrorKind::InvalidArgument)?;
    let urange: usize = it
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(ErrorKind::InvalidArgument)?;
    let max_depth: usize = it
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(ErrorKind::InvalidArgument)?;
    let filter = it
        .next()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .map(Address::from);

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

/// `write {idx/*} {o/c} {value}` — single (`o`) or continuous (`c`) write.
fn handle_write<T>(session: &mut Session<T>, args: &str) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    let mut it = args.splitn(3, ' ');
    let idx = it.next().ok_or(ErrorKind::InvalidArgument)?;
    let mode = it.next().ok_or(ErrorKind::InvalidArgument)?;
    let value = it.next().ok_or(ErrorKind::InvalidArgument)?;

    let target = if idx == "*" {
        WriteTarget::All
    } else {
        WriteTarget::One(
            idx.parse::<usize>()
                .map_err(|_| ErrorKind::InvalidArgument)?,
        )
    };

    match mode {
        "o" => {
            let n = session.write_value(target, value)?;
            println!(
                "Write done ({} location{})",
                n,
                if n == 1 { "" } else { "s" }
            );
            Ok(())
        }
        "c" => continuous_write(session, target, value),
        _ => Err(ErrorKind::InvalidArgument.into()),
    }
}

/// Spawn a writer thread that keeps writing `value` until the user presses
/// Enter on the main thread.
fn continuous_write<T>(session: &mut Session<T>, target: WriteTarget, value: &str) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    // We need an independent clone of the memory object for the writer thread.
    let mut writer_mem = session.memory_mut().clone();
    let typename = session
        .typename()
        .ok_or(ErrorKind::Uninitialized)?
        .to_string();
    let ty = scanflow::types::find_type(&typename).ok_or(ErrorKind::InvalidArgument)?;
    let data = (ty.parse)(value).ok_or(ErrorKind::InvalidArgument)?;

    let matches: Vec<Address> = match target {
        WriteTarget::All => session.matches().to_vec(),
        WriteTarget::One(i) => vec![*session.matches().get(i).ok_or(ErrorKind::InvalidArgument)?],
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_w = stop.clone();

    println!(
        "Continuous write to {} address(es). Press Enter to stop...",
        matches.len()
    );
    let handle = std::thread::spawn(move || {
        while !stop_w.load(Ordering::Relaxed) {
            for &m in &matches {
                let _ = writer_mem.write_raw(m, data.as_ref());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    // Block on stdin until Enter. Use a blocking read outside rustyline.
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    println!("Write stopped");
    Ok(())
}

/// Scan/filter input fallback: `{type} {value}` for first scan, `{value}` to
/// filter when a type is already selected.
fn handle_scan_input<T>(session: &mut Session<T>, cmd: &str, args: &str) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    // Reconstruct the full line; the split dropped the space.
    let line = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{} {}", cmd, args)
    };

    if session.typename().is_some() {
        // Filter pass.
        let res = session.filter_value(&line)?;
        render::print_scan_result(&res, render::MAX_PRINT);
        Ok(())
    } else {
        // First scan: line must be "{type} {value}".
        let mut it = line.splitn(2, ' ');
        let type_name = it.next().ok_or(ErrorKind::InvalidArgument)?;
        let value = it.next().ok_or(ErrorKind::InvalidArgument)?;
        let res = session.scan_value(type_name, value)?;
        // Show typed values for the first scan, like the old `print` behavior.
        let rows = session.read_matches(render::MAX_PRINT)?;
        render::print_match_displays(&rows, res.count());
        Ok(())
    }
}

fn print_help(args: &str, is_process: bool) {
    if args.is_empty() {
        println!("Command reference:");
        println!("quit q              quit the CLI");
        println!("help h              show this help");
        println!("help h {{cmd}}       show longer help for a command");
        println!("reset r            reset all context state");
        println!("reinterpret ri {{type}} [{{len}}]  reinterpret matches as another type");
        println!("add a {{addr}}       manually add an address to matches");
        println!("remove rm {{idx}}    remove match by index");
        println!("print p            print found matches (typed)");
        println!("write wr {{idx/*}} {{o/c}} {{value}}  write values to matches");
        println!("sig sg {{pattern}}  scan memory for a byte pattern (IDA style)");
        if is_process {
            println!("pointer_map pm     build a pointer map");
            println!("globals g [{{module}}]  find global variables referenced by code");
            println!("sigmaker s {{addr}} find code signatures for an address");
            println!("offset_scan os {{y/n}} {{lrange}} {{urange}} {{max_depth}} [{{filter}}]");
        }
        println!();
        println!("Anything not in this list is interpreted as a scan input:");
        println!("  i64 64         (first scan: type + value)");
        println!("  42             (subsequent filter call)");
        println!("Available types: str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64");
    } else {
        println!("(no further help available for `{}`)", args);
    }
}
