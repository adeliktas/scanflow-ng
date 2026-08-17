//! scanflow-cli entry point.
//!
//! Parses arguments, optionally elevates privileges (unix), initializes
//! logging, builds the memflow inventory/chain, wraps the resulting process
//! or memory view in a [`scanflow::Session`], and dispatches either to the
//! interactive REPL or to a one-shot subcommand.

use std::process;

use clap::Parser;
use either::{Either, Left, Right};
use memflow::prelude::v1::*;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

mod cli;
mod commands;
mod render;
mod repl;

use cli::{log_level, Cli, Command};
use scanflow::Session;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.elevate {
        escalate_if_needed();
    }

    TermLogger::init(
        log_level(cli.verbose).to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .ok();

    let mut inventory = Inventory::scan();

    let chain = build_chain(&cli)?;

    match chain {
        Left(os_chain) => {
            let os = inventory.builder().os_chain(os_chain).build()?;
            let program = match cli.program.as_deref() {
                Some(p) => p,
                None => {
                    eprintln!("error: in OS mode a target program (-p/--program) or --pid must be supplied");
                    return Err(ErrorKind::ArgValidation.into());
                }
            };
            let process = open_process(os, program, cli.pid)?;
            let session = Session::for_process(process);
            run_process(session, cli.subcommand, cli.history_file)
        }
        Right(conn_chain) => {
            // View mode (raw physical memory). A target program can't be
            // opened here — if the user supplied -p, they meant process mode
            // and are missing an OS layer (e.g. --os win32). Error clearly
            // instead of silently dropping -p and scanning huge physical RAM.
            if cli.program.is_some() || cli.pid.is_some() {
                eprintln!(
                    "error: a target process ({} {}) was requested, but the chain resolves to a\n\
                     raw memory view, not an OS. To open a process by name you need an OS\n\
                     layer: add e.g. `--os win32`, or use an OS plugin (like `qemu_procfs`)\n\
                     as the connector.\n\
                     Example:  scanflow-cli -c kvm --os win32 -p {}",
                    cli.program
                        .as_deref()
                        .map(|n| format!("--program {n}"))
                        .unwrap_or_default(),
                    cli.pid.map(|p| format!("--pid {p}")).unwrap_or_default(),
                    cli.program.as_deref().unwrap_or("PROCESS"),
                );
                return Err(ErrorKind::ArgValidation.into());
            }
            let conn = inventory.builder().connector_chain(conn_chain).build()?;
            let view = conn.into_phys_view();
            let session = Session::for_view(view);
            run_view(session, cli.subcommand, cli.history_file)
        }
    }
}

/// Build either an OsChain (if both connectors and os entries resolve) or a
/// ConnectorChain (raw memory view). Mirrors the original `extract_args`.
/// The memflow chain builders consume `(index, &str)` pairs (the index is the
/// occurrence position among repeated args).
fn build_chain(cli: &Cli) -> Result<Either<OsChain<'_>, ConnectorChain<'_>>> {
    let conn_it = || {
        cli.connector
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.as_str()))
    };
    let os_it = || cli.os.iter().enumerate().map(|(i, s)| (i, s.as_str()));

    if let Ok(chain) = OsChain::new(conn_it(), os_it()) {
        return Ok(Left(chain));
    }
    ConnectorChain::new(conn_it(), os_it()).map(Right)
}

fn run_process<T>(
    mut session: Session<T>,
    sub: Option<Command>,
    history: Option<std::path::PathBuf>,
) -> Result<()>
where
    T: Process + MemoryView + Clone + Send + 'static,
{
    match sub.unwrap_or(Command::Repl) {
        Command::Repl => match history {
            Some(h) => repl::run_process_with_history(session, h),
            None => repl::run_process(session),
        },
        sub => commands::dispatch_process(&mut session, sub),
    }
}

fn run_view<T>(
    mut session: Session<T>,
    sub: Option<Command>,
    history: Option<std::path::PathBuf>,
) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    match sub.unwrap_or(Command::Repl) {
        Command::Repl => match history {
            Some(h) => repl::run_view_with_history(session, h),
            None => repl::run_view(session),
        },
        sub => commands::dispatch_view(&mut session, sub),
    }
}

/// Open a process from an OS instance, selecting by PID or by name.
///
/// - `pid = Some(p)` -> open that exact PID.
/// - `pid = None`, `program` matches exactly one process -> open it.
/// - `pid = None`, `program` matches several -> print all candidates (PID +
///   name + state) and return an error telling the user to re-run with
///   `--pid`, instead of silently grabbing the first/random one.
/// - `pid = None`, no match -> error.
pub(crate) fn open_process<O: Os>(
    mut os: O,
    program: &str,
    pid: Option<u32>,
) -> Result<O::IntoProcessType> {
    if let Some(pid) = pid {
        return os.into_process_by_pid(pid);
    }

    let infos = os.process_info_list()?;
    let matching: Vec<ProcessInfo> = infos
        .into_iter()
        .filter(|i| i.name.as_ref() == program)
        .collect();

    match matching.len() {
        0 => {
            eprintln!("error: no process named `{}` is running", program);
            Err(ErrorKind::ModuleNotFound.into())
        }
        1 => os.into_process_by_info(matching.into_iter().next().unwrap()),
        n => {
            eprintln!(
                "error: {} processes are named `{}`; re-run with --pid to pick one:",
                n, program
            );
            for m in &matching {
                eprintln!("  pid={} name={} state={:?}", m.pid, m.name, m.state);
            }
            Err(ErrorKind::ArgValidation.into())
        }
    }
}

/// Privilege escalation. Replaces the `sudo` crate: on unix, if not already
/// root, re-exec the current binary through `sudo`. On non-unix this is a no-op.
fn escalate_if_needed() {
    #[cfg(unix)]
    {
        unsafe {
            if libc::geteuid() == 0 {
                return;
            }
        }
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(_) => return,
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let status = process::Command::new("sudo").arg(&exe).args(&args).status();
        match status {
            Ok(s) if s.success() => process::exit(0),
            Ok(s) => process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("failed to re-exec via sudo: {}", e);
                process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        log::warn!("elevation not supported on this platform");
    }
}

#[cfg(test)]
mod tests {
    //! Tests for `open_process` process selection (unique name, ambiguous name,
    //! PID selection, not-found). Uses memflow's in-process `DummyOs`. Every
    //! dummy process is named "Dummy", so allocating two gives an ambiguous
    //! name.

    use super::open_process;
    use memflow::dummy::{DummyMemory, DummyOs};
    use memflow::prelude::v1::*;

    fn os_with_procs(n: usize) -> DummyOs {
        let mem = DummyMemory::new(size::mb(16));
        let mut os = DummyOs::new(mem);
        for _ in 0..n {
            os.alloc_process(size::mb(2), &[]);
        }
        os
    }

    #[test]
    fn unique_name_opens() {
        let os = os_with_procs(1);
        let res = open_process(os, "Dummy", None);
        assert!(res.is_ok(), "a single matching process should open");
    }

    #[test]
    fn ambiguous_name_errors() {
        let os = os_with_procs(3);
        let res = open_process(os, "Dummy", None);
        assert!(
            res.is_err(),
            "multiple same-named processes must error instead of grabbing one"
        );
    }

    #[test]
    fn pid_selection_opens() {
        let mem = DummyMemory::new(size::mb(16));
        let mut os = DummyOs::new(mem);
        let pid = os.alloc_process(size::mb(2), &[]);
        let res = open_process(os, "ignored-name", Some(pid));
        assert!(res.is_ok(), "selecting by exact PID should succeed");
    }

    #[test]
    fn not_found_errors() {
        let os = os_with_procs(1);
        let res = open_process(os, "does-not-exist", None);
        assert!(res.is_err(), "a non-matching name should error");
    }
}
