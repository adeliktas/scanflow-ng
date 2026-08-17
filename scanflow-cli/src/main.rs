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
            let program = cli
                .program
                .as_deref()
                .expect("in OS mode a target program (-p/--program) must be supplied");
            let os = inventory.builder().os_chain(os_chain).build()?;
            let process = os.into_process_by_name(program)?;
            let session = Session::for_process(process);
            run_process(session, cli.subcommand, cli.history_file)
        }
        Right(conn_chain) => {
            let conn = inventory.builder().connector_chain(conn_chain).build()?;
            let view = conn.into_phys_view();
            let session = Session::for_view(view);
            run_view(session, cli.subcommand)
        }
    }
}

/// Build either an OsChain (if both connectors and os entries resolve) or a
/// ConnectorChain (raw memory view). Mirrors the original `extract_args`.
/// The memflow chain builders consume `(index, &str)` pairs (the index is the
/// occurrence position among repeated args).
fn build_chain(cli: &Cli) -> Result<Either<OsChain, ConnectorChain>> {
    let conn_it = || cli.connector.iter().enumerate().map(|(i, s)| (i, s.as_str()));
    let os_it = || cli.os.iter().enumerate().map(|(i, s)| (i, s.as_str()));

    if let Ok(chain) = OsChain::new(conn_it(), os_it()) {
        return Ok(Left(chain));
    }
    ConnectorChain::new(conn_it(), os_it()).map(Right)
}

fn run_process<T>(mut session: Session<T>, sub: Option<Command>, history: Option<std::path::PathBuf>) -> Result<()>
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

fn run_view<T>(mut session: Session<T>, sub: Option<Command>) -> Result<()>
where
    T: MemoryView + Clone + Send + 'static,
{
    match sub.unwrap_or(Command::Repl) {
        Command::Repl => repl::run_view(session),
        sub => commands::dispatch_view(&mut session, sub),
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
        let status = process::Command::new("sudo")
            .arg(&exe)
            .args(&args)
            .status();
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