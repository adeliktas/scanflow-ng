# scanflow

[![Crates.io](https://img.shields.io/crates/v/scanflow.svg)](https://crates.io/crates/scanflow)
[![Crates.io](https://img.shields.io/crates/v/scanflow-cli.svg)](https://crates.io/crates/scanflow-cli)
[![API Docs](https://docs.rs/scanflow/badge.svg)](https://docs.rs/scanflow)
[![Build and test](https://github.com/h33p/scanflow/actions/workflows/build.yml/badge.svg)](https://github.com/h33p/scanflow/actions/workflows/build.yml)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## A comprehensive memory scanning library

scanflow boasts a feature set similar to the likes of CheatEngine, with a
command line interface **and an MCP server** for AI agents. Utilizing
[memflow](https://crates.io/crates/memflow), scanflow works in a wide range of
situations - from virtual machines, to dedicated DMA hardware. With
performance at its forefront, scanflow should be able to achieve revolutionary
memory scan speeds.

## Workspace layout

This repository (`scanflow-ng`) is the modernized next-generation of scanflow:

| Crate | Description |
|-------|-------------|
| `scanflow` | The core library. A typed, IO-free `Session<T>` API over all scanners (value scanner, pointer map, sigmaker, disassembler). Returns structured results — no `println!`. |
| `scanflow-cli` | Human-facing CLI. Interactive REPL (rustyline, with up/down arrow history) **and** one-shot subcommands (`scan`, `sig`, `offset-scan`, ...), both built on `Session`. |
| `scanflow-mcp` | An [MCP](https://modelcontextprotocol.io) server (stdio) exposing scanflow to AI agents via the official Rust SDK (`rmcp`). Multi-session, 18 tools. |

All scanning logic lives in `scanflow::Session`; the CLI and MCP server are
thin fronts that call `Session` methods and format the output.

## Setting up the CLI

1. Install the CLI:

```
cargo install scanflow-cli
```

2. Optionally enable ptrace for the binary (for use with qemu):

```
sudo setcap 'CAP_SYS_PTRACE=ep' ~/.cargo/bin/scanflow-cli
```

3. Set up connectors using [memflowup](https://github.com/memflow/memflowup)

4. Drop into the interactive REPL (up/down arrow history, persisted to
   `~/.scanflow_history`):

```
scanflow-cli -c qemu_procfs -p svchost.exe
```

Or run a one-shot subcommand:

```
scanflow-cli -c qemu_procfs -p svchost.exe sig "4D 85 C0 ? ? ? 4D 8B 40 ?"
scanflow-cli -c qemu_procfs -p svchost.exe scan i64 42
scanflow-cli --help
scanflow-cli offset-scan --help
```

### REPL commands (default mode)

```
quit | q                help | h [cmd]
reset | r               reinterpret | ri {type} [{len}]
add | a {addr}          remove | rm {idx}
print | p               write | wr {idx/*} {o/c} {value}
sig | sg {pattern}      pointer_map | pm
globals | g [module]    sigmaker | s {addr}
offset_scan | os {y/n} {lrange} {urange} {max_depth} [{filter}]
```

Anything not in this list is interpreted as a scan input: `{type} {value}`
for a first scan (e.g. `i64 64`), or just `{value}` to filter the current
matches. Available types: `str, str_utf16, i8, u8, i16, u16, i32, u32, i64,
u64, i128, u128, f32, f64`.

## Setting up the MCP server (for AI agents)

`scanflow-mcp` speaks MCP over stdio, so any MCP-compatible client (Claude
Desktop, etc.) can drive scanflow. Build and run:

```
cargo build -p scanflow-mcp
./target/debug/scanflow-mcp
```

Wire it into Claude Desktop by adding to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scanflow": {
      "command": "/absolute/path/to/scanflow-mcp",
      "env": {}
    }
  }
}
```

The server exposes 18 tools covering the full scanflow workflow — see
[`docs/MCP-TOOLS.md`](docs/MCP-TOOLS.md) for the complete reference. Typical
agent flow:

1. `attach_process` (or `attach_view`) → get a `session_id`
2. `scan_value` / `filter_value` / `sig_scan` to find memory
3. `get_matches` / `read_memory` to inspect it
4. `offset_scan` / `sigmaker` / `collect_globals` to build pointer chains &
   signatures

Multiple sessions are supported concurrently (Q2). HTTP/SSE transport can be
bridged later with tools like `mcporter` / `supergateway`.

## Background

This tool came to be as a result of a YouTube series detailing memflow and
various memory scanning techniques. The original repo is
[`h33p/scanflow`](https://github.com/h33p/scanflow); `scanflow-ng` modernizes it
(edition 2021, clap 4, rmcp MCP, memchr-backed sig scan, structured `Session`
API) while preserving the original scanner logic.

See [`PLAN.md`](PLAN.md) for the full modernization plan and design notes.

## License

MIT (see [LICENSE](LICENSE)).