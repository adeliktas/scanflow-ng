# scanflow-ng Modernization & MCP Integration Plan

> Status: **Phases 0–3 DONE. Phase 4 in progress.**
> Baseline tag: `v0.2.1-baseline` (original upstream snapshot, committed)
> Checkpoint tags: `phase1-core-refactor`, `phase2-cli`, `phase3-mcp`
> Methodology: PDCA (Plan-Do-Check-Act) with git versioning at each phase.

---

## Research findings (informed by live web research via camoufox/curl)

### R1. memflow thread-safety → `rayon_tlsctx` is still necessary
- `pub trait MemoryView: Send` (only `Send`, **not** `Sync`) — confirmed in
  `memflow/src/mem/memory_view/mod.rs:56`.
- `pub trait Process: Send` (only `Send`, not `Sync`) — confirmed in
  `memflow/src/os/process.rs:56`.
- Implication: you can **move** a memory object to another thread, but you
  cannot **share** `&T` across threads. The existing clone-per-thread pattern
  (`ThreadLocalCtx::new_locked(move || proc.clone())`) is the **correct** and
  idiomatic approach. memflow `Process`/`MemoryView` clones are cheap
  (Arc-wrapped connectors), so cloning per rayon worker is fine.
- **Decision:** keep `rayon_tlsctx` (latest 0.2.0). For MCP, sessions must be
  guarded by a `Mutex` (one mutable access at a time per session).

### R2. MCP SDK → use `rmcp` (official Rust MCP SDK)
- Crate: `rmcp` v3.1.2 (released 2026-08-07, very active).
- Repo: https://github.com/modelcontextprotocol/rust-sdk (official org).
- 20.6M total downloads, 10.4M recent. Implements MCP spec 2026-07-28.
- Features we need: `server` + `macros` (`#[tool]`, `#[prompt]`, `#[tool_router]`)
  + `transport-io` (stdio server) + `schemars` (JSON schema for tool args).
- API style: `#[tool_router] impl MyServer { #[tool(description=...)] async fn
  ...(&self, params: MyArgs) -> Result<CallToolResult, McpError> }` +
  `impl ServerHandler` + `MyServer.serve(stdio()).await`.
- Built on tokio. Fits the stdio-only requirement (Q6) perfectly; HTTP can be
  bridged later via `mcporter`/supergateway as the user noted.

### R3. Pattern matching → `memchr` + verify
- `memchr` v2.8.3, SIMD-optimized, 1.27B downloads, BurntSushi (trusted).
- Strategy for IDA-style wildcard signatures: locate the **first non-wildcard
  byte** in the pattern, use `memchr::find` to find candidate offsets, then
  verify the full masked pattern at each candidate. This replaces the
  hand-rolled `OptimizedPattern` and the O(n*m) naive loops in `sig_scan` /
  `sig_scan_debug` / `sig_scan_sequential`.
- **Decision:** remove `OptimizedPattern`, `sig_scan`, `sig_scan_debug`; keep
  one `sig_scan` implementation backed by `memchr`.

### R4. REPL history → `rustyline`
- `rustyline` v18.0.1 (45M downloads) — readline/linenoise port with up/down
  history, line editing, Ctrl-R search, emacs/vi modes. Minimal deps.
- `reedline` v0.50.0 (nushell) is fancier (syntax highlighting, menu-based
  history) but heavier.
- **Decision:** use `rustyline` for the REPL. Replaces the current
  `std::io::stdin().read_line` + `get_line` plumbing. Adds up/down arrow
  history out of the box.

### R5. Other dependency upgrades
- `clap` 3 → 4.6.6 (derive macros; needed for subcommand CLI + nicer help).
- `iced-x86` 1.10 → 1.21.0.
- `simplelog` 0.8 → latest; consider `tracing` for the MCP crate (rmcp uses it).
- `scan_fmt` 0.2.5 → **remove** (Q3). Only 2 usages; replace with manual
  `split_whitespace` + `parse`. Fewer deps.
- `sudo` 0.6 → keep (still maintained) or inline. Minor.
- `edition` 2018 → 2021.
- `dashmap` v6.2.1 for the MCP session store (concurrent map, Q2 multi-session).

---

## Architecture (target)

```
scanflow-ng/                       (workspace)
├── scanflow/                       core library (refactored, no I/O)
│   └── src/
│       ├── lib.rs
│       ├── session.rs              NEW — Session<T> holds ValueScanner,
│       │                                Disasm, PointerMap, type info, matches.
│       │                                Exposes typed methods returning
│       │                                structured results (no printing).
│       ├── value_scanner.rs        (cleanup + memchr optional)
│       ├── pointer_map.rs
│       ├── sigmaker.rs
│       ├── disasm.rs
│       ├── pbar.rs
│       ├── sig_scan.rs             NEW — memchr-backed wildcard pattern scan
│       ├── types.rs                NEW — ScanResult, OffsetMatch, ModuleInfo,
│       │                                value type table (moved from cli.rs)
│       └── error.rs                NEW — thiserror-based error type
│
├── scanflow-cli/                   human-facing binary
│   └── src/
│       ├── main.rs                 clap 4: subcommands + `repl` subcommand
│       ├── repl.rs                 NEW — rustyline REPL (thin over Session)
│       ├── commands.rs             NEW — subcommand handlers (thin over Session)
│       └── render.rs               NEW — pretty-print Session results
│
├── scanflow-mcp/                   NEW crate — MCP server (stdio)
│   └── src/
│       ├── main.rs                 tokio main, serve(stdio())
│       ├── server.rs               #[tool_router] server, ServerHandler impl
│       ├── tools.rs                #[tool] handlers (thin over SessionManager)
│       ├── session_mgr.rs          DashMap<SessionId, Arc<Mutex<Session>>>
│       └── args.rs                 serde+schemars param structs
│
└── .github/workflows/ci.yml        modernized CI
```

### Key design principle
All scanning logic lives in `scanflow::Session<T>` and returns **structured
data** (`ScanResult`, `Vec<OffsetMatch>`, etc.). Both `scanflow-cli` (REPL +
subcommands) and `scanflow-mcp` (MCP tools) are thin fronts that call
`Session` methods and format output for their respective consumers. No
`println!` inside the library.

---

## Phased implementation

### Phase 0 — Setup & safety net  ✅ DONE
- [x] `git init`, baseline commit, tag `v0.2.1-baseline`.
- [x] `.gitignore` (target/, etc.).

### Phase 1 — Core library refactor (`scanflow` crate)
- [ ] Add `error.rs` (thiserror), `types.rs` (move `Type` table + result structs).
- [ ] Add `session.rs` with `Session<T>` exposing typed methods:
      `scan_value`, `filter_value`, `sig_scan`, `build_pointer_map`,
      `offset_scan`, `sigmaker`, `collect_globals`, `read_memory`,
      `write_memory`, `list_modules`, `read_match`, `reset`, `add_match`,
      `remove_match`, `reinterpret`, `matches`, `set_typename`.
- [ ] Add `sig_scan.rs` (memchr-backed). Delete `sig_scan_debug`, old `sig_scan`,
      `OptimizedPattern` from `cli.rs`.
- [ ] Keep `value_scanner`/`pointer_map`/`sigmaker`/`disasm` logic, just wire
      them through `Session`.
- [ ] Bump edition 2018 → 2021; update deps (iced-x86 1.21, rayon-tlsctx 0.2).
- [ ] Unit tests for types + sig_scan parser/matcher.
- **Checkpoint:** `git commit` + tag `phase1-core-refactor`. Compile-only (CLI
  temporarily broken, fixed in Phase 2).

### Phase 2 — CLI modernization (`scanflow-cli` crate)
- [ ] clap 4 derive subcommands: `scan`, `filter`, `sig`, `read`, `write`,
      `modules`, `pointer-map`, `offset-scan`, `sigmaker`, `globals`, plus
      `repl` (default) and connection args (`-c`, `-o`, `-p`, `-e`, `-v`).
- [ ] `repl.rs`: rustyline REPL with up/down history, persistent history file
      (`~/.scanflow_history`), Tab completion for commands.
- [ ] `commands.rs`: subcommand handlers call `Session` methods.
- [ ] `render.rs`: pretty-print `ScanResult`/matches.
- [ ] Remove `scan_fmt`.
- **Checkpoint:** `git commit` + tag `phase2-cli`. Manual smoke test in REPL.

### Phase 3 — MCP server (`scanflow-mcp` crate)
- [ ] New crate; deps: `rmcp` (server+macros+transport-io+schemars), `tokio`,
      `dashmap`, `serde`, `schemars`, `scanflow` (path), `memflow`.
- [ ] `session_mgr.rs`: `SessionManager { inventory, sessions: DashMap }`.
      Methods: `create_session`, `list_sessions`, `get_session`, `drop_session`.
- [ ] `tools.rs`: `#[tool]` handlers — `list_processes`, `attach_process`,
      `list_sessions`, `detach_session`, `scan_value`, `filter_value`,
      `get_matches`, `read_memory`, `write_memory`, `sig_scan`, `list_modules`,
      `build_pointer_map`, `offset_scan`, `sigmaker`, `collect_globals`,
      `reset_session`.
- [ ] `server.rs`: `#[tool_router]` + `impl ServerHandler` (get_info with
      capabilities).
- [ ] `main.rs`: `tokio::main`, tracing to stderr, `serve(stdio())`.
- [ ] Long scans run via `tokio::task::spawn_blocking` (memflow is blocking),
      guarded by per-session `Mutex`.
- **Checkpoint:** `git commit` + tag `phase3-mcp`. Test with
  `npx @modelcontextprotocol/inspector`.

### Phase 4 — Testing, CI, docs
- [ ] Integration tests with memflow `dummy` connector.
- [ ] Modernize CI: `dtolnay/rust-toolchain`, `Swatinem/rust-cache`,
      `taiki-e/install-action`; drop deprecated `actions-rs`.
- [ ] `cargo fmt`, `cargo clippy --all-targets --all-features`, `cargo audit`.
- [ ] Update README (CLI + MCP usage, `claude_desktop_config.json` example).
- [ ] Add `docs/ARCHITECTURE.md`, `docs/MCP-TOOLS.md`.
- **Checkpoint:** `git commit` + tag `v0.3.0`.

---

## Open risks / things to verify during implementation
- `memflow::Inventory` Send/Sync: `Inventory::scan()` loads plugins; need to
  confirm it can be shared across sessions (likely fine — it's just a libloading
  registry). If not Sync, wrap in `Mutex`/clone-per-session.
- `scanflow` crate is generic over `T: MemoryView` — the MCP `Session` must be
  monomorphized. We'll fix `T` to a concrete memflow type alias
  (`OsInstanceArcBox<'static>` or the boxed process type) to keep the MCP
  crate dyn-safe. (Decision deferred to Phase 3 spike.)
- Long-running scans blocking tokio: mitigate with `spawn_blocking`.
- Progress bar (`pbar`) prints to stdout in REPL mode; in MCP mode we should
  disable it (feature flag) and instead report progress via MCP notifications
  (future enhancement).

---

## What I need from you before I start coding
1. Confirm the **crate layout** (3 crates: `scanflow`, `scanflow-cli`,
   `scanflow-mcp`) — OK?
2. Confirm **rustyline** (vs reedline) for the REPL — OK?
3. Confirm **memchr** for sig scanning — OK?
4. Confirm **rmcp** for MCP — OK?
5. Should the MCP server be a **separate binary** (`scanflow-mcp`) or a
   `--mcp` subcommand of `scanflow-cli`? (I lean separate binary — cleaner deps,
   MCP users don't pull rustyline, CLI users don't pull rmcp/tokio.)
6. Version target: bump to **0.3.0** for this work — OK?
7. Any platform priority? (Linux primary, Windows/macOS secondary, or all
   equal?)