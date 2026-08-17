# scanflow-ng architecture

## Workspace

```
scanflow/        core library (no I/O)
scanflow-cli/    human REPL + subcommand CLI (rustyline + clap 4)
scanflow-mcp/    MCP server over stdio (rmcp)
```

## The `Session<T>` core

All scanning logic lives in `scanflow::Session<T>` (`scanflow/src/session.rs`),
generic over a memflow memory object `T`:

- `T: MemoryView + Clone` — the shared baseline (value scan, sig scan, raw
  read/write, read-back).
- `T: Process + MemoryView + Clone` — adds `build_pointer_map`,
  `collect_globals`, `sigmaker`, `offset_scan`, `list_modules`.

`Session` owns the scanners (`ValueScanner`, `Disasm`, `PointerMap`), the
selected value type, and the match list. Every method returns **structured**
data (`ScanResult`, `MatchDisplay`, `OffsetMatch`, ...) — never printing.
Frontends render the results.

`Funcs<T>` adapts `Session` to the two memory kinds: `Funcs::process()` (uses
`proc.info().name` + `mapped_mem_range_vec`) and `Funcs::view()` (uses metadata
+ a single range). Kept as `fn` pointers so `Session` stays cheap to store.

## sig_scan

`scanflow/src/sig_scan.rs` — IDA-style byte signatures with wildcards, backed
by [`memchr`](https://crates.io/crates/memchr). Strategy: find the first
non-wildcard *anchor* byte with `memchr` (SIMD), then verify the full masked
pattern at each candidate. Replaces the old naive / Boyer-Moore-like
implementations that lived in `scanflow-cli`.

## Thread-safety & multi-session (MCP)

Research (`PLAN.md` R1): memflow `MemoryView` and `Process` are `Send` but **not
`Sync``. So:

- Scanning uses `rayon` + `rayon_tlsctx` to clone the memory object per rayon
  worker (the original pattern, kept).
- The MCP server holds sessions in `DashMap<SessionId, Arc<tokio::sync::Mutex<
  AnySession>>>` — one tool call mutates a session at a time.
- `AnySession` is an enum of the two concrete memflow types
  (`IntoProcessInstanceArcBox`, `PhysicalMemoryView<ConnectorInstanceArcBox>`)
  since the generic `Session<T>` is not dyn-safe. Process-only dispatch methods
  return an error for the view variant.
- The memflow `Inventory` is behind a sync mutex (`builder()` takes `&mut`).

## Error handling

The library returns memflow's `Result<T, memflow::error::Error>` (re-exported as
`scanflow::error::Result`). The MCP server maps these to MCP error codes:
`INTERNAL_ERROR`, `RESOURCE_NOT_FOUND`, `INVALID_PARAMS`.

## CI

`.github/workflows/build.yml` builds and tests across linux/mac/windows (+ cross
aarch64), runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and
`cargo audit`. Uses `dtolnay/rust-toolchain`, `Swatinem/rust-cache`,
`taiki-e/install-action` (replaces the deprecated `actions-rs`).

## Testing

- `scanflow` unit tests: value-type roundtrips, sig-scan matcher (13).
- `scanflow/tests/dummy_session.rs`: end-to-end against memflow's in-process
  `DummyOs` — value scan, filter, readback, raw read/write, sig scan, reset
  (5). Note: the dummy's `mapped_mem_range` only yields *modules*, so tests
  write known values into a module's range before scanning.