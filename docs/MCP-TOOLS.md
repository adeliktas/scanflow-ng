# scanflow-mcp — MCP tool reference

`scanflow-mcp` exposes scanflow's memory-scanning capabilities to AI agents via
the [Model Context Protocol](https://modelcontextprotocol.io) over stdio, using
the official Rust SDK ([`rmcp`](https://crates.io/crates/rmcp)).

## Transport & runtime

- **Transport:** stdio only (rmcp `transport-io`). HTTP/SSE can be bridged with
  `mcporter` / `supergateway` if needed later.
- **Runtime:** tokio multi-threaded. Long scans run synchronously while holding
  the per-session `tokio::sync::Mutex`; this is acceptable for a single MCP
  client issuing sequential requests. (Future: report progress via MCP
  notifications.)
- **Thread safety:** memflow's `MemoryView` is `Send` but **not** `Sync`, so
  each session is guarded by a `tokio::sync::Mutex` — one tool call mutates a
  session at a time. The memflow `Inventory` is guarded by a sync mutex
  (`builder()` takes `&mut self`).

## Sessions

Every session-scoped tool takes a `session_id` (returned by `attach_process` /
`attach_view`, a UUIDv4). Two session kinds:

- **process** — full command set (value scan, pointer map, sigmaker, offset
  scan, modules, globals).
- **view** — raw physical memory view (value scan, sig scan, read/write only).
  Process-only tools return an MCP `INVALID_PARAMS` error on a view session.

## Tool reference

### Session lifecycle

| Tool | Args | Returns |
|------|------|---------|
| `attach_process` | `connectors: [String]`, `os: [String]`, `program: String` | `{ session_id, kind: "process", program }` |
| `attach_view` | `connectors: [String]`, `os: [String]` | `{ session_id, kind: "view" }` |
| `list_processes` | `connectors`, `os` | `[{ pid, name, state }]` |
| `list_sessions` | — | `[{ id, kind, target }]` |
| `detach_session` | `session_id` | `{ detached, session_id }` |

### Value scanning (process + view)

| Tool | Args | Returns |
|------|------|---------|
| `scan_value` | `session_id`, `type_name`, `value` | `{ count, is_initial_scan, type, first_matches[] }` |
| `filter_value` | `session_id`, `value` | (same as scan_value, `is_initial_scan: false`) |
| `get_matches` | `session_id`, `max?` (default 64) | `{ count, matches: [{ address, value }] }` |
| `set_type` | `session_id`, `type_name`, `len?` | `{ type, len }` |
| `reset_session` | `session_id` | `{ reset, session_id }` |

`type_name` ∈ `str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128,
f32, f64`. `len` is required only for unsized types (`str`, `str_utf16`).

### Raw memory (process + view)

| Tool | Args | Returns |
|------|------|---------|
| `read_memory` | `session_id`, `addr` (hex), `len` | `{ address, length, hex }` |
| `write_memory` | `session_id`, `addr` (hex), `data` (hex) | `{ written, address }` |

`addr` accepts `0x...` or bare hex. `data` accepts `"4D 5A"` or `"4D5A"`.

### Signatures (process + view)

| Tool | Args | Returns |
|------|------|---------|
| `sig_scan` | `session_id`, `pattern` | `{ count, is_initial_scan, first_matches[] }` |

`pattern` is IDA-style space-separated hex with `?`/`??` wildcards, e.g.
`"4D 85 C0 ? ? ? 4D 8B 40 ?"`. Backed by `memchr` for fast anchor-based search.

### Process-only (pointer chains & signatures)

| Tool | Args | Returns |
|------|------|---------|
| `list_modules` | `session_id` | `[{ name, base, size }]` |
| `build_pointer_map` | `session_id` | `{ pointer_map: "built", session_id }` |
| `collect_globals` | `session_id`, `module?` | `{ globals, session_id }` |
| `sigmaker` | `session_id`, `addr` (hex) | `{ signatures[] }` |
| `offset_scan` | `session_id`, `use_disasm`, `lrange`, `urange`, `max_depth`, `filter?` | `{ count, matches: [{ target, chain: [{ addr, off }] }] }` |

`offset_scan` finds pointer chains from binary globals (`use_disasm: true`) or
the whole pointer map (`false`) to the current matches. `filter` keeps only
chains starting at that hex address. `sigmaker` should be preceded by
`collect_globals`.

## Example agent exchange

```text
user:      "Find the address holding the integer 1337 in svchost.exe and show me a signature for it."
agent →    attach_process { connectors: ["qemu_procfs"], os: ["win32"], program: "svchost.exe" }
           → { session_id: "uuid-1", ... }
agent →    scan_value { session_id: "uuid-1", type_name: "i64", value: "1337" }
           → { count: 3, first_matches: [...], type: "i64" }
agent →    collect_globals { session_id: "uuid-1" }
           → { globals: 12345, ... }
agent →    sigmaker { session_id: "uuid-1", addr: "0x7ff..." }
           → { signatures: ["48 8B 05 ? ? ? ? ...", ...] }
```

## Claude Desktop config

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

## Smoke-testing locally

```bash
cargo build -p scanflow-mcp
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | ./target/debug/scanflow-mcp
```

`tools/list` returns all 18 tools. Or use the official inspector:

```
npx @modelcontextprotocol/inspector ./target/debug/scanflow-mcp
```