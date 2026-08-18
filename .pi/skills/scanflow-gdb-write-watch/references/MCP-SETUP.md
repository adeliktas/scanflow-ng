# MCP-SETUP — wiring scanflow-mcp + openmcpgdb into pi

The "find what writes" workflow relies on two MCP servers registered as
**defaults** in pi (loaded at startup), plus the QEMU gdb stub. This documents
the one-time setup so a future agent can reproduce or repair it.

## 1. QEMU gdb stub (the trap source)

Add to the libvirt domain XML `/etc/libvirt/qemu/win10-stealth.xml`, inside
`<qemu:commandline>` (needs the `xmlns:qemu` namespace on `<domain>`):
```xml
<qemu:arg value='-gdb'/>
<qemu:arg value='tcp::7331'/>
```
- Do **not** add `-S` (that freezes the VM at boot; the `-S` you see in the
  running process is libvirt's own boot-freeze, which it auto-resumes).
- After editing, restart the domain (`virsh destroy`/`start` or `virsh reboot`
  won't pick up `<qemu:commandline>` changes — a full shutdown + start is
  needed for `qemu:arg` changes to take effect).
- Verify from the host: `ss -tlnp | grep 7331` should show `qemu-system-x86`
  listening. Connecting a gdb client is a separate step (see `gdb_watch.sh`).
- The QMP monitor socket (`-qmp unix:/tmp/qmp-win10-stealth.sock,server,nowait`)
  is used to manually resume the VM if a gdb session leaves it paused.

## 2. scanflow-mcp (process model + value scanner)

Built from this repo's `scanflow-mcp/` crate (v0.3.0), installed to a stable path:
```bash
cd <repo>
cargo install --path scanflow-mcp --locked --force
# -> ~/.cargo/bin/scanflow-mcp
```
Smoke-test (stdio):
```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
 | ~/.cargo/bin/scanflow-mcp
# expect: serverInfo scanflow-mcp 0.3.0, 18 tools
```
It exposes 18 tools (prefixed `scanflow_` by pi): `attach_process`, `attach_view`,
`list_processes`, `list_sessions`, `detach_session`, `scan_value`,
`filter_value`, `sig_scan`, `get_matches`, `read_memory`, `write_memory`,
`reset_session`, `set_type`, `list_modules`, `build_pointer_map`,
`collect_globals`, `sigmaker`, `offset_scan`. Multi-session (each session is an
`Arc<tokio::Mutex<AnySession>>`); process-vs-view selected at attach.

## 3. openmcpgdb (interactive gdb over MCP — optional, for non-time-critical use)

`openmcpgdb` drives the host `gdb` CLI over MI and exposes ~33 `gdb_*` tools
(`gdb_target_remote`, `gdb_custom`, `gdb_info_regs`, `gdb_full_backtrace`, …).
It's installed + wired into pi but **not used for the live watchpoint trigger**
(per-command IPC round-trips pause the VM too long — use `gdb_watch.sh` for
that). It's still useful for: freeing the stub (`gdb_custom {cmd:"detach"}`),
interactive stepping on a paused target, and reading state.

```bash
cargo install openmcpgdb --locked --force   # -> ~/.cargo/bin/openmcpgdb
mkdir -p ~/.config/scanflow-ng
cat > ~/.config/scanflow-ng/openmcpgdb.json <<'JSON'
{
  "gdb_path": "/usr/bin/gdb",
  "gdb_options": "--quiet",
  "codebase_dir": "/tmp",
  "executable_path": "/tmp/nonexistent",
  "mcp_server_name": "openmcpgdb",
  "mcp_server_url": "stdio://local",
  "display_lines_before_current": 7,
  "display_lines_after_current": 8,
  "display_backtrace": 50,
  "display_variable_list": 20,
  "display_join_current_code": false
}
JSON
```
Smoke-test (stdio):
```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
 | ~/.cargo/bin/openmcpgdb ~/.config/scanflow-ng/openmcpgdb.json
# expect: serverInfo rmcp, 33 tools
```

## 4. The gdb_watch.sh runtime helper

Copied into this skill at `../scripts/gdb_watch.sh`; a runtime copy lives at
`~/.config/scanflow-ng/gdb_watch.sh`. Either works. It needs host `gdb` and the
QEMU stub on `:7331` (overridable). See `../SKILL.md` Step 2 and
`PROCEDURE.md` §8.

## 5. Register both MCP servers as pi defaults

pi reads MCP servers at startup from `~/.config/mcp/mcp.json` (the
`pi-mcp-adapter` package's `GENERIC_GLOBAL_CONFIG_PATH`). Add `scanflow` and
`openmcpgdb` alongside any existing servers (e.g. `camoufox`):
```json
{
  "mcpServers": {
    "camoufox": { "...": "..." },
    "scanflow": {
      "command": "/home/adeliktas/.cargo/bin/scanflow-mcp",
      "args": [],
      "env": {}
    },
    "openmcpgdb": {
      "command": "/home/adeliktas/.cargo/bin/openmcpgdb",
      "args": ["/home/adeliktas/.config/scanflow-ng/openmcpgdb.json"],
      "env": {}
    }
  }
}
```
- **Restart pi** to load new servers (pi loads the server list once at startup).
- After restart, `mcp({})` should list `camoufox`, `scanflow`, `openmcpgdb`.
- A server shows `(not connected)` until first used; `mcp({connect:"scanflow"})`
  or `mcp({tool:"scanflow_..."})` connects it. Tool names are prefixed with the
  server name + `_` (e.g. `scanflow_scan_value`, `openmcpgdb_gdb_target_remote`).

## 6. ptrace capability (only if you use qemu_procfs / direct process memory)

For connectors that need ptrace (`qemu_procfs`), give the binary the capability
once (not needed for the `kvm` connector used in this workflow):
```bash
sudo setcap 'CAP_SYS_PTRACE=ep' ~/.cargo/bin/scanflow-mcp
```