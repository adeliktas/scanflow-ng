---
name: scanflow-gdb-write-watch
description: Find the instruction/function that WRITES to a memory address in a QEMU/KVM Windows (or Linux) guest — the CheatEngine "find what writes to this address" feature. Combines the scanflow MCP server (fast parallel value-scan to locate the address) with a minimal-freeze GDB hardware write-watchpoint driven through the QEMU gdb stub, so the VM pauses only for milliseconds (one DR trap + immediate resume). Use when you need to know what code writes a given memory location in a VM target and cannot tolerate a long VM freeze.
---

# scanflow-gdb-write-watch

Goal: given a value the user cares about in a process running inside a QEMU/KVM
guest, determine **which instruction writes it** — with near-zero VM pause.

Two cooperating pieces:
1. **scanflow MCP** — locates the address fast (scan value → filter → 1 match) and gives the module list.
2. **`scripts/gdb_watch.sh`** — arms a hardware write watchpoint on that address via the QEMU gdb stub and, on the next write, dumps all registers + disasm and detaches — all in-process inside one `gdb -batch`, so the freeze is only the unavoidable DR trap + immediate resume (~ms).

This is the **only** way to get "find what writes" here: memflow/scanflow has no
execution-control plane (its `CpuState` trait has `// breakpoints` / `// single-step` as
unimplemented TODOs), so scanflow can read/write memory and build pointers/signatures but
cannot trap on a write. The QEMU gdb stub + `KVM_SET_GUEST_DEBUG` provides the trap; gdb
adds the watchpoint logic. See `references/PROCEDURE.md` for the full reasoning.

## Prerequisites (one-time) — see references/MCP-SETUP.md
- Host `gdb` installed (`/usr/bin/gdb`).
- QEMU launched with a gdb stub: libvirt `<qemu:arg value='-gdb'/><qemu:arg value='tcp::7331'/>` (default port 7331). **No `-S`** — that flag is libvirt's normal "freeze during boot, then auto-`cont`" and is benign; do NOT add it yourself.
- `scanflow-mcp` and (optionally) `openmcpgdb` registered in pi's `~/.config/mcp/mcp.json`.
- `~/.config/scanflow-ng/gdb_watch.sh` present (or use the copy in this skill's `scripts/`).

## Workflow

### Step 1 — Locate the target address with scanflow (MCP)
1. `scanflow_list_processes` `{connectors, os}` → find the target **PID**.
   - The win32 layer **truncates names to 14 chars** and is **case-sensitive** (`rtmtutorial` ≠ `RTMTutorial-x8`). Attach by **PID**, not name.
   - If several processes share the (truncated) name, `scanflow_attach_process` with `pid` (it lists candidates on ambiguity).
2. `scanflow_attach_process` `{connectors, os, pid}` → `session_id`.
3. `scanflow_scan_value` `{session_id, type_name, value}` → N matches (common values like 100 give 1000+ — normal).
4. Ask the user to **change the value in the target** to a new number, then `scanflow_filter_value` `{session_id, value}` → repeat until **1 address** (e.g. `0x15edce8`).
5. `scanflow_list_modules` `{session_id}` → note the **module base** containing the target (e.g. `rtmtutorial-x86_64.exe` @ `0x100000000`). You'll need it in Step 3 to convert raw addresses to `module+offset`.

### Step 2 — Arm a minimal-freeze write watchpoint
1. Ensure the gdb stub (port 7331) is **free** — only one gdb client at a time:
   - If `openmcpgdb`'s gdb is attached, free it: `openmcpgdb_gdb_custom` `{cmd:"detach"}` (then the stub is free; the idle gdb process is harmless).
   - Check with `ss -tnp | grep 7331` — no `ESTAB` line = free.
2. Run the watch script (it backgrounds gdb and returns immediately):
   ```bash
   bash .pi/skills/scanflow-gdb-write-watch/scripts/gdb_watch.sh 0x15edce8 int 7331
   # args: <hex_addr> [type=int|short|char|long long] [port=7331]
   ```
   - It attaches → arms `Hardware watchpoint 1: *(<type>*)0x<addr>` → resumes the VM, **all in-process (sub-ms pause)**. gdb then blocks in the background waiting for the write.
3. Confirm it armed: `head /tmp/gdb_watch_<addr>.log` should show `Hardware watchpoint 1: *(int*)0x<addr>` and **no error**; the VM should still be `running` (verify via QMP — `references/PROCEDURE.md` has the one-liner).

### Step 3 — Trigger, read, interpret
1. Ask the user to **change the value again** in the target. The watchpoint fires; the in-process `commands`-block dumps all registers + `x/12i $rip-16`, deletes the watchpoint, `detach`s (VM resumes), and `quit`s — ~ms total.
2. Read `/tmp/gdb_watch_<addr>.log`. Look for the sentinel `=== WATCHPOINT DONE ===` (means it caught the writer and released the VM).
3. Interpret:
   - **`RIP`** is the instruction **AFTER** the write (x86 hardware watchpoints trap post-write). The writing instruction is the one just before `RIP` in the `x/12i $rip-16` block — a store/sub/add to `[reg+off]`.
   - **Verify the address**: the store is to `[reg+0xoff]`; compute `reg + off` from the register dump and confirm it equals the watched address (e.g. `rbx=0x15ed4f0`, `+0x7f8` → `0x15edce8` ✅).
   - **Convert to module+offset**: `addr - module_base` (from Step 1.5). E.g. `0x10002b4bc - 0x100000000 = 0x2b4bc` → `rtmtutorial-x86_64.exe + 0x2b4bc`.
   - **Confirm the process context**: `cr3` in the dump should be the target's CR3 (a false trigger from another process would have a different CR3 and RIP outside the module).

### Report to the user
- Writing instruction (asm + `module+offset`).
- Enclosing function entry (the `push rbp; mov rsp,rbp` prologue above the write).
- Struct offset of the field (the `[reg+off]`).
- What the write did (e.g. `value -= eax`, with the `eax` value).

## Notes / gotchas
- **Every gdb break pauses the VM — always resume.** The script auto-`detach`es on trigger. If you abort manually (`kill <gdb_pid>`) while the VM is paused, resume via QMP `cont` (one-liner in `references/PROCEDURE.md`).
- **Hardware watchpoints match the VA regardless of CR3** (x86 DRs aren't address-space tagged). If `RIP` is outside your target's module, it's a false trigger from another process — delete & re-arm, or just re-run and check CR3.
- **Never use single-step on a live game** — it traps on every instruction (~1000× slower). HW watchpoints have ~zero steady-state cost (checked in silicon); only the one trigger pause exists.
- **Anti-cheat / anti-VM**: the one unavoidable pause is the `#DB` trap at the writing instruction (~ms with this script). Truly zero would require an in-KVM `#DB` logger that records `RIP` and continues without surfacing to QEMU/gdb — a custom KVM feature, out of scope here. Do not leave a watchpoint armed longer than needed.
- **Max 4 hardware watchpoints** (x86 DR0–DR3). The script uses 1 and deletes it on trigger.

## Files
- `scripts/gdb_watch.sh` — the minimal-freeze watch script.
- `references/PROCEDURE.md` — full verbose context: why this design, perf reasoning, the memflow-vs-gdb split, the worked RTMTutorial example with all register/disasm output, troubleshooting.
- `references/MCP-SETUP.md` — installing & wiring `scanflow-mcp` + `openmcpgdb` into pi; the libvirt `-gdb` arg; the `openmcpgdb.json` config.