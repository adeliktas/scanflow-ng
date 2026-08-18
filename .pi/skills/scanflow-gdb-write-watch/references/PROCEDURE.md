# PROCEDURE — Finding "what writes to an address" in a QEMU/KVM guest

This is the full, verbose companion to `../SKILL.md`. It captures the complete
context, reasoning, the worked example (RTMTutorial), all captured output, and
troubleshooting, so a future agent can reproduce and adapt the workflow.

---

## 1. The task

CheatEngine's **"Find out what writes to this address"** feature: you give it a
memory address holding a value you care about, it arms a write breakpoint, and
when the game's code writes that address it reports the **writing instruction
(RIP) and call stack**. We needed the same for a process running inside a
QEMU/KVM Windows guest (`RTMTutorial`), driven from the pi coding agent over
MCP, with **minimal VM freeze** (anti-VM/anti-cheat concern).

## 2. Why scanflow alone can't do it

scanflow is built on **memflow**, a *memory-introspection* library. It can
read/write memory, scan for values (parallel, fast), build pointer chains, and
generate code signatures — but it has **no execution-control plane**. memflow's
`CpuState` trait literally has breakpoints as unfinished TODOs:

```rust
// memflow/src/connector/cpu_state.rs
pub trait CpuState {
    // TODO:
    // read_register(s)
    // write_register(s)
    // pause          <- implemented
    // resume         <- implemented
    // single-step    <- TODO (not implemented)
    // breakpoints    <- TODO (not implemented)
    fn pause(&mut self);
    fn resume(&mut self);
}
```

So scanflow can find the address (scan → filter → 1 match) and make it reusable
(`offset_scan`, `sigmaker`), but it **cannot trap on a write**. That requires
guest execution control — a hardware watchpoint.

## 3. The two-layer solution (complementary, not redundant)

| | **scanflow (memflow)** | **QEMU gdb stub + gdb** |
|---|------------------------|------------------------|
| Process model (by name/PID, modules, VAD ranges) | ✅ win32 OS layer | ❌ raw machine memory, no process concept |
| "Scan whole process for i32=100" (parallel, fast) | ✅ rayon value scanner | ❌ no scanner |
| Filter to narrow matches | ✅ | ❌ |
| Pointer chains to static globals (`offset_scan`) | ✅ | ❌ |
| Code signatures (`sigmaker`) | ✅ | ❌ |
| **Breakpoints / watchpoints / "what writes"** | ❌ (TODO in memflow) | ✅ HW watchpoint → RIP |
| Registers / single-step / execution context | ❌ | ✅ |
| Throughput | batched connector, optimized | GDB-remote over TCP, verbose |

**Neither replaces the other.** The workflow uses both:
1. **scanflow** finds the address fast (scan → filter → 1 match) and gives the module base.
2. **gdb** arms a HW write watchpoint on that address via the QEMU stub, the VM runs free, the user changes the value, the watchpoint fires → gdb reports `RIP` + disasm.

## 4. KVM_SET_GUEST_DEBUG performance (the key concern)

The user's hard requirement: **do not hurt VM performance** (game FPS, anti-cheat
timing). `KVM_SET_GUEST_DEBUG` is a per-vCPU ioctl you issue **only while
debugging**; when not debugging you don't arm anything → zero cost. While armed:

| Mode | Overhead while active | Usable on a live game? |
|------|----------------------|------------------------|
| Hardware write breakpoint (DR0 = addr, write-trigger) | ~none — checked in silicon; KVM exits only on trigger | ✅ no FPS impact |
| Single-step (`RFLAGS.TF` / `SINGLESTEP`) | huge — trap on **every instruction** (~1000×) | ❌ micro-traces only |
| Software breakpoint (int3 patch) | only the patched instruction traps | ✅ |

So "find what writes to `0xADDR`" = one hardware write watchpoint = **no
measurable FPS impact while armed**, and only the one trigger pause. Nothing
persists when you stop. QEMU's `-gdb tcp::7331` stub implements write watchpoints
(`Z2`) via `KVM_SET_GUEST_DEBUG` — and gdb confirmed it: `Hardware watchpoint 1:
*(int*)0x15edce8` (a real DR watchpoint, not a software/single-step fallback).

## 5. QEMU gdb stub setup

Libvirt XML (`/etc/libvirt/qemu/win10-stealth.xml`), `<qemu:commandline>`:
```xml
<qemu:arg value='-gdb'/>
<qemu:arg value='tcp::7331'/>
```
- **No `-S`.** The `-S` you may see in the running `qemu` process is libvirt's
  normal "freeze CPU during setup, then auto-`cont`" boot sequence — benign and
  unrelated. Do **not** add `-S` yourself (it would leave the VM paused at boot).
- Enabling `-gdb` is ~free when idle: the stub just listens on a socket; with no
  client/breakpoint the vCPU runs normally. Connecting a client and `continue`ing
  also runs at full speed until a watchpoint triggers.
- The QEMU QMP monitor is at `unix:/tmp/qmp-win10-stealth.sock` — use it to
  manually resume the VM if a gdb session leaves it paused (see §11).

## 6. The golden rule: every gdb break pauses the VM — always resume

Any gdb attach/break/watchpoint-hit halts the guest. You **must** `continue` /
`detach` afterward. The `gdb_watch.sh` script auto-detaches on trigger. If you
abort manually while paused, resume via QMP `cont` (one-liner in §11).

## 7. Why a gdb script (not per-command MCP round-trips)

The first attempt used the **openmcpgdb** MCP server, issuing one `gdb_custom`
per action (`info_regs`, `disas`, `delete`, `continue`...) **while the VM was
paused at the trigger**. Each call is a full IPC round-trip (MCP JSON-RPC →
openmcpgdb → gdb CLI + sentinel → back), so the trigger-pause summed to
**seconds** — long enough to be a real anti-VM/anti-cheat signal (RDTSC drift,
frame stalls).

The fix: a **standalone `gdb -batch -x script`** that does attach+arm+resume
and, on trigger, runs a `commands`-block (dump all registers + disasm + delete +
detach + quit) **all in-process inside gdb** — no IPC round-trips while paused.
The freeze shrinks to the unavoidable DR-trap + immediate resume (**~ms**).

## 8. `gdb_watch.sh` (the minimal-freeze script)

Located at `~/.config/scanflow-ng/gdb_watch.sh` and copied into this skill at
`../scripts/gdb_watch.sh`. Usage:
```bash
gdb_watch.sh <hex_addr> [type] [port]   # type default int (=4 bytes), port default 7331
```
It generates a gdb command file `/tmp/gdb_watch_<addr>.gdb`:
```
set pagination off
set confirm off
target remote :7331
watch *(<type>*)0x<addr>
commands 1
  silent
  printf "=== WATCHPOINT HIT ===\n"
  printf "RIP=... rbx=... rax=...\n", $rip, $rbx, $rax
  info registers
  printf "=== disasm around write (RIP-16 ..) ===\n"
  x/12i $rip-16
  delete 1
  detach
  printf "=== WATCHPOINT DONE ===\n"
  quit
end
continue
```
and runs `nohup gdb -batch -x <script> > /tmp/gdb_watch_<addr>.log 2>&1 &`
(background). It attaches (brief pause), arms the HW watchpoint, `continue`s
(VM free), then blocks on `continue` until the watchpoint fires. On fire, the
`commands`-block runs in-process (dump + delete + detach + quit) — ~ms — and
the VM resumes. Output (all registers + disasm) is in the log, terminated by
the `=== WATCHPOINT DONE ===` sentinel.

## 9. Worked example — RTMTutorial (full output)

### 9.1 Locate the address (scanflow MCP)
- `scanflow_list_processes` {connectors:["kvm"], os:["win32"]} → found
  `RTMTutorial-x8`, **PID 12220**. (Win32 truncates names to 14 chars and is
  case-sensitive — `rtmtutorial` did not match; attach by PID.)
- `scanflow_attach_process` {connectors:["kvm"], os:["win32"], pid:12220} →
  `session_id = 87756d8a-8e12-45a8-89c6-ee51409d1eb7`.
- `scanflow_scan_value` {session_id, type_name:"i32", value:"100"} → **1156 matches**.
- User changed 100 → 95; `scanflow_filter_value` {session_id, value:"95"} → **1 match: `0x15edce8`**.
- `scanflow_list_modules` {session_id} → `rtmtutorial-x86_64.exe` base `0x100000000`, size `0x353000`.

### 9.2 First attempt (openmcpgdb, per-command — SLOW pause, do not use for live targets)
Documented for context; prefer §9.3.
- `openmcpgdb_gdb_target_remote` {ip:"127.0.0.1", port:7331} → attached (VM paused).
- `openmcpgdb_gdb_custom` {cmd:"watch *(int*)0x15edce8"} → `Hardware watchpoint 1`.
- `openmcpgdb_gdb_continue` {} → VM running.
- User clicked → VM froze → `openmcpgdb_gdb_info_regs` → `RIP=0x10002b4c2`,
  `rbx=0x15ed4f0`, `rax=0x2`. Then `gdb_custom "disas 0x10002b4a0,0x10002b4d0"`
  showed the store. Each of those calls was a round-trip **while paused** → seconds of freeze.

### 9.3 Minimal-freeze attempt (gdb_watch.sh — ~ms pause, the recommended way)
- Freed the stub: `openmcpgdb_gdb_custom` {cmd:"detach"}; confirmed `ss -tnp | grep 7331` had no ESTAB.
- `gdb_watch.sh 0x15edce8 int 7331` → `Hardware watchpoint 1: *(int*)0x15edce8`; VM stayed `running`.
- User clicked (value 93 → 86). Log `/tmp/gdb_watch_15edce8.log`:

```
=== WATCHPOINT HIT ===
RIP=0x10002b4c2 rbx=0x15ed4f0 rax=0x3 rcx=0x7ec5ef13 rdx=0x9945ef13
rax            0x3                 3
rbx            0x15ed4f0           22992112
rcx            0x7ec5ef13          2126901011
rdx            0x9945ef13          2571497235
rsi            0x0                 0
rdi            0x1002902d8         4297655000
rbp            0x13feda0           0x13feda0
rsp            0x13fec70           0x13fec70
r8             0x5074e             329550
r9             0x5074e             329550
r10            0x20758             132952
r11            0x13fef80           20967296
r12            0x15ee9b0           22997424
r13            0x10015e1b0         4296401328
r14            0x10028f998         4297652632
r15            0x1002902d0         4297654992
rip            0x10002b4c2         0x10002b4c2
eflags         0x206               [ IOPL=0 IF PF ]
cr3            0x3b5ad7000         [ PDBR=3889879 PCID=0 ]
... (all xmm/mxcsr zero) ...
=== disasm around write (RIP-16 ..) ===
   0x10002b4b2: add    %al,(%rax)
   0x10002b4b4: call   0x10000fc10
   0x10002b4b9: add    $0x1,%eax
   0x10002b4bc: sub    %eax,0x7f8(%rbx)        ; ★ THE WRITE
=> 0x10002b4c2: lea    -0x8(%rbp),%rcx        ; (RIP, just after the write)
   0x10002b4c6: call   0x100008f10
   0x10002b4cb: mov    0x7f8(%rbx),%ecx       ; re-read the field
   0x10002b4d1: mov    $0xff,%r9d
   0x10002b4d7: lea    -0x108(%rbp),%r8
   0x10002b4de: mov    $0xffffffffffffffff,%rdx
   0x10002b4e5: movslq %ecx,%rcx
   0x10002b4e8: call   0x100006090
[Inferior 1 (process 1) detached]
=== WATCHPOINT DONE ===
```

### 9.4 Interpretation (raw addrs → module+offset)
Module base = `0x100000000` (`rtmtutorial-x86_64.exe`).
- `RIP = 0x10002b4c2` → **`+0x2b4c2`** (the instruction after the write — x86 HW watchpoints trap post-write).
- The writing instruction is the one just before RIP: `sub %eax,0x7f8(%rbx)` at `0x10002b4bc` → **`rtmtutorial-x86_64.exe + 0x2b4bc`**.
- Verify the address: `rbx=0x15ed4f0`, `+0x7f8` → `0x15edce8` ✅ (matches the watched address).
- `cr3=0x3b5ad7000` = RTMTutorial's address space → **not a false trigger**.
- Enclosing function: the prologue `push rbp; mov rsp,rbp; lea -0x130(%rsp),%rsp` at `0x10002b490` → **`+0x2b490`**.
- Semantics: `call +0xfc10` (arg 5) → `eax = result + 1` → `sub [rbx+0x7f8], eax` → re-read → `call +0x6090` (UI refresh with the new value). Each click **decrements** the field by a computed amount (`rax=2` first run, `rax=3` second run).

### 9.5 Result reported to the user
- **Writing instruction:** `sub dword ptr [rbx+0x7f8], eax` at `rtmtutorial-x86_64.exe + 0x2b4bc`.
- **Enclosing function:** entry `+ 0x2b490`.
- **Field:** at struct offset `0x7f8` of an object whose base is in `rbx` (`0x15ed4f0`).
- **Action:** `value -= eax` (computed decrement per click).

## 10. Anti-cheat / anti-VM notes

- The **one unavoidable pause** is the `#DB` trap at the writing instruction
  (~ms with `gdb_watch.sh`). A hardware watchpoint has no steady-state cost
  (silicon-checked); only the trigger stops the CPU.
- **Truly zero** would require an **in-KVM `#DB` logger**: a custom KVM
  extension that, on a DR trap, records `RIP` (and `CR3`) into a ring buffer and
  resumes the vCPU **without exiting to QEMU/gdb** — no userspace involvement.
  That's a substantial kernel/KVM project, out of scope here. `gdb_watch.sh`
  gets you to the one unavoidable micro-pause.
- Do **not** leave a watchpoint armed longer than needed; the script deletes it
  on trigger and detaches. If you abort, `kill <gdb_pid>` and confirm the VM is
  running (QMP `query-status`); resume with `cont` if needed.

## 11. QMP cont one-liner (manual resume)

If a gdb session is killed while the VM is paused and the VM stays stopped:
```python
python3 - <<'PY'
import socket,json,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect("/tmp/qmp-win10-stealth.sock")
def rj():
 d=b""
 while b"\n" not in d:
  c=s.recv(4096); 
  if not c:break
  d+=c
 return json.loads(d.decode().splitlines()[-1])
rj();s.sendall(b'{"execute":"qmp_capabilities"}\n');rj()
s.sendall(b'{"execute":"query-status"}\n');time.sleep(0.2);print("before:",rj())
s.sendall(b'{"execute":"cont"}\n');rj()
s.sendall(b'{"execute":"query-status"}\n');time.sleep(0.2);print("after:",rj());s.close()
PY
```
(Adjust the socket path for other domains.)

## 12. openmcpgdb vs gdb_watch.sh — when to use which

- **`gdb_watch.sh`** — use for the **live "find what writes"** step. Minimal
  freeze (in-process), dumps all registers + disasm, auto-detaches. This is the
  recommended path and what this skill documents as Step 2–3.
- **openmcpgdb (MCP)** — convenient for **interactive** gdb driving from the
  agent (`gdb_target_remote`, `gdb_info_regs`, `gdb_full_backtrace`,
  `gdb_custom`, …) when freeze length doesn't matter (e.g. a paused
  non-time-sensitive target, or repeated stepping). It's installed and wired
  into pi as a default MCP server (see `MCP-SETUP.md`). Its per-command round
  trips make it **too slow for live-game watchpoint triggers** — that's why
  `gdb_watch.sh` exists. You can still use openmcpgdb to **free the stub**
  (`gdb_custom {cmd:"detach"}`) before running `gdb_watch.sh`.

## 13. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `gdb_watch.sh` log: `localhost:7331: Connection refused` / `Remote communication error` | Stub not free — another gdb client (openmcpgdb) is attached. Detach it (`openmcpgdb_gdb_custom {cmd:"detach"}`) or `kill` it, then re-run. |
| Watchpoint "armed" but never fires | The value didn't change, or the write is a different width (try `short`/`char`/`long long`), or the address changed (rescan with scanflow). |
| `RIP` is outside the target's module | False trigger from another process (same VA, different CR3). Check `cr3`; re-arm and try again. |
| VM left paused after aborting | Run the QMP `cont` one-liner (§11). |
| `scanflow_attach_process` "no process named X" | Win32 truncates names to 14 chars + case-sensitive. `list_processes` first, attach by PID. Or use `pid` arg. |
| "invalid builder configuration, last build step has to be a os" with `-c kvm -p X` | `kvm` is a connector, not an OS layer. Add `--os win32` (or use an OS plugin like `qemu_procfs` as the connector). |
| `attach_process` returns ambiguous list | Several processes share the (truncated) name. Re-call with `pid`. |

## 14. Inventory / where things live

- Repo skill: `.pi/skills/scanflow-gdb-write-watch/` (this file, `SKILL.md`, `scripts/gdb_watch.sh`, `MCP-SETUP.md`).
- Host gdb: `/usr/bin/gdb` (GNU gdb 17.2, Gentoo).
- QEMU gdb stub: `tcp::7331` (libvirt XML).
- QEMU QMP: `unix:/tmp/qmp-win10-stealth.sock`.
- `scanflow-mcp` binary: `~/.cargo/bin/scanflow-mcp` (built from `scanflow-mcp/` in this repo).
- `openmcpgdb` binary: `~/.cargo/bin/openmcpgdb`; config `~/.config/scanflow-ng/openmcpgdb.json` (`mcp_server_url: "stdio://local"`, `gdb_path: "/usr/bin/gdb"`).
- `gdb_watch.sh` (runtime copy): `~/.config/scanflow-ng/gdb_watch.sh`.
- pi global MCP config: `~/.config/mcp/mcp.json` (`camoufox`, `scanflow`, `openmcpgdb`).