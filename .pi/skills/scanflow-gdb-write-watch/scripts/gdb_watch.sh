#!/bin/bash
# Minimal-freeze GDB write watchpoint via the QEMU gdb stub.
# Usage: gdb_watch.sh <hex_addr> [type] [port]
#   <hex_addr>  guest VA to watch (e.g. 0x15edce8)
#   [type]      C type -> watch width (default int = 4 bytes; use short/char/long long)
#   [port]      gdb stub port (default 7331)
#
# Runs gdb in batch (background). It:
#   1. attaches to the stub (brief pause), arms a HW write watchpoint, resumes -> VM runs free
#   2. on the NEXT write to <addr>: dumps ALL registers + disasm around RIP, deletes the
#      watchpoint, detaches (VM resumes), and quits -- all in-process, so the freeze window
#      is just the unavoidable DR trap + immediate resume.
# Output: /tmp/gdb_watch_<addr>.log  (sentinel "=== WATCHPOINT DONE ===" marks completion)
set -euo pipefail
ADDR="${1:?usage: gdb_watch.sh <hex_addr> [type] [port]}"
TYPE="${2:-int}"
PORT="${3:-7331}"
A="${ADDR#0x}"
LOG="/tmp/gdb_watch_${A}.log"
GDBSCRIPT="/tmp/gdb_watch_${A}.gdb"
cat > "$GDBSCRIPT" <<EOF
set pagination off
set confirm off
set print pretty on
target remote :${PORT}
watch *(${TYPE}*)0x${A}
commands 1
  silent
  printf "=== WATCHPOINT HIT ===\n"
  printf "RIP=0x%lx rbx=0x%lx rax=0x%lx rcx=0x%lx rdx=0x%lx\n", \$rip, \$rbx, \$rax, \$rcx, \$rdx
  info registers
  printf "=== disasm around write (RIP-16 ..) ===\n"
  x/12i \$rip-16
  delete 1
  detach
  printf "=== WATCHPOINT DONE ===\n"
  quit
end
continue
EOF
echo "[gdb_watch] script=$GDBSCRIPT log=$LOG type=$TYPE"
nohup gdb -batch -x "$GDBSCRIPT" > "$LOG" 2>&1 &
GDB_PID=$!
echo "[gdb_watch] gdb pid=$GDB_PID  (VM resumed; waiting for a write to 0x${A})"
echo "[gdb_watch] abort: kill $GDB_PID   |   watch: tail -f $LOG"
