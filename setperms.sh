#!/bin/bash
# setcaps on built scanflow binaries so they can use ptrace (for qemu_procfs).
# Uses `sudo -n` (non-interactive): if no cached sudo creds, it silently skips
# instead of blocking `cargo test`/`cargo run` with a password prompt.

do_setcap() {
	for f in "$1/$2"*; do
		if [[ -f $f && $f != *.* ]] ; then
			if [[ -z "$(getcap $f 2>/dev/null | grep -i cap_sys_ptrace)" ]]; then
				if sudo -n true 2>/dev/null; then
					echo "setcap for $f"
					sudo -n setcap 'CAP_SYS_PTRACE=ep' "$f" 2>/dev/null || echo "  (setcap failed, continuing)"
				else
					# no cached sudo creds — skip silently to avoid blocking builds/tests
					:
				fi
			fi
		fi
	done
}

files=(
	scanflow
	scanflow-cli
	scanflow-mcp
)

for f in "${files[@]}"; do
	do_setcap target/debug "$f"
done

for f in "${files[@]}"; do
	do_setcap target/release "$f"
done