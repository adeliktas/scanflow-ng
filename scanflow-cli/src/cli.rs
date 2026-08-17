use memflow::prelude::v1::*;
use std::convert::TryInto;
use std::io::Write;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Instant;

use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

use scanflow::{
    disasm::Disasm,
    pointer_map::PointerMap,
    sigmaker::Sigmaker,
    value_scanner::ValueScanner,
};

pub const MAX_PRINT: usize = 16;

pub struct Funcs<T> {
    maps: fn(&mut T, imem, Address, Address) -> Vec<MemoryRange>,
    info: fn(&T) -> &str,
}

impl<T: Process + MemoryView> Funcs<T> {
    fn process() -> Self {
        Self {
            maps: |proc, gap_size, from, to| proc.mapped_mem_range_vec(gap_size, from, to),
            info: |proc| &proc.info().name,
        }
    }
}

impl<T: MemoryView> Funcs<T> {
    fn view() -> Self {
        Self {
            maps: |view, _, from, to| {
                let mdata = view.metadata();
                if from < mdata.max_address {
                    vec![CTup3(
                        from,
                        (core::cmp::min(mdata.max_address, to) - from) as umem,
                        PageType::UNKNOWN,
                    )]
                } else {
                    vec![]
                }
            },
            info: |_| "view",
        }
    }
}

impl<T> Clone for Funcs<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Funcs<T> {}

/// Scanflow CLI context.
pub struct CliCtx<T> {
    memory: T,
    value_scanner: ValueScanner,
    typename: Option<String>,
    buf_len: usize,
    disasm: Disasm,
    pointer_map: PointerMap,
    funcs: Funcs<T>,
}

impl<T> CliCtx<T> {
    fn new(memory: T, funcs: Funcs<T>) -> Self {
        Self {
            memory,
            value_scanner: Default::default(),
            typename: None,
            buf_len: 0,
            disasm: Default::default(),
            pointer_map: Default::default(),
            funcs,
        }
    }
}

/// Scanflow command.
pub trait CliCmd<T> {
    /// Handle the command invokation.
    ///
    /// # Arguments
    /// * `args` - string arguments that were passed.
    /// * `ctx` - reference to scanflow context.
    fn invoke(&mut self, args: &str, ctx: &mut CliCtx<T>) -> Result<()>;
    /// Get the help about this command.
    fn help(&self) -> String;
}

/// Scanflow command handler.
pub type CmdHandler<T> = fn(&str, &mut CliCtx<T>) -> Result<()>;

/// Standard scanflow command definition.
pub struct CmdDef<'a, T> {
    long: &'a str,
    short: &'a str,
    invoke: CmdHandler<T>,
    help: &'a str,
    long_help: Option<&'a str>,
}

impl<'a, T> Clone for CmdDef<'a, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, T> Copy for CmdDef<'a, T> {}

impl<'a, T> CmdDef<'a, T> {
    fn new(
        long: &'a str,
        short: &'a str,
        handle: CmdHandler<T>,
        help: &'a str,
        long_help: Option<&'a str>,
    ) -> Self {
        Self {
            long,
            short,
            invoke: handle,
            help,
            long_help,
        }
    }
}

impl<'a, T> CliCmd<T> for CmdDef<'a, T> {
    fn invoke(&mut self, args: &str, ctx: &mut CliCtx<T>) -> Result<()> {
        (self.invoke)(args, ctx)
    }

    fn help(&self) -> String {
        format!("{} {}: {}", self.long, self.short, self.help)
    }
}

/// Optimized pattern structure for faster searching
struct OptimizedPattern {
    pattern: Vec<Option<u8>>,
    skip_table: HashMap<u8, usize>,
    last_byte_pos: Option<usize>,
}

impl OptimizedPattern {
    fn new(pattern: Vec<Option<u8>>) -> Self {
        let mut skip_table = HashMap::new();
        let mut last_byte_pos = None;
        
        // Build Boyer-Moore-like skip table
        // For each byte value, store how far we can skip if we see it
        for (i, &byte_opt) in pattern.iter().enumerate().rev() {
            if let Some(byte) = byte_opt {
                skip_table.entry(byte).or_insert(pattern.len() - 1 - i);
                if last_byte_pos.is_none() {
                    last_byte_pos = Some(i);
                }
            }
        }
        
        Self {
            pattern,
            skip_table,
            last_byte_pos,
        }
    }
    
    fn len(&self) -> usize {
        self.pattern.len()
    }
    
    /// Fast pattern matching with Boyer-Moore-like skipping
    fn find_matches(&self, buf: &[u8], base_addr: Address) -> Vec<Address> {
        let mut matches = Vec::new();
        let pat_len = self.pattern.len();
        
        if buf.len() < pat_len {
            return matches;
        }
        
        let mut i = 0;
        while i <= buf.len() - pat_len {
            // Check if pattern matches at position i
            let mut match_found = true;
            let mut last_checked_pos = pat_len - 1;
            
            // Check from right to left (Boyer-Moore style)
            for j in (0..pat_len).rev() {
                last_checked_pos = j;
                if let Some(expected_byte) = self.pattern[j] {
                    if buf[i + j] != expected_byte {
                        match_found = false;
                        break;
                    }
                }
            }
            
            if match_found {
                matches.push(base_addr + i as umem);
                i += 1; // Move by 1 to find overlapping matches
            } else {
                // Calculate skip distance based on the mismatched byte
                let mismatch_byte = buf[i + last_checked_pos];
                let skip_dist = self.skip_table.get(&mismatch_byte)
                    .copied()
                    .unwrap_or(pat_len);
                
                // Skip at least 1 position to avoid infinite loops
                i += skip_dist.max(1);
            }
        }
        
        matches
    }
}

/// Debug version to see what's happening with pattern parsing
fn sig_scan_debug<T: MemoryView>(args: &str, ctx: &mut CliCtx<T>) -> Result<()> {
    // Parse the pattern from arguments
    let mut pattern: Vec<Option<u8>> = vec![];
    println!("Parsing pattern: '{}'", args);
    
    for (i, token) in args.split_whitespace().enumerate() {
        if token == "?" || token == "??" {
            pattern.push(None);
            println!("Token {}: '{}' -> wildcard", i, token);
        } else {
            if token.len() != 2 {
                println!("ERROR: Token '{}' has length {} (expected 2)", token, token.len());
                return Err(ErrorKind::InvalidArgument.into());
            }
            match u8::from_str_radix(token, 16) {
                Ok(byte) => {
                    pattern.push(Some(byte));
                    println!("Token {}: '{}' -> 0x{:02X}", i, token, byte);
                }
                Err(e) => {
                    println!("ERROR: Failed to parse '{}' as hex: {}", token, e);
                    return Err(ErrorKind::InvalidArgument.into());
                }
            }
        }
    }
    
    if pattern.is_empty() {
        println!("ERROR: Pattern is empty");
        return Err(ErrorKind::InvalidArgument.into());
    }
    
    println!("Final pattern ({} bytes):", pattern.len());
    for (i, &byte_opt) in pattern.iter().enumerate() {
        match byte_opt {
            Some(b) => print!("{:02X} ", b),
            None => print!("?? "),
        }
        if (i + 1) % 16 == 0 { println!(); }
    }
    println!();
    
    let pat_len = pattern.len();
    let start = Instant::now();
    
    // Get all mapped memory ranges
    let ranges = (ctx.funcs.maps)(&mut ctx.memory, 0x1000, Address::NULL, Address::INVALID);
    println!("Scanning {} memory ranges", ranges.len());
    
    let mut matches: Vec<Address> = vec![];
    let mut total_bytes_scanned = 0usize;
    
    // Check if the specific address range is included
    let target_addr = 0x185D9AC4Du64; // Your target address
    let gameassembly_base = 0x7FF977BD0000u64; // Your GameAssembly.dll base
    let expected_addr = gameassembly_base + (target_addr - 0x180000000);
    
    println!("Looking for address around: 0x{:X}", expected_addr);
    
    for (range_idx, range) in ranges.iter().enumerate() {
        let base = range.0;
        let size = range.1 as usize;
        total_bytes_scanned += size;
        
        // Check if this range contains our expected address
        let range_end = base + size as umem;
        if base.to_umem() <= expected_addr && expected_addr < range_end.to_umem() {
            println!("*** Found target range {}: 0x{:X} - 0x{:X} (size: 0x{:X})", 
                     range_idx, base.to_umem(), range_end.to_umem(), size);
        }
        
        if size < pat_len {
            continue;
        }
        
        let mut buf = vec![0u8; size];
        match ctx.memory.read_raw_into(base, &mut buf) {
            Ok(_) => {
                // Manual pattern matching with detailed logging for target range
                let is_target_range = base.to_umem() <= expected_addr && expected_addr < range_end.to_umem();
                
                for i in 0..=(size - pat_len) {
                    let current_addr = base + i as umem;
                    
                    // Check if we're near the target address
                    if is_target_range && (current_addr.to_umem() as i64 - expected_addr as i64).abs() < 100 {
                        println!("Checking near target at 0x{:X}:", current_addr.to_umem());
                        print!("Memory: ");
                        for j in 0..pat_len {
                            print!("{:02X} ", buf[i + j]);
                        }
                        println!();
                        print!("Pattern: ");
                        for &byte_opt in &pattern {
                            match byte_opt {
                                Some(b) => print!("{:02X} ", b),
                                None => print!("?? "),
                            }
                        }
                        println!();
                    }
                    
                    // Check if pattern matches
                    let mut matches_pattern = true;
                    for j in 0..pat_len {
                        if let Some(expected_byte) = pattern[j] {
                            if buf[i + j] != expected_byte {
                                matches_pattern = false;
                                break;
                            }
                        }
                    }
                    
                    if matches_pattern {
                        matches.push(current_addr);
                        println!("MATCH found at: 0x{:X}", current_addr.to_umem());
                    }
                }
            }
            Err(e) => {
                if base.to_umem() <= expected_addr && expected_addr < range_end.to_umem() {
                    println!("ERROR: Failed to read target range at 0x{:X}: {:?}", base.to_umem(), e);
                }
            }
        }
    }
    
    let duration = start.elapsed().as_secs_f64() * 1000.0;
    
    println!("Scanned {} bytes in {:.2}ms", total_bytes_scanned, duration);
    println!("Found {} matches", matches.len());
    
    for &addr in matches.iter().take(MAX_PRINT) {
        println!("Match: 0x{:X}", addr.to_umem());
    }
    
    // Store matches in the value scanner for further use
    ctx.value_scanner.reset();
    ctx.value_scanner
        .matches_mut()
        .extend(matches.into_iter());
    ctx.typename = None;
    
    Ok(())
}

fn sig_scan<T: MemoryView>(args: &str, ctx: &mut CliCtx<T>) -> Result<()> {
    // Parse the pattern from arguments
    let mut pattern: Vec<Option<u8>> = vec![];
    for token in args.split_whitespace() {
        if token == "?" || token == "??" {
            pattern.push(None);
        } else {
            if token.len() != 2 {
                return Err(ErrorKind::InvalidArgument.into());
            }
            let byte = u8::from_str_radix(token, 16).map_err(|_| ErrorKind::InvalidArgument)?;
            pattern.push(Some(byte));
        }
    }

    if pattern.is_empty() {
        return Err(ErrorKind::InvalidArgument.into());
    }

    let pat_len = pattern.len();

    // Start timing the scan
    let start = Instant::now();

    // Get all mapped memory ranges
    let ranges = (ctx.funcs.maps)(&mut ctx.memory, 0x1000, Address::NULL, Address::INVALID);

    let mut matches: Vec<Address> = vec![];

    // Scan each memory range for the pattern
    for range in ranges {
        let base = range.0;
        let size = range.1 as usize;
        if size < pat_len {
            continue;
        }
        let mut buf = vec![0u8; size];
        if ctx.memory.read_raw_into(base, &mut buf).is_ok() {
            for i in 0..=(size - pat_len) {
                if (0..pat_len).all(|j| pattern[j].map_or(true, |p| p == buf[i + j])) {
                    matches.push(base + i as umem);
                }
            }
        }
    }

    // Calculate duration
    let duration = start.elapsed().as_secs_f64() * 1000.0;

    // Output results
    println!("Found {} matches in {:.2}ms", matches.len(), duration);
    if matches.len() > MAX_PRINT {
        println!("Printing first {} matches", MAX_PRINT);
    }
    for &addr in matches.iter().take(MAX_PRINT) {
        println!("{:x}", addr);
    }

    // Store matches in the value scanner for further use
    ctx.value_scanner.reset();
    ctx.value_scanner
        .matches_mut()
        .extend(matches.into_iter());
    ctx.typename = None;

    Ok(())
}


// Alternative: Sequential version if thread safety is problematic
fn sig_scan_sequential<T: MemoryView>(args: &str, ctx: &mut CliCtx<T>) -> Result<()> {
    // Parse the pattern from arguments
    let mut pattern: Vec<Option<u8>> = vec![];
    for token in args.split_whitespace() {
        if token == "?" || token == "??" {
            pattern.push(None);
        } else {
            if token.len() != 2 {
                return Err(ErrorKind::InvalidArgument.into());
            }
            let byte = u8::from_str_radix(token, 16).map_err(|_| ErrorKind::InvalidArgument)?;
            pattern.push(Some(byte));
        }
    }
    
    if pattern.is_empty() {
        return Err(ErrorKind::InvalidArgument.into());
    }
    
    // Create optimized pattern for faster searching
    let opt_pattern = OptimizedPattern::new(pattern);
    let pat_len = opt_pattern.len();
    
    // Start timing the scan
    let start = Instant::now();
    
    // Get all mapped memory ranges
    let ranges = (ctx.funcs.maps)(&mut ctx.memory, 0x1000, Address::NULL, Address::INVALID);
    
    let mut matches: Vec<Address> = Vec::new();
    
    // Sequential scan with optimized pattern matching
    for range in ranges {
        let base = range.0;
        let size = range.1 as usize;
        if size < pat_len {
            continue;
        }
        
        let mut buf = vec![0u8; size];
        if ctx.memory.read_raw_into(base, &mut buf).is_ok() {
            let range_matches = opt_pattern.find_matches(&buf, base);
            matches.extend(range_matches);
        }
    }
    
    // Calculate duration
    let duration = start.elapsed().as_secs_f64() * 1000.0;
    
    // Output results
    println!("Found {} matches in {:.2}ms", matches.len(), duration);
    if matches.len() > MAX_PRINT {
        println!("Printing first {} matches", MAX_PRINT);
    }
    for &addr in matches.iter().take(MAX_PRINT) {
        println!("{:x}", addr);
    }
    
    // Store matches in the value scanner for further use
    ctx.value_scanner.reset();
    ctx.value_scanner
        .matches_mut()
        .extend(matches.into_iter());
    ctx.typename = None;
    
    Ok(())
}

fn view_cmds<'a, T: MemoryView + Clone>() -> impl IntoIterator<Item = CmdDef<'a, T>> {
    [
        CmdDef::<T>::new(
            "reset",
            "r",
            |_, ctx| {
                ctx.value_scanner.reset();
                ctx.disasm.reset();
                ctx.pointer_map.reset();
                ctx.typename = None;
                Ok(())
            },
            "reset all context state",
            None,
        ),
        CmdDef::<T>::new(
            "reinterpret",
            "ri",
            |arg, ctx| {
                let mut split = arg.split_whitespace();

                let (arg, len) = (
                    split.next().ok_or(ErrorKind::InvalidArgument)?.to_string(),
                    split.next(),
                );

                if let Some(Type(_, size, _, _)) = TYPES
                    .iter()
                    .filter(|Type(name, _, _, _)| name == &arg)
                    .next()
                {
                    ctx.typename = Some(arg);

                    if let Some(size) = size {
                        ctx.buf_len = *size;
                    } else {
                        ctx.buf_len = len
                            .and_then(|len| len.parse().ok())
                            .ok_or(ErrorKind::InvalidArgument)?;
                    }

                    Ok(())
                } else {
                    Err(ErrorKind::InvalidArgument.into())
                }
            },
            "reinterpret matches as another type. Usage: {type} ({unsized len})",
            Some(
                r#"- {type}
  - Target recast type: `str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64`
  - ({unsized len})
    - Optional: Size of the type, Applicable to `str` and `str_utf16`"#,
            ),
        ),
        CmdDef::<T>::new(
            "add",
            "a",
            |arg, ctx| {
                let addr = u64::from_str_radix(arg, 16).map_err(|_| ErrorKind::InvalidArgument)?;
                ctx.value_scanner.matches_mut().push(addr.into());
                Ok(())
            },
            "manually add an address to matches",
            None,
        ),
        CmdDef::<T>::new(
            "remove",
            "rm",
            |arg, ctx| {
                let idx = arg
                    .parse::<usize>()
                    .map_err(|_| ErrorKind::InvalidArgument)?;
                ctx.value_scanner.matches_mut().remove(idx);
                Ok(())
            },
            "remove match by index",
            None,
        ),
        CmdDef::new(
            "print",
            "p",
            |_, ctx| {
                if let Some(t) = &ctx.typename {
                    print_matches(&ctx.value_scanner, &mut ctx.memory, ctx.buf_len, t)
                } else {
                    Err(ErrorKind::Uninitialized.into())
                }
            },
            "print found matches after initial scan",
            None,
        ),
        CmdDef::new(
            "write",
            "wr",
            |args, ctx| {
                write_value(
                    args,
                    &ctx.typename,
                    ctx.value_scanner.matches(),
                    &mut ctx.memory,
                )
            },
            "write values to select matches. Arguments: {idx/*} {o/c} {value}",
            Some(
                r#"Arguments:
- {idx/*}
  - `idx`: Write to the search match idx.
  - `*`: Write to the all search matches. (I'd prefer `all` as oppose to `*`)
- {o/c}
  - `o`: Write once.
  - `c`: Spawn thread and continuously write.
- value: Self explanatory "#,
            ),
        ),
        CmdDef::new( // code must be actively running to be paged in memory and findable !!! like autorun or echo spam for argo-cmd ConsoleSystem_Arg__HasPermission pattern
            "sig",
            "sg",
            sig_scan_sequential, //sig_scan_sequential faster and thread-safe; sig_scan slow; sig_scan_debug 
            "scan memory for a byte pattern (IDA style)",
            Some(
                r#"Usage: sig {pattern}

Pattern is space-separated hex bytes (two digits each) or wildcards (? or ?? for any byte).

Example: sig 4D 85 C0 0F 84 ? ? ? ? 4D 8B 40 ? B8 ? ? ? ? 41 F7 E0 B8 ? ? ? ? C1 EA ? 8D 0C 92

This will search the entire memory for the pattern, print the starting addresses of matches, and store them in the value scanner matches for further processing."#,
            ),
        ),
    ]
}

fn proc_cmds<'a, T: Process + MemoryView + Clone>() -> impl IntoIterator<Item = CmdDef<'a, T>> {
    [
        CmdDef::new(
            "pointer_map",
            "pm",
            |_, ctx: &mut CliCtx<T>| {
                let size_addr = ArchitectureObj::from(ctx.memory.info().proc_arch).size_addr();

                ctx.pointer_map.reset();
                ctx.pointer_map.create_map(&mut ctx.memory, size_addr)
            },
            "build a pointer map",
            Some(
                r#"- Re-builds pointer map, (used in `offset_scan`)
  - Done automatically in `offset_scan`.
  - Allows to manually trigger rebuild, if process memory has changed significantly."#,
            ),
        ),
        CmdDef::new(
            "globals",
            "g",
            |args, ctx| {
                ctx.disasm.reset();
                ctx.disasm.collect_globals(
                    &mut ctx.memory,
                    if args.is_empty() { None } else { Some(args) },
                )?;
                println!("Global variable references found: {:x}", ctx.disasm.map().len());
                Ok(())
            },
            "find all global variables referenced by code. args: ({module})",
            Some(
                r#"Finds globals in target process' binary.

It is automatically invoked by `sigmaker` and `offset_scan`, however, executing it manually allows the user to limit global variable search to a single module."#,
            ),
        ),
        CmdDef::new(
            "sigmaker",
            "s",
            |args: &str, ctx| {
                if let Some(addr) = scan_fmt_some!(args, "{x}", [hex u64]) {
                    match Sigmaker::find_sigs(&mut ctx.memory, &ctx.disasm, addr.into()) {
                        Ok(sigs) => {
                            println!("Found signatures:");
                            for sig in sigs {
                                println!("{}", sig);
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(ErrorKind::ArgValidation.into())
                }
            },
            "finds code signatures referring to given address. args: {addr}",
            Some(
                r#"Usage: After using offset scan, take the first hex value of the result you want, and sigmaker will produce a signature which you can scan for.

If `globals` was not previously run, then this command will generate a list of globals on all executable regions. If you wish to look for signatures within a single module, first run `globals {module}`."#,
            ),
        ),
        CmdDef::new(
            "offset_scan",
            "os",
            |args, ctx| {
                if let (Some(use_di), Some(lrange), Some(urange), Some(max_depth), filter_addr) =
                    scan_fmt_some!(args, "{} {} {} {} {x}", String, usize, usize, usize, [hex u64])
                {
                    if ctx.pointer_map.map().is_empty() {
                        let size_addr =
                            ArchitectureObj::from(ctx.memory.info().proc_arch).size_addr();
                        ctx.pointer_map.create_map(&mut ctx.memory, size_addr)?;
                    }

                    let start = Instant::now();

                    let matches = if use_di == "y" {
                        if ctx.disasm.map().is_empty() {
                            ctx.disasm.collect_globals(&mut ctx.memory, None)?;
                        }
                        ctx.pointer_map.find_matches_addrs(
                            (lrange, urange),
                            max_depth,
                            ctx.value_scanner.matches(),
                            ctx.disasm.globals(),
                        )
                    } else {
                        ctx.pointer_map.find_matches(
                            (lrange, urange),
                            max_depth,
                            ctx.value_scanner.matches(),
                        )
                    };

                    println!(
                        "Matches found: {} in {:.2}ms",
                        matches.len(),
                        start.elapsed().as_secs_f64() * 1000.0
                    );

                    if matches.len() > MAX_PRINT {
                        println!("Printing first {} matches", MAX_PRINT);
                    }
                    for (m, offsets) in matches
                        .into_iter()
                        .filter(|(_, v)| {
                            if let Some(a) = filter_addr {
                                if let Some((s, _)) = v.first() {
                                    s.to_umem() == a as umem
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        })
                        .take(MAX_PRINT)
                    {
                        for (start, off) in offsets.into_iter() {
                            print!("{:x} + ({}) => ", start, off);
                        }
                        println!("{:x}", m);
                    }

                    Ok(())
                } else {
                    Err(ErrorKind::InvalidArgument.into())
                }
            },
            "scan for offsets to matches. Arguments: {y/[n]} {lower range} {upper range} {max depth} ({filter})",
            Some(
                r#"Arguments:
- {y/[n]}
  - y: Use disassembler to find instructions in binary to refer to globals. If `globals` was not previously run, then this command will generate a list of globals on all executable regions. If you wish to look for pointers referred from a single module, first run `globals {module}`.
  - n: use the whole memory range
  - Default = n
- {lower range}
  - scan_result_ptr - lower range
- {upper range}
  - scan_result_ptr + upper range
  - `[scan_result_ptr - lower range, scan_result_ptr + upper range] = scan area`
- {max depth}
  - max scan depth
- ({filter})
  - Optional: Filter address (hex)

Explanation: Finds a pointer chains from the binary to the scan results."#,
            ),
        ),
    ]
}

/// Run the CLI
///
/// # Arguments
///
/// * `process` - target process
pub fn run<T: Process + MemoryView + Clone>(process: T) -> Result<()> {
    let mut cmds = view_cmds()
        .into_iter()
        .chain(proc_cmds().into_iter())
        .collect::<Vec<_>>();

    run_with_cmds(process, Funcs::process(), &mut cmds)
}

/// Run the CLI with a view
///
/// If `memory` is a process, consider using [`run`], since it provides more functionality.
///
/// # Arguments
///
/// * `memory` - target memory object
pub fn run_with_view<T: MemoryView + Clone>(process: T) -> Result<()> {
    let mut cmds = view_cmds().into_iter().collect::<Vec<_>>();

    run_with_cmds(process, Funcs::view(), &mut cmds)
}

fn run_with_cmds<T: MemoryView + Clone>(
    state: T,
    funcs: Funcs<T>,
    cmds: &mut [CmdDef<T>],
) -> Result<()> {
    let mut ctx = CliCtx::new(state, funcs);

    loop {
        if let Some(tn) = &ctx.typename {
            print!("[{}] ", tn)
        }

        print!("scanflow@{} >> ", (ctx.funcs.info)(&ctx.memory));

        std::io::stdout().flush().ok();

        let line = get_line().map_err(|_| ErrorKind::UnableToReadFile)?;

        let line = line.trim();

        let mut toks = line.splitn(2, ' ');
        let (cmd, args) = (toks.next().unwrap_or(""), toks.next().unwrap_or(""));

        match cmd {
            "quit" | "q" => break,
            "help" | "h" => {
                if args.is_empty() {
                    println!("Command reference:");
                    println!("quit q: quit the CLI");
                    println!("help h: show this help");
                    println!("help h {{cmd}}: show longer help for a given command");

                    for cmd in &*cmds {
                        println!("{}", cmd.help());
                    }

                    println!();

                    println!("Anything not in this list will be interpreted as a scan input.");

                    println!();

                    println!("To scan memory, enter wanted data type and its value. The type is omitted in consequtive function calls.");
                    println!("Available types: str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64");

                    println!();

                    println!("Example:");
                    println!("i64 64");
                    println!("Next filtering call:");
                    println!("42");
                } else {
                    if let Some(cmd) = cmds
                        .iter_mut()
                        .find(|cmd| cmd.short == args || cmd.long == args)
                    {
                        println!("{}", cmd.help);
                        println!();
                        if let Some(long) = cmd.long_help {
                            println!("{}", long);
                        } else {
                            println!("(no further help available)");
                        }
                    } else if ["quit", "help", "q", "h"].contains(&args) {
                        println!("Built-in command with no further help");
                    } else {
                        println!(
                            "Could not find command `{args}`. Use `help` for command reference."
                        );
                    }
                }
            }
            x => {
                if let Some(cmd) = cmds.iter_mut().find(|cmd| cmd.short == x || cmd.long == x) {
                    match cmd.invoke(args, &mut ctx) {
                        Ok(()) => {}
                        Err(e) => println!("{} error: {}\nHelp:\n{}", cmd.long, e, cmd.help()),
                    }
                } else {
                    if let Some((buf, t)) = parse_input(line, &ctx.typename) {
                        ctx.buf_len = buf.len();
                        ctx.value_scanner
                            .scan_for_2(&mut ctx.memory, ctx.funcs.maps, &buf)?;
                        print_matches(&ctx.value_scanner, &mut ctx.memory, ctx.buf_len, &t)?;
                        ctx.typename = Some(t);
                    } else {
                        println!("Invalid input! Use `help` for command reference.");
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn print_matches(
    value_scanner: &ValueScanner,
    mem: &mut impl MemoryView,
    buf_len: usize,
    typename: &str,
) -> Result<()> {
    println!("Matches found: {}", value_scanner.matches().len());

    for &m in value_scanner.matches().iter().take(MAX_PRINT) {
        let mut buf = vec![0; buf_len];
        mem.read_raw_into(m, &mut buf).data_part()?;
        println!(
            "{:x}: {}",
            m,
            print_value(&buf, typename).ok_or(ErrorKind::InvalidArgument)?
        );
    }

    Ok(())
}

pub fn get_line() -> std::io::Result<String> {
    let mut output = String::new();
    std::io::stdin().read_line(&mut output).map(|_| output)
}

pub fn async_get_line() -> Receiver<std::io::Result<String>> {
    let (tx, rx) = channel();
    thread::spawn(move || tx.send(get_line()).unwrap());
    rx
}

pub fn write_value(
    args: &str,
    typename: &Option<String>,
    matches: &[Address],
    mem: &mut impl MemoryView,
) -> Result<()> {
    if matches.is_empty() {
        return Err(ErrorKind::Uninitialized.into());
    }

    let usage: Error = ErrorKind::ArgValidation.into();
    let mut words = args.splitn(3, " ");
    let (idx, mode, value) = (
        words.next().ok_or(usage)?,
        words.next().ok_or(usage)?,
        words.next().ok_or(usage)?,
    );

    let (skip, take) = if idx == "*" {
        (0, matches.len())
    } else {
        (
            idx.parse::<usize>()
                .map_err(|_| ErrorKind::InvalidArgument)?,
            1,
        )
    };

    let gl = match mode {
        "o" => Ok(None),
        "c" => Ok(Some(async_get_line())),
        _ => Err(ErrorKind::InvalidArgument),
    }?;

    let (v, _) = parse_input(value, typename).ok_or(ErrorKind::InvalidArgument)?;

    println!("Write to matches {}-{}", skip, skip + take - 1);

    loop {
        for &m in matches.iter().skip(skip).take(take) {
            mem.write_raw(m, v.as_ref()).data_part()?;
        }

        if let Some(try_get_line) = &gl {
            if let Ok(ret) = try_get_line.try_recv() {
                if let Err(e) = ret {
                    println!("Error reading line: {}", e.to_string());
                }
                break;
            }
        } else {
            break;
        }
    }

    println!("Write done");

    Ok(())
}

type PrintFn = fn(&[u8]) -> Option<String>;
type ParseFn = fn(&str) -> Option<Box<[u8]>>;

pub struct Type(&'static str, Option<usize>, PrintFn, ParseFn);

const TYPES: &[Type] = &[
    Type(
        "str",
        None,
        |buf| Some(String::from_utf8_lossy(buf).to_string()),
        |value| Some(Box::from(value.as_bytes())),
    ),
    Type(
        "str_utf16",
        None,
        |buf| {
            let mut vec = vec![];
            for w in buf.chunks_exact(2) {
                let s = u16::from_ne_bytes(w.try_into().unwrap());
                vec.push(s);
            }
            Some(format!("{}", String::from_utf16_lossy(&vec)))
        },
        |value| {
            let mut out = vec![];
            for v in value.encode_utf16() {
                out.extend(v.to_ne_bytes().iter().copied());
            }
            Some(out.into_boxed_slice())
        },
    ),
    Type(
        "i128",
        Some(16),
        |buf| Some(format!("{}", i128::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i128>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i64",
        Some(8),
        |buf| Some(format!("{}", i64::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i64>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i32",
        Some(4),
        |buf| Some(format!("{}", i32::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i32>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i16",
        Some(2),
        |buf| Some(format!("{}", i16::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i16>().ok()?.to_ne_bytes())),
    ),
    Type(
        "i8",
        Some(1),
        |buf| Some(format!("{}", i8::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<i8>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u128",
        Some(16),
        |buf| Some(format!("{}", u128::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u128>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u64",
        Some(8),
        |buf| Some(format!("{}", u64::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u64>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u32",
        Some(4),
        |buf| Some(format!("{}", u32::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u32>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u16",
        Some(2),
        |buf| Some(format!("{}", u16::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u16>().ok()?.to_ne_bytes())),
    ),
    Type(
        "u8",
        Some(1),
        |buf| Some(format!("{}", u8::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<u8>().ok()?.to_ne_bytes())),
    ),
    Type(
        "f64",
        Some(8),
        |buf| Some(format!("{}", f64::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<f64>().ok()?.to_ne_bytes())),
    ),
    Type(
        "f32",
        Some(4),
        |buf| Some(format!("{}", f32::from_ne_bytes(buf.try_into().ok()?))),
        |value| Some(Box::from(value.parse::<f32>().ok()?.to_ne_bytes())),
    ),
];

pub fn print_value(buf: &[u8], typename: &str) -> Option<String> {
    TYPES
        .iter()
        .filter(|Type(name, _, _, _)| name == &typename)
        .next()
        .and_then(|Type(_, _, pfn, _)| pfn(buf))
}

pub fn parse_input(input: &str, opt_typename: &Option<String>) -> Option<(Box<[u8]>, String)> {
    let (typename, value) = if let Some(t) = opt_typename {
        (t.as_str(), input)
    } else {
        let mut words = input.splitn(2, " ");
        (words.next()?, words.next()?)
    };

    let b = TYPES
        .iter()
        .filter(|Type(name, _, _, _)| name == &typename)
        .next()?
        .3(value)?;

    Some((b, typename.to_string()))
}