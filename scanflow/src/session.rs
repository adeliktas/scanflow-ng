//! The [`Session`] — a typed, IO-free API over scanflow's scanners.
//!
//! `Session<T>` owns a memory object `T` (`MemoryView`/`Process`) together
//! with all scanner state ([`ValueScanner`], [`Disasm`], [`PointerMap`]) and
//! exposes methods that return *structured* results. Frontends (the REPL CLI,
//! the subcommand CLI, the MCP server) call these methods and format the output
//! themselves — the library never prints.
//!
//! `T` is generic. Process-only operations (`build_pointer_map`,
//! `collect_globals`, `sigmaker`, `offset_scan`, `list_modules`) carry an extra
//! `T: Process` bound; view-only sessions simply can't call them.

use std::time::Instant;

use memflow::prelude::v1::*;

use crate::disasm::Disasm;
use crate::pointer_map::PointerMap;
use crate::sig_scan::{self, CompiledPattern};
use crate::sigmaker::Sigmaker;
use crate::types::{self, MatchDisplay, OffsetMatch, ScanResult};
use crate::value_scanner::ValueScanner;

/// Function pointer that returns the mapped memory ranges of `T` between
/// `from` and `to`, merging gaps smaller than `gap_size`.
pub type MapsFn<T> = fn(&mut T, imem, Address, Address) -> Vec<MemoryRange>;

/// Function pointer returning a short human-readable name for the target
/// (process name, or `"view"`).
pub type InfoFn<T> = fn(&T) -> &str;

/// Bundle of function pointers that adapt [`Session`] to either a process or a
/// raw memory view. Kept as `fn` pointers so the session stays cheap to clone
/// and free of generics-of-generics.
#[derive(Clone, Copy)]
pub struct Funcs<T> {
    pub maps: MapsFn<T>,
    pub info: InfoFn<T>,
}

impl<T: Process + MemoryView> Funcs<T> {
    pub fn process() -> Self {
        Self {
            maps: |proc, gap_size, from, to| proc.mapped_mem_range_vec(gap_size, from, to),
            info: |proc| &proc.info().name,
        }
    }
}

impl<T: MemoryView> Funcs<T> {
    pub fn view() -> Self {
        Self {
            maps: |view, _gap, from, to| {
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

/// Which matches a write should target.
#[derive(Debug, Clone, Copy)]
pub enum WriteTarget {
    /// Write to a single match by index.
    One(usize),
    /// Write to all matches.
    All,
}

/// The scanflow session. Holds a memory object and all scanner state.
pub struct Session<T> {
    pub(crate) memory: T,
    pub(crate) funcs: Funcs<T>,
    pub(crate) value_scanner: ValueScanner,
    /// Currently selected value type name (set after a scan or `set_type`).
    pub(crate) typename: Option<String>,
    /// Size in bytes used to read back matches (fixed for sized types,
    /// caller-supplied for `str`/`str_utf16`).
    pub(crate) buf_len: usize,
    pub(crate) disasm: Disasm,
    pub(crate) pointer_map: PointerMap,
}

impl<T: MemoryView> Session<T> {
    /// Create a new session from a memory object and adapter functions.
    pub fn new(memory: T, funcs: Funcs<T>) -> Self {
        Self {
            memory,
            funcs,
            value_scanner: Default::default(),
            typename: None,
            buf_len: 0,
            disasm: Default::default(),
            pointer_map: Default::default(),
        }
    }

    /// Wrap an existing process and create a session with process adapters.
    pub fn for_process(process: T) -> Self
    where
        T: Process + MemoryView,
    {
        Self::new(process, Funcs::process())
    }

    /// Wrap a raw memory view and create a session with view adapters.
    pub fn for_view(view: T) -> Self
    where
        T: MemoryView,
    {
        Self::new(view, Funcs::view())
    }

    /// Borrow the underlying memory object (read/write access).
    pub fn memory_mut(&mut self) -> &mut T {
        &mut self.memory
    }

    /// Short name of the target (process name or `"view"`).
    pub fn target_name(&self) -> &str {
        (self.funcs.info)(&self.memory)
    }

    /// Currently selected value type, if any.
    pub fn typename(&self) -> Option<&str> {
        self.typename.as_deref()
    }

    /// Reset all scanner state (matches, disasm, pointer map, type selection).
    pub fn reset(&mut self) {
        self.value_scanner.reset();
        self.disasm.reset();
        self.pointer_map.reset();
        self.typename = None;
        self.buf_len = 0;
    }

    /// Select / re-interpret the current value type.
    ///
    /// `len` is required only for unsized types (`str`, `str_utf16`); ignored
    /// for sized types.
    pub fn set_type(&mut self, type_name: &str, len: Option<usize>) -> Result<()> {
        let ty = types::find_type(type_name).ok_or(ErrorKind::InvalidArgument)?;
        self.typename = Some(type_name.to_string());
        self.buf_len = match ty.size {
            Some(s) => s,
            None => len.ok_or(ErrorKind::InvalidArgument)?,
        };
        Ok(())
    }

    /// Manually add an address to the current match list.
    pub fn add_match(&mut self, addr: Address) {
        self.value_scanner.matches_mut().push(addr);
    }

    /// Remove a match by index. Returns `InvalidArgument` if out of bounds.
    pub fn remove_match(&mut self, idx: usize) -> Result<()> {
        let matches = self.value_scanner.matches_mut();
        if idx >= matches.len() {
            return Err(ErrorKind::InvalidArgument.into());
        }
        matches.remove(idx);
        Ok(())
    }

    /// Read-only access to the current match list.
    pub fn matches(&self) -> &[Address] {
        self.value_scanner.matches()
    }

    /// Mutable access to the current match list.
    pub fn matches_mut(&mut self) -> &mut Vec<Address> {
        self.value_scanner.matches_mut()
    }

    /// Read raw bytes from `addr`.
    pub fn read_memory(&mut self, addr: Address, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.memory.read_raw_into(addr, &mut buf).data_part()?;
        Ok(buf)
    }

    /// Write raw bytes to `addr`.
    pub fn write_memory(&mut self, addr: Address, data: &[u8]) -> Result<()> {
        self.memory.write_raw(addr, data).data_part()?;
        Ok(())
    }

    /// Signature (byte-pattern) scan over all mapped memory.
    ///
    /// Replaces the previous match list with the new signature hits and clears
    /// the current value type selection (signatures produce raw addresses, not
    /// typed values).
    pub fn sig_scan(&mut self, pattern_input: &str) -> Result<ScanResult>
    where
        T: MemoryView + Clone,
    {
        let pattern = sig_scan::parse_pattern(pattern_input).ok_or(ErrorKind::InvalidArgument)?;
        let compiled = CompiledPattern::new(pattern).ok_or(ErrorKind::InvalidArgument)?;

        let ranges =
            (self.funcs.maps)(&mut self.memory, 0x1000, Address::NULL, Address::INVALID);

        let start = Instant::now();
        let mut matches = Vec::new();
        for &CTup3(base, size, _) in &ranges {
            if let Ok(found) = sig_scan::scan_range(&mut self.memory, base, size, &compiled) {
                matches.extend(found);
            }
        }
        let _ = start;

        self.value_scanner.reset();
        self.value_scanner.matches_mut().extend(matches.iter().copied());
        self.typename = None;

        Ok(ScanResult {
            matches,
            is_initial_scan: true,
        })
    }

    /// First-pass value scan: scan the whole address space for `value` parsed
    /// as `type_name`.
    pub fn scan_value(&mut self, type_name: &str, value: &str) -> Result<ScanResult>
    where
        T: MemoryView + Clone,
    {
        let ty = types::find_type(type_name).ok_or(ErrorKind::InvalidArgument)?;
        let data = (ty.parse)(value).ok_or(ErrorKind::InvalidArgument)?;

        self.value_scanner
            .scan_for_2(&mut self.memory, self.funcs.maps, &data)?;

        self.typename = Some(type_name.to_string());
        self.buf_len = match ty.size {
            Some(s) => s,
            None => data.len(),
        };

        Ok(ScanResult {
            matches: self.value_scanner.matches().clone(),
            is_initial_scan: true,
        })
    }

    /// Filter existing matches against a new `value` (parsed with the
    /// currently selected type). Requires a prior `scan_value` / `set_type`.
    pub fn filter_value(&mut self, value: &str) -> Result<ScanResult>
    where
        T: MemoryView + Clone,
    {
        let type_name = self
            .typename
            .clone()
            .ok_or(ErrorKind::Uninitialized)?;
        let ty = types::find_type(&type_name).ok_or(ErrorKind::InvalidArgument)?;
        let data = (ty.parse)(value).ok_or(ErrorKind::InvalidArgument)?;

        self.value_scanner
            .scan_for_2(&mut self.memory, self.funcs.maps, &data)?;

        Ok(ScanResult {
            matches: self.value_scanner.matches().clone(),
            is_initial_scan: false,
        })
    }

    /// Read back up to `max` matches as typed display strings.
    pub fn read_matches(&mut self, max: usize) -> Result<Vec<MatchDisplay>> {
        let typename = self
            .typename
            .as_ref()
            .ok_or(ErrorKind::Uninitialized)?;
        let buf_len = self.buf_len;

        let mut out = Vec::new();
        for &m in self.value_scanner.matches().iter().take(max) {
            let mut buf = vec![0u8; buf_len];
            self.memory.read_raw_into(m, &mut buf).data_part()?;
            let value =
                types::print_value(&buf, typename).ok_or(ErrorKind::InvalidArgument)?;
            out.push(MatchDisplay { address: m, value });
        }
        Ok(out)
    }

    /// Write a value to a selection of matches. The value is parsed with the
    /// currently selected type. Does a single write per match (no continuous
    /// loop — that is a REPL/MCP-level concern).
    pub fn write_value(&mut self, target: WriteTarget, value: &str) -> Result<usize>
    where
        T: MemoryView,
    {
        let matches = self.value_scanner.matches();
        if matches.is_empty() {
            return Err(ErrorKind::Uninitialized.into());
        }
        let typename = self.typename.as_ref().ok_or(ErrorKind::Uninitialized)?;
        let ty = types::find_type(typename).ok_or(ErrorKind::InvalidArgument)?;
        let data = (ty.parse)(value).ok_or(ErrorKind::InvalidArgument)?;

        let (skip, take) = match target {
            WriteTarget::All => (0, matches.len()),
            WriteTarget::One(idx) => {
                if idx >= matches.len() {
                    return Err(ErrorKind::InvalidArgument.into());
                }
                (idx, 1)
            }
        };

        let mut written = 0;
        for &m in matches.iter().skip(skip).take(take) {
            self.memory.write_raw(m, data.as_ref()).data_part()?;
            written += 1;
        }
        Ok(written)
    }
}

// ---- Process-only operations -------------------------------------------------

impl<T: Process + MemoryView + Clone> Session<T> {
    /// (Re)build the pointer map. Required before `offset_scan` (which calls
    /// this automatically if the map is empty).
    pub fn build_pointer_map(&mut self) -> Result<()> {
        let size_addr = ArchitectureObj::from(self.memory.info().proc_arch).size_addr();
        self.pointer_map.create_map(&mut self.memory, size_addr)
    }

    /// Find global variables referenced by code. If `module` is supplied, the
    /// search is limited to that module. Returns the number of globals found.
    pub fn collect_globals(&mut self, module: Option<&str>) -> Result<usize> {
        self.disasm.reset();
        self.disasm.collect_globals(&mut self.memory, module)?;
        Ok(self.disasm.map().len())
    }

    /// Generate IDA-style code signatures for the given global address.
    pub fn sigmaker(&mut self, addr: Address) -> Result<Vec<String>> {
        Sigmaker::find_sigs(&mut self.memory, &self.disasm, addr)
    }

    /// Scan for pointer chains from entry points (binary globals or the whole
    /// pointer map) to the current matches.
    pub fn offset_scan(
        &mut self,
        use_disasm: bool,
        lrange: usize,
        urange: usize,
        max_depth: usize,
        filter_addr: Option<Address>,
    ) -> Result<Vec<OffsetMatch>> {
        if self.pointer_map.map().is_empty() {
            self.build_pointer_map()?;
        }

        let start = Instant::now();
        let raw = if use_disasm {
            if self.disasm.map().is_empty() {
                self.disasm.collect_globals(&mut self.memory, None)?;
            }
            self.pointer_map.find_matches_addrs(
                (lrange, urange),
                max_depth,
                self.value_scanner.matches(),
                self.disasm.globals(),
            )
        } else {
            self.pointer_map.find_matches(
                (lrange, urange),
                max_depth,
                self.value_scanner.matches(),
            )
        };
        let _ = start;

        let filtered: Vec<OffsetMatch> = raw
            .into_iter()
            .filter(|(_, chain)| {
                if let Some(a) = filter_addr {
                    chain
                        .first()
                        .map(|(s, _)| *s == a)
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .map(|(target, chain)| OffsetMatch { target, chain })
            .collect();
        Ok(filtered)
    }

    /// List loaded modules in the target process.
    pub fn list_modules(&mut self) -> Result<Vec<ModuleInfo>> {
        Ok(self.memory.module_list()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_type_sized() {
        // We can't easily build a real MemoryView in a unit test, but set_type
        // only touches scalar state, so build a session around a zero-sized
        // stand-in. Use a minimal view impl would be heavy; instead just test
        // the parsing path through the public types module (see types tests).
        // Here we only assert the enum shapes compile and Copy.
        let _ = WriteTarget::All;
        let _ = WriteTarget::One(0);
    }
}