//! End-to-end integration test exercising the [`scanflow::Session`] pipeline
//! against memflow's in-process `DummyOs`.
//!
//! The dummy's `mapped_mem_range` only yields *modules* (not the process's
//! raw allocation), so we create a process with a module, write known values
//! into the module's address range, and then verify scanning/readback through
//! the typed `Session` API.

use memflow::dummy::{DummyMemory, DummyOs};
use memflow::prelude::v1::*;
use scanflow::Session;

/// Build a dummy process that has at least one scannable module, and return a
/// `Session` over it together with the first module's base address (a
/// guaranteed-readable, scannable region).
fn make_session() -> (
    Session<impl Process + MemoryView + Clone + 'static>,
    Address,
) {
    let mem = DummyMemory::new(size::mb(16));
    let mut os = DummyOs::new(mem);
    let pid = os.alloc_process_with_module(size::mb(8), &[]);
    let process = os.into_process_by_pid(pid).expect("into_process_by_pid");
    let mut session = Session::for_process(process);
    let modules = session.list_modules().expect("module_list");
    assert!(!modules.is_empty(), "dummy process should have a module");
    let base = modules[0].base;
    (session, base)
}

#[test]
fn dummy_value_scan_and_readback() {
    let (mut session, base) = make_session();

    // Write a known i64 into the scannable module range.
    let val: i64 = 0x1337; // 4919
    session
        .write_memory(base, &val.to_ne_bytes())
        .expect("write_memory");

    let res = session.scan_value("i64", "4919").expect("scan_value");
    assert!(
        res.count() >= 1,
        "expected at least one i64=4919 match in the module range"
    );

    let rows = session.read_matches(64).expect("read_matches");
    assert!(!rows.is_empty());
    for row in &rows {
        assert_eq!(
            row.value, "4919",
            "match at {:x} did not read back as 4919",
            row.address
        );
    }
}

#[test]
fn dummy_filter_narrows_matches() {
    let (mut session, base) = make_session();
    session
        .write_memory(base, &42i64.to_ne_bytes())
        .expect("write");

    let r1 = session.scan_value("i64", "42").expect("scan");
    assert!(r1.count() >= 1);

    // Memory unchanged -> filter keeps the same matches.
    let r2 = session.filter_value("42").expect("filter");
    assert_eq!(r2.count(), r1.count());

    // Filter for a value that isn't present -> drops to zero.
    let r3 = session.filter_value("999999").expect("filter-miss");
    assert_eq!(r3.count(), 0);
}

#[test]
fn dummy_raw_read_and_write() {
    let (mut session, base) = make_session();

    let bytes = [0xAAu8, 0xBB, 0xCC, 0xDD];
    session.write_memory(base, &bytes).expect("write");

    let read = session.read_memory(base, 4).expect("read");
    assert_eq!(read, vec![0xAA, 0xBB, 0xCC, 0xDD]);

    // Overwrite and read back.
    session.write_memory(base, &[1, 2, 3, 4]).expect("write2");
    let read2 = session.read_memory(base, 4).expect("read2");
    assert_eq!(read2, vec![1, 2, 3, 4]);
}

#[test]
fn dummy_sig_scan() {
    let (mut session, base) = make_session();
    let pattern_bytes = [0x4Du8, 0x85, 0xC0, 0x00, 0x00, 0x4D, 0x8B];
    session.write_memory(base, &pattern_bytes).expect("write");

    let res = session.sig_scan("4D 85 C0 ? ? 4D 8B").expect("sig_scan");
    assert!(res.count() >= 1, "signature not found in the module range");
}

#[test]
fn dummy_reset_and_set_type() {
    let (mut session, base) = make_session();
    session
        .write_memory(base, &7i64.to_ne_bytes())
        .expect("write");

    session.scan_value("i64", "7").expect("scan");
    assert!(!session.matches().is_empty());

    session.reset();
    assert!(session.matches().is_empty());
    assert!(session.typename().is_none());

    session.set_type("u32", None).expect("set_type");
    assert_eq!(session.typename(), Some("u32"));
}
