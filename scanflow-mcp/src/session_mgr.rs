//! Multi-session manager for the MCP server.
//!
//! Holds a memflow [`Inventory`] and a [`DashMap`] of named sessions. Each
//! session is either a *process* session (full command set) or a *view*
//! session (raw memory view, no process-only operations). Sessions are guarded
//! by a [`tokio::sync::Mutex`] because memflow's `MemoryView` is `Send` but not
//! `Sync` (see `PLAN.md` R1) — only one tool call may mutate a session at a
//! time.
//!
//! The two session kinds wrap two different concrete memflow types, so we
//! model them as an [`AnySession`] enum rather than a trait object (the
//! generic `Session<T>` is not dyn-safe).

use std::sync::Mutex as StdMutex;

use dashmap::DashMap;
use memflow::mem::phys_mem::PhysicalMemoryView;
use memflow::prelude::v1::*;
use tokio::sync::Mutex;

use scanflow::Session;

/// Concrete memflow process type returned by `OsInstance::into_process_by_name`.
pub type ProcessMem = IntoProcessInstanceArcBox<'static>;
/// Concrete memflow view type returned by `ConnectorInstance::into_phys_view`.
pub type ViewMem = PhysicalMemoryView<ConnectorInstanceArcBox<'static>>;

/// Either kind of session the MCP server can hold.
pub enum AnySession {
    Process(Session<ProcessMem>),
    View(Session<ViewMem>),
}

impl AnySession {
    pub fn is_process(&self) -> bool {
        matches!(self, AnySession::Process(_))
    }

    pub fn target_name(&self) -> String {
        match self {
            AnySession::Process(s) => s.target_name().to_string(),
            AnySession::View(s) => s.target_name().to_string(),
        }
    }

    pub fn typename(&self) -> Option<String> {
        match self {
            AnySession::Process(s) => s.typename().map(str::to_string),
            AnySession::View(s) => s.typename().map(str::to_string),
        }
    }

    #[allow(dead_code)]
    pub fn matches_snapshot(&self) -> Vec<Address> {
        match self {
            AnySession::Process(s) => s.matches().to_vec(),
            AnySession::View(s) => s.matches().to_vec(),
        }
    }

    pub fn match_count(&self) -> usize {
        match self {
            AnySession::Process(s) => s.matches().len(),
            AnySession::View(s) => s.matches().len(),
        }
    }
}

// ---- shared (process + view) dispatch -------------------------------------

impl AnySession {
    pub fn scan_value(&mut self, type_name: &str, value: &str) -> Result<scanflow::ScanResult> {
        match self {
            AnySession::Process(s) => s.scan_value(type_name, value),
            AnySession::View(s) => s.scan_value(type_name, value),
        }
    }

    pub fn filter_value(&mut self, value: &str) -> Result<scanflow::ScanResult> {
        match self {
            AnySession::Process(s) => s.filter_value(value),
            AnySession::View(s) => s.filter_value(value),
        }
    }

    pub fn sig_scan(&mut self, pattern: &str) -> Result<scanflow::ScanResult> {
        match self {
            AnySession::Process(s) => s.sig_scan(pattern),
            AnySession::View(s) => s.sig_scan(pattern),
        }
    }

    pub fn read_matches(&mut self, max: usize) -> Result<Vec<scanflow::MatchDisplay>> {
        match self {
            AnySession::Process(s) => s.read_matches(max),
            AnySession::View(s) => s.read_matches(max),
        }
    }

    pub fn read_memory(&mut self, addr: Address, len: usize) -> Result<Vec<u8>> {
        match self {
            AnySession::Process(s) => s.read_memory(addr, len),
            AnySession::View(s) => s.read_memory(addr, len),
        }
    }

    pub fn write_memory(&mut self, addr: Address, data: &[u8]) -> Result<()> {
        match self {
            AnySession::Process(s) => s.write_memory(addr, data),
            AnySession::View(s) => s.write_memory(addr, data),
        }
    }

    pub fn reset(&mut self) {
        match self {
            AnySession::Process(s) => s.reset(),
            AnySession::View(s) => s.reset(),
        }
    }

    pub fn set_type(&mut self, type_name: &str, len: Option<usize>) -> Result<()> {
        match self {
            AnySession::Process(s) => s.set_type(type_name, len),
            AnySession::View(s) => s.set_type(type_name, len),
        }
    }
}

// ---- process-only dispatch (errors for view sessions) ---------------------

const VIEW_NOT_SUPPORTED: ErrorKind = ErrorKind::InvalidArgument;

impl AnySession {
    pub fn build_pointer_map(&mut self) -> Result<()> {
        match self {
            AnySession::Process(s) => s.build_pointer_map(),
            AnySession::View(_) => Err(VIEW_NOT_SUPPORTED.into()),
        }
    }

    pub fn collect_globals(&mut self, module: Option<&str>) -> Result<usize> {
        match self {
            AnySession::Process(s) => s.collect_globals(module),
            AnySession::View(_) => Err(VIEW_NOT_SUPPORTED.into()),
        }
    }

    pub fn sigmaker(&mut self, addr: Address) -> Result<Vec<String>> {
        match self {
            AnySession::Process(s) => s.sigmaker(addr),
            AnySession::View(_) => Err(VIEW_NOT_SUPPORTED.into()),
        }
    }

    pub fn offset_scan(
        &mut self,
        use_disasm: bool,
        lrange: usize,
        urange: usize,
        max_depth: usize,
        filter: Option<Address>,
    ) -> Result<Vec<scanflow::OffsetMatch>> {
        match self {
            AnySession::Process(s) => s.offset_scan(use_disasm, lrange, urange, max_depth, filter),
            AnySession::View(_) => Err(VIEW_NOT_SUPPORTED.into()),
        }
    }

    pub fn list_modules(&mut self) -> Result<Vec<ModuleInfo>> {
        match self {
            AnySession::Process(s) => s.list_modules(),
            AnySession::View(_) => Err(VIEW_NOT_SUPPORTED.into()),
        }
    }
}

/// A session shared between the manager and concurrent tool calls.
pub type SharedSession = std::sync::Arc<Mutex<AnySession>>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub kind: String,
    pub target: String,
}

/// Outcome of [`SessionManager::attach_process`]: either a created session,
/// or a structured error the caller (MCP tool) should surface to the user.
#[derive(Debug)]
pub enum AttachOutcome {
    /// A session was created; this is its id.
    Session(String),
    /// Several processes matched the name — the caller should show these
    /// candidates (pid/name/state) and ask the user to re-call with `pid`.
    Ambiguous {
        program: String,
        candidates: Vec<ProcessInfo>,
    },
    /// No process matched the name.
    NotFound(String),
    /// Neither `program` nor `pid` was supplied.
    NoTarget,
}

/// Owns the memflow inventory and all active sessions.
pub struct SessionManager {
    /// memflow plugin inventory. Guarded by a sync mutex because
    /// `Inventory::builder()` takes `&mut self`; it's only locked briefly
    /// during session creation.
    inventory: StdMutex<Inventory>,
    sessions: DashMap<String, SharedSession>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            inventory: StdMutex::new(Inventory::scan()),
            sessions: DashMap::new(),
        }
    }

    /// Build an OS chain and attach to a process by name or PID.
    ///
    /// `pid` takes precedence over `program`. If neither is given, returns
    /// [`AttachOutcome::NoTarget`]. If `program` matches several processes,
    /// returns [`AttachOutcome::Ambiguous`] with the candidate list (so the
    /// caller — e.g. the MCP tool — can surface the PIDs to the user instead
    /// of silently grabbing the first).
    pub fn attach_process(
        &self,
        connectors: &[String],
        os: &[String],
        program: Option<&str>,
        pid: Option<u32>,
    ) -> Result<AttachOutcome> {
        let chain = build_os_chain(connectors, os)?;
        let mut os_inst = {
            let mut inv = self.inventory.lock().unwrap();
            inv.builder().os_chain(chain).build()?
        };

        if let Some(pid) = pid {
            let process = os_inst.into_process_by_pid(pid)?;
            let id = self.store(AnySession::Process(Session::for_process(process)))?;
            return Ok(AttachOutcome::Session(id));
        }

        let name = match program {
            Some(n) => n,
            None => return Ok(AttachOutcome::NoTarget),
        };

        let matching: Vec<ProcessInfo> = os_inst
            .process_info_list()?
            .into_iter()
            .filter(|i| i.name.as_ref() == name)
            .collect();

        match matching.len() {
            0 => Ok(AttachOutcome::NotFound(name.to_string())),
            1 => {
                let process = os_inst.into_process_by_info(matching.into_iter().next().unwrap())?;
                let id = self.store(AnySession::Process(Session::for_process(process)))?;
                Ok(AttachOutcome::Session(id))
            }
            _ => Ok(AttachOutcome::Ambiguous {
                program: name.to_string(),
                candidates: matching,
            }),
        }
    }

    /// Build a connector chain and store a raw memory view session.
    pub fn attach_view(&self, connectors: &[String], os: &[String]) -> Result<String> {
        let chain = build_connector_chain(connectors, os)?;
        let conn = {
            let mut inv = self.inventory.lock().unwrap();
            inv.builder().connector_chain(chain).build()?
        };
        let view = conn.into_phys_view();
        let session = Session::for_view(view);
        self.store(AnySession::View(session))
    }

    /// List running processes of an OS without creating a session.
    pub fn list_processes(&self, connectors: &[String], os: &[String]) -> Result<Vec<ProcessInfo>> {
        let chain = build_os_chain(connectors, os)?;
        let mut os_inst = {
            let mut inv = self.inventory.lock().unwrap();
            inv.builder().os_chain(chain).build()?
        };
        os_inst.process_info_list()
    }

    fn store(&self, session: AnySession) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.sessions
            .insert(id.clone(), std::sync::Arc::new(Mutex::new(session)));
        Ok(id)
    }

    /// Look up a shared session by id.
    pub fn get(&self, id: &str) -> Option<SharedSession> {
        self.sessions
            .get(id)
            .map(|r| std::sync::Arc::clone(r.value()))
    }

    /// Remove (drop) a session by id. Returns true if it existed.
    pub fn detach(&self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Snapshot of all sessions.
    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .map(|r| {
                let s = r.value().blocking_lock();
                SessionInfo {
                    id: r.key().clone(),
                    kind: if s.is_process() {
                        "process".into()
                    } else {
                        "view".into()
                    },
                    target: s.target_name(),
                }
            })
            .collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an OsChain from string args. Mirrors scanflow-cli build_chain.
fn build_os_chain<'a>(connectors: &'a [String], os: &'a [String]) -> Result<OsChain<'a>> {
    let conn_it = || connectors.iter().enumerate().map(|(i, s)| (i, s.as_str()));
    let os_it = || os.iter().enumerate().map(|(i, s)| (i, s.as_str()));
    OsChain::new(conn_it(), os_it())
}

fn build_connector_chain<'a>(
    connectors: &'a [String],
    os: &'a [String],
) -> Result<ConnectorChain<'a>> {
    let conn_it = || connectors.iter().enumerate().map(|(i, s)| (i, s.as_str()));
    let os_it = || os.iter().enumerate().map(|(i, s)| (i, s.as_str()));
    ConnectorChain::new(conn_it(), os_it())
}
