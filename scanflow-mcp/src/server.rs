//! The MCP server: `#[tool_router]` + `#[tool]` handlers + `ServerHandler`.
//!
//! All tools either operate on the [`SessionManager`] directly (session
//! lifecycle, process discovery) or lock a session and delegate to its
//! [`AnySession`] dispatch methods. Results are returned as JSON text blocks.

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
};

use crate::session_mgr::{AnySession, SessionInfo, SessionManager, SharedSession};

use memflow::types::Address;

/// The scanflow MCP server.
pub struct ScanflowServer {
    mgr: Arc<SessionManager>,
    #[allow(dead_code)]
    tool_router: ToolRouter<ScanflowServer>,
}

#[tool_router]
impl ScanflowServer {
    pub fn new() -> Self {
        Self {
            mgr: Arc::new(SessionManager::new()),
            tool_router: Self::tool_router(),
        }
    }

    // ---- session lifecycle ----

    #[tool(
        description = "Attach to a process and create a new scan session. `connectors` and `os` are memflow chain entries (e.g. connectors=[\"qemu_procfs\"], os=[\"win32\"]). Open by `program` name or by `pid`. If several processes share the name, the error lists all candidate PIDs — re-call with `pid` to pick one. Returns the new session id."
    )]
    async fn attach_process(
        &self,
        Parameters(args): Parameters<AttachProcessArgs>,
    ) -> Result<CallToolResult, McpError> {
        use crate::session_mgr::AttachOutcome;
        let outcome = self
            .mgr
            .attach_process(
                &args.connectors,
                &args.os,
                args.program.as_deref(),
                args.pid,
            )
            .map_err(mcp_err)?;
        match outcome {
            AttachOutcome::Session(id) => {
                text_result(serde_json::json!({ "session_id": id, "kind": "process" }))
            }
            AttachOutcome::Ambiguous {
                program,
                candidates,
            } => {
                let list = candidates
                    .iter()
                    .map(|c| format!("pid={} name={} state={:?}", c.pid, c.name, c.state))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(McpError::new(
                    ErrorCode::INVALID_PARAMS,
                    format!(
                        "{} processes are named `{}`; re-call attach_process with `pid` to pick one. Candidates: {}",
                        candidates.len(),
                        program,
                        list,
                    ),
                    None,
                ))
            }
            AttachOutcome::NotFound(name) => Err(McpError::new(
                ErrorCode::RESOURCE_NOT_FOUND,
                format!("no process named `{}` is running", name),
                None,
            )),
            AttachOutcome::NoTarget => Err(McpError::new(
                ErrorCode::INVALID_PARAMS,
                "attach_process requires `program` or `pid`".to_string(),
                None,
            )),
        }
    }

    #[tool(
        description = "Attach to a raw physical memory view via a connector chain and create a new view session (no process-only operations). Returns the new session id."
    )]
    async fn attach_view(
        &self,
        Parameters(args): Parameters<AttachViewArgs>,
    ) -> Result<CallToolResult, McpError> {
        let id = self
            .mgr
            .attach_view(&args.connectors, &args.os)
            .map_err(mcp_err)?;
        text_result(serde_json::json!({ "session_id": id, "kind": "view" }))
    }

    #[tool(
        description = "List running processes of an OS chain without creating a session. Useful to discover the target `program` name before `attach_process`."
    )]
    async fn list_processes(
        &self,
        Parameters(args): Parameters<ChainArgs>,
    ) -> Result<CallToolResult, McpError> {
        let procs = self
            .mgr
            .list_processes(&args.connectors, &args.os)
            .map_err(mcp_err)?;
        text_result(serde_json::json!(
            procs
                .iter()
                .map(|p| serde_json::json!({ "pid": p.pid, "name": p.name, "state": format!("{:?}", p.state) }))
                .collect::<Vec<_>>()
        ))
    }

    #[tool(description = "List all active sessions.")]
    async fn list_sessions(&self) -> Result<CallToolResult, McpError> {
        let sessions: Vec<SessionInfo> = self.mgr.list();
        text_result(serde_json::json!(sessions))
    }

    #[tool(description = "Drop (detach) a session by id.")]
    async fn detach_session(
        &self,
        Parameters(args): Parameters<SessionIdArg>,
    ) -> Result<CallToolResult, McpError> {
        let removed = self.mgr.detach(&args.session_id);
        text_result(serde_json::json!({ "detached": removed, "session_id": args.session_id }))
    }

    // ---- value scanning (shared) ----

    #[tool(
        description = "First-pass value scan: scan the session's whole address space for `value` parsed as `type_name` (str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64). Stores the matches and returns the count plus the first few addresses."
    )]
    async fn scan_value(
        &self,
        Parameters(args): Parameters<ScanValueArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let res = g
            .scan_value(&args.type_name, &args.value)
            .map_err(mcp_err)?;
        text_result(scan_summary(&res, &g))
    }

    #[tool(
        description = "Filter the session's existing matches against a new `value` (parsed with the currently selected type). Requires a prior `scan_value` or `set_type`."
    )]
    async fn filter_value(
        &self,
        Parameters(args): Parameters<FilterValueArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let res = g.filter_value(&args.value).map_err(mcp_err)?;
        text_result(scan_summary(&res, &g))
    }

    #[tool(
        description = "Scan memory for an IDA-style byte pattern (space-separated hex bytes, `?` or `??` for wildcards). Replaces the match list with the hits."
    )]
    async fn sig_scan(
        &self,
        Parameters(args): Parameters<SigScanArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let res = g.sig_scan(&args.pattern).map_err(mcp_err)?;
        text_result(scan_summary(&res, &g))
    }

    #[tool(
        description = "Read up to `max` matches back as typed values (requires a selected type)."
    )]
    async fn get_matches(
        &self,
        Parameters(args): Parameters<GetMatchesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let max = args.max.unwrap_or(64);
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let rows = g.read_matches(max).map_err(mcp_err)?;
        text_result(serde_json::json!({
            "count": g.match_count(),
            "matches": rows.iter().map(|m| serde_json::json!({
                "address": format!("{:x}", m.address),
                "value": m.value,
            })).collect::<Vec<_>>(),
        }))
    }

    // ---- raw memory read/write (shared) ----

    #[tool(
        description = "Read `len` raw bytes at `addr` (hex). Returns the bytes as a hex string."
    )]
    async fn read_memory(
        &self,
        Parameters(args): Parameters<ReadMemoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let addr = parse_addr(&args.addr)?;
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let data = g.read_memory(addr, args.len).map_err(mcp_err)?;
        text_result(serde_json::json!({
            "address": format!("{:x}", addr),
            "length": data.len(),
            "hex": hex::encode(&data),
        }))
    }

    #[tool(
        description = "Write raw `data` (hex string, e.g. \"4D 5A\" or \"4D5A\") to `addr` (hex)."
    )]
    async fn write_memory(
        &self,
        Parameters(args): Parameters<WriteMemoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let addr = parse_addr(&args.addr)?;
        let data = parse_hex_bytes(&args.data)?;
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        g.write_memory(addr, &data).map_err(mcp_err)?;
        text_result(serde_json::json!({ "written": data.len(), "address": format!("{:x}", addr) }))
    }

    #[tool(description = "Reset a session: clear matches, pointer map, disasm state, and type.")]
    async fn reset_session(
        &self,
        Parameters(args): Parameters<SessionIdArg>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        g.reset();
        text_result(serde_json::json!({ "reset": true, "session_id": args.session_id }))
    }

    #[tool(
        description = "Select / re-interpret the session's value type. `len` is required only for unsized types (str, str_utf16)."
    )]
    async fn set_type(
        &self,
        Parameters(args): Parameters<SetTypeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        g.set_type(&args.type_name, args.len).map_err(mcp_err)?;
        text_result(serde_json::json!({ "type": args.type_name, "len": args.len }))
    }

    // ---- process-only operations ----

    #[tool(description = "List loaded modules in the target process (process sessions only).")]
    async fn list_modules(
        &self,
        Parameters(args): Parameters<SessionIdArg>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let mods = g.list_modules().map_err(mcp_err)?;
        text_result(serde_json::json!(
            mods.iter()
                .map(|m| serde_json::json!({ "name": m.name, "base": format!("{:x}", m.base), "size": m.size }))
                .collect::<Vec<_>>()
        ))
    }

    #[tool(description = "Build (rebuild) the pointer map (process sessions only).")]
    async fn build_pointer_map(
        &self,
        Parameters(args): Parameters<SessionIdArg>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        g.build_pointer_map().map_err(mcp_err)?;
        text_result(serde_json::json!({ "pointer_map": "built", "session_id": args.session_id }))
    }

    #[tool(
        description = "Find global variables referenced by code. `module` restricts the search to a single module; omit for all modules. Returns the count. (process sessions only)"
    )]
    async fn collect_globals(
        &self,
        Parameters(args): Parameters<CollectGlobalsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let n = g.collect_globals(args.module.as_deref()).map_err(mcp_err)?;
        text_result(serde_json::json!({ "globals": n, "session_id": args.session_id }))
    }

    #[tool(
        description = "Generate IDA-style code signatures for a global `addr` (hex). Run `collect_globals` first. (process sessions only)"
    )]
    async fn sigmaker(
        &self,
        Parameters(args): Parameters<AddrSessionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let addr = parse_addr(&args.addr)?;
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let sigs = g.sigmaker(addr).map_err(mcp_err)?;
        text_result(serde_json::json!({ "signatures": sigs }))
    }

    #[tool(
        description = "Find pointer chains from binary globals (or the whole pointer map) to the current matches. `use_disasm` uses disassembler-found globals. `lrange`/`urange` bound the address delta; `max_depth` limits the chain depth; optional `filter` (hex) keeps only chains starting at that address. (process sessions only)"
    )]
    async fn offset_scan(
        &self,
        Parameters(args): Parameters<OffsetScanArgs>,
    ) -> Result<CallToolResult, McpError> {
        let filter = match args.filter.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_addr(s)?),
            _ => None,
        };
        let session = self.require_session(&args.session_id)?;
        let mut g = session.lock().await;
        let matches = g
            .offset_scan(
                args.use_disasm,
                args.lrange,
                args.urange,
                args.max_depth,
                filter,
            )
            .map_err(mcp_err)?;
        text_result(serde_json::json!({
            "count": matches.len(),
            "matches": matches.iter().take(64).map(|m| serde_json::json!({
                "target": format!("{:x}", m.target),
                "chain": m.chain.iter().map(|(a, o)| serde_json::json!({
                    "addr": format!("{:x}", a), "off": o,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }))
    }
}

impl ScanflowServer {
    /// Look up a session by id.
    fn require_session(&self, id: &str) -> Result<SharedSession, McpError> {
        self.mgr.get(id).ok_or_else(|| {
            McpError::new(
                ErrorCode::RESOURCE_NOT_FOUND,
                format!("session `{}` not found", id),
                None,
            )
        })
    }
}

#[tool_handler]
impl ServerHandler for ScanflowServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "scanflow-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "scanflow MCP server: memory scanning over memflow. Use `attach_process` or \
             `attach_view` to create a session, then `scan_value`/`filter_value`/`sig_scan` \
             to find memory, `get_matches`/`read_memory` to read it, and `offset_scan`/\
             `sigmaker` to build pointers/signatures. All session-scoped tools take a \
             `session_id`."
                    .to_string(),
            )
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}

// ---- helpers ----

fn mcp_err(e: memflow::error::Error) -> McpError {
    McpError::new(ErrorCode::INTERNAL_ERROR, format!("{}", e), None)
}

fn text_result(v: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
    )]))
}

fn scan_summary(res: &scanflow::ScanResult, g: &AnySession) -> serde_json::Value {
    serde_json::json!({
        "count": res.count(),
        "is_initial_scan": res.is_initial_scan,
        "type": g.typename(),
        "first_matches": res.matches.iter().take(64).map(|a| format!("{:x}", a)).collect::<Vec<_>>(),
    })
}

fn parse_addr(s: &str) -> Result<memflow::types::Address, McpError> {
    let s = s.trim().trim_start_matches("0x");
    u64::from_str_radix(s, 16).map(Address::from).map_err(|e| {
        McpError::new(
            ErrorCode::INVALID_PARAMS,
            format!("invalid address `{}`: {}", s, e),
            None,
        )
    })
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, McpError> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = cleaned.trim_start_matches("0x");
    if !s.len().is_multiple_of(2) {
        return Err(McpError::new(
            ErrorCode::INVALID_PARAMS,
            "hex byte string has odd length".to_string(),
            None,
        ));
    }
    let bytes = hex::decode(s).map_err(|e| {
        McpError::new(
            ErrorCode::INVALID_PARAMS,
            format!("invalid hex bytes: {}", e),
            None,
        )
    })?;
    Ok(bytes)
}

// ---- tool argument structs ----

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AttachProcessArgs {
    pub connectors: Vec<String>,
    pub os: Vec<String>,
    /// Process name to open. Mutually exclusive with `pid`; `pid` wins if both are given.
    pub program: Option<String>,
    /// Exact PID to open. Use when several processes share `program`.
    pub pid: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AttachViewArgs {
    pub connectors: Vec<String>,
    pub os: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ChainArgs {
    pub connectors: Vec<String>,
    pub os: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SessionIdArg {
    /// The session id returned by `attach_process` / `attach_view`.
    pub session_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanValueArgs {
    pub session_id: String,
    /// Value type: str, str_utf16, i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, f32, f64.
    pub type_name: String,
    /// The value to scan for.
    pub value: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FilterValueArgs {
    pub session_id: String,
    pub value: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SigScanArgs {
    pub session_id: String,
    /// IDA-style pattern, e.g. "4D 85 C0 ? ? ? 4D 8B 40 ?".
    pub pattern: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetMatchesArgs {
    pub session_id: String,
    /// Maximum number of matches to read back (default 64).
    pub max: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ReadMemoryArgs {
    pub session_id: String,
    /// Hex address, e.g. "0x7ff12345" or "7ff12345".
    pub addr: String,
    pub len: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WriteMemoryArgs {
    pub session_id: String,
    /// Hex address.
    pub addr: String,
    /// Hex bytes, e.g. "4D 5A" or "4D5A".
    pub data: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SetTypeArgs {
    pub session_id: String,
    pub type_name: String,
    /// Required only for str / str_utf16.
    pub len: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CollectGlobalsArgs {
    pub session_id: String,
    /// Restrict to a single module; omit for all modules.
    pub module: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddrSessionArgs {
    pub session_id: String,
    /// Hex address.
    pub addr: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct OffsetScanArgs {
    pub session_id: String,
    /// Use disassembler-found globals (true) or the whole pointer map (false).
    pub use_disasm: bool,
    pub lrange: usize,
    pub urange: usize,
    pub max_depth: usize,
    /// Optional hex filter address.
    pub filter: Option<String>,
}
