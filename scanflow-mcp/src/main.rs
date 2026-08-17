//! scanflow-mcp entry point: a stdio MCP server exposing scanflow's memory
//! scanning capabilities to AI agents.
//!
//! Run directly:
//!     scanflow-mcp
//! Or wire into an MCP client (e.g. Claude Desktop) via stdio. HTTP/SSE
//! transport can be bridged later with a tool like `mcporter`/`supergateway`.

use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::{self, EnvFilter};

mod server;
mod session_mgr;

use server::ScanflowServer;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("starting scanflow-mcp (stdio)");

    let service = ScanflowServer::new()
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("serving error: {:?}", e))?;

    service.waiting().await?;
    Ok(())
}
