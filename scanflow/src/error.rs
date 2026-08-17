//! Error types for scanflow.
//!
//! scanflow's scanners are built on memflow, so the library returns
//! [`memflow`] errors directly. This module re-exports them under stable
//! `scanflow`-namespaced aliases so frontends don't have to depend on memflow's
//! exact module paths. If richer, scanflow-specific error variants become
//! necessary later, this is the place to introduce a `thiserror`-based enum.

pub use memflow::prelude::v1::Error as ScanflowError;
pub use memflow::prelude::v1::Result;
