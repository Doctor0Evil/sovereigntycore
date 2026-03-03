//! Cyberspectre Introspection Engine - Generate audit traces for all decisions
//!
//! This module emits CyberspectreTrace records for every privileged decision,
//! enabling full replay and forensic analysis of governance actions.

use crate::types::{Decision, AlnEnvelope};
use aln_syntax_core::schemas::cyberspectre::CyberspectreTrace;
use uuid::Uuid;
use chrono::Utc;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// Cyberspectre trace emitter
pub struct CyberspectreTracer {
    log_path: PathBuf,
    enabled: bool,
}

impl CyberspectreTracer {
    /// Create a new tracer
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            enabled: true,
        }
    }

    /// Enable/disable tracing
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Emit a trace for a decision
    ///
    /// # Arguments
    ///
    /// * `envelope` - Original ALN envelope
    /// * `decision` - Evaluation decision
    /// * `trace_id` - Unique trace identifier
    pub fn emit_trace(&self, envelope: &AlnEnvelope, decision: &Decision, trace_id: &str) {
        if !self.enabled {
            return;
        }

        let trace = CyberspectreTrace {
            trace_id: trace_id.to_string(),
            timestamp: Utc::now().timestamp(),
            envelope_kind: format!("{:?}", envelope.kind),
            decision: format!("{:?}", decision),
            row_id: match decision {
                Decision::Approved { row_id: Some(id), .. } => Some(id.clone()),
                _ => None,
            },
            node_path: vec!["sovereigntycore".to_string()],
            capabilities_invoked: vec![],
            effects: vec![],
        };

        // Append to trace log
        self.append_trace(&trace);
    }

    /// Append trace to log file
    fn append_trace(&self, trace: &CyberspectreTrace) {
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open trace log: {}", e);
                return;
            }
        };

        let json = serde_json::to_string(trace).unwrap_or_default();
        if let Err(e) = writeln!(file, "{}", json) {
            eprintln!("Failed to write trace: {}", e);
        }
    }
}

/// Emit a trace (convenience function)
pub fn emit_trace(envelope: &AlnEnvelope, decision: &Decision, trace_id: &str) {
    let tracer = CyberspectreTracer::new(PathBuf::from("/var/log/aln/cyberspectre.log"));
    tracer.emit_trace(envelope, decision, trace_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_trace_emission() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("trace.log");
        
        let tracer = CyberspectreTracer::new(log_path.clone());
        
        let envelope = AlnEnvelope {
            kind: crate::types::ShardKind::SourzePolicy,
            payload: serde_json::json!({}),
        };

        let decision = Decision::Approved {
            envelope: vec![],
            trace_id: "test-trace".to_string(),
            row_id: Some("test-row".to_string()),
        };

        tracer.emit_trace(&envelope, &decision, "test-trace");

        // Verify file was created
        assert!(log_path.exists());
    }
}
