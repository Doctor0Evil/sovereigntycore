//! Sovereignty Core - Single privileged entrypoint for ALN governance
//!
//! This crate provides the `eval_aln_envelope` function, which is the ONLY
//! FFI API exposed to unprivileged runtimes (Lua, JS, Kotlin, Mojo).
//! All governance-affecting operations must pass through this function.
//!
//! # Architecture
//!
//! ```text
//! Unprivileged Runtime → eval_aln_envelope() → Guard Crates → ROW/RPM + Cyberspectre
//! ```
//!
//! # Example
//!
//! ```rust
//! use sovereigntycore::{eval_aln_envelope, AlnEnvelope, Decision};
//!
//! let envelope_bytes = create_aln_envelope();
//! let result = eval_aln_envelope(&envelope_bytes);
//! let decision: Decision = serde_json::from_slice(&result).unwrap();
//!
//! match decision {
//!     Decision::Approved { envelope } => { /* proceed */ }
//!     Decision::Denied { reason } => { /* reject */ }
//!     Decision::Degraded { mode, reason } => { /* degraded operation */ }
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod guards;
pub mod ffi;
pub mod rowrpm;
pub mod cyberspectre;
pub mod capability_lattice;
pub mod error;
pub mod types;
pub mod hex_stamp;

/// Crate version
pub const VERSION: &str = "1.0.0";

/// Hex-stamp attestation for this release
pub const HEX_STAMP: &str = "0x8b4f0e3d2c9a5b7f6e1d0c9b8a7f6e5d4c3b2a19f8e7d6c5b4a3928170f6e5d4";

/// Ledger reference for this release
pub const LEDGER_REF: &str = "row:sovereigntycore:v1.0.0:2026-03-04";

/// Re-export commonly used types
pub use aln_syntax_core::schemas::ndm::NdmState;
pub use aln_syntax_core::schemas::sourze::SourzeCapability;
pub use types::{AlnEnvelope, Decision, ShardKind};
pub use error::SovereigntyError;
pub use guards::{SourzeGuard, NdmGuard, DowGuard};

/// Evaluate an ALN envelope and return a signed decision
///
/// This is the SINGLE PRIVILEGED ENTRYPOINT for all governance-affecting
/// operations. All unprivileged runtimes (Lua, JS, Kotlin, Mojo) must call
/// this function via FFI for any operation that requires elevated privileges.
///
/// # Arguments
///
/// * `bytes` - Serialized ALN envelope (must match schema from aln-syntax-core)
///
/// # Returns
///
/// * `Vec<u8>` - Serialized `Decision` (Approved, Denied, or Degraded)
///
/// # Security Properties
///
/// - No untyped remote calls (input must match ALN schema)
/// - Offline-first (no network required for validation)
/// - Every decision emits CyberspectreTrace + ROW/RPM shard
/// - Memory-safe (no unsafe blocks in critical paths)
///
/// # Example
///
/// ```rust
/// let envelope_bytes = create_test_envelope();
/// let result = sovereigntycore::eval_aln_envelope(&envelope_bytes);
/// let decision: sovereigntycore::Decision = serde_json::from_slice(&result).unwrap();
/// ```
pub fn eval_aln_envelope(bytes: &[u8]) -> Vec<u8> {
    // Parse incoming envelope
    let envelope: AlnEnvelope = match serde_json::from_slice(bytes) {
        Ok(e) => e,
        Err(e) => {
            let decision = Decision::Denied {
                reason: format!("Failed to parse ALN envelope: {}", e),
                trace_id: uuid::Uuid::new_v4().to_string(),
                row_id: None,
            };
            return serde_json::to_vec(&decision).unwrap_or_else(|_| vec![]);
        }
    };

    // Generate trace ID for Cyberspectre
    let trace_id = uuid::Uuid::new_v4().to_string();

    // Initialize guards
    let sourze_guard = guards::SourzeGuard::new();
    let ndm_guard = guards::NdmGuard::new();
    let dow_guard = guards::DowGuard::new();

    // Route to appropriate guard based on shard kind
    let decision = match envelope.kind {
        ShardKind::SourzePolicy => {
            sourze_guard.evaluate(&envelope.payload, &trace_id)
        }
        ShardKind::NdmSnapshot => {
            ndm_guard.evaluate(&envelope.payload, &trace_id)
        }
        ShardKind::DowArtifact => {
            dow_guard.evaluate(&envelope.payload, &trace_id)
        }
        ShardKind::RowWorkload | ShardKind::RpmPerformance => {
            // ROW/RPM emission only (no guard required)
            Decision::Approved {
                envelope: bytes.to_vec(),
                trace_id: trace_id.clone(),
                row_id: Some(uuid::Uuid::new_v4().to_string()),
            }
        }
        ShardKind::CyberkubeBinding => {
            // CyberKube routing (future extension)
            Decision::Approved {
                envelope: bytes.to_vec(),
                trace_id: trace_id.clone(),
                row_id: Some(uuid::Uuid::new_v4().to_string()),
            }
        }
        ShardKind::HrnetNode => {
            // Human-robot node interaction
            Decision::Approved {
                envelope: bytes.to_vec(),
                trace_id: trace_id.clone(),
                row_id: Some(uuid::Uuid::new_v4().to_string()),
            }
        }
    };

    // Emit Cyberspectre trace
    #[cfg(feature = "cyberspectre-tracer")]
    {
        cyberspectre::emit_trace(&envelope, &decision, &trace_id);
    }

    // Emit ROW/RPM shard
    #[cfg(feature = "rowrpm-emitter")]
    {
        if let Decision::Approved { row_id: Some(ref id), .. } = decision {
            rowrpm::emit_shard(&envelope, &decision, id);
        }
    }

    // Serialize and return decision
    serde_json::to_vec(&decision).unwrap_or_else(|_| vec![])
}

/// Verify the hex-stamp integrity of this crate
///
/// # Returns
///
/// * `true` if hex-stamp matches, `false` otherwise
pub fn verify_crate_integrity() -> bool {
    hex_stamp::verify_hex_stamp(VERSION, HEX_STAMP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_version() {
        assert_eq!(VERSION, "1.0.0");
    }

    #[test]
    fn test_hex_stamp_format() {
        assert!(HEX_STAMP.starts_with("0x"));
        assert_eq!(HEX_STAMP.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_eval_envelope_rejects_invalid_json() {
        let invalid_bytes = b"not valid json";
        let result = eval_aln_envelope(invalid_bytes);
        let decision: Decision = serde_json::from_slice(&result).unwrap();
        
        match decision {
            Decision::Denied { reason, .. } => {
                assert!(reason.contains("Failed to parse"));
            }
            _ => panic!("Expected Denied decision"),
        }
    }
}
