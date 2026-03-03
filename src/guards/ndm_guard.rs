//! NDM Guard - Enforce monotone NDM state transitions and K-score thresholds
//!
//! This guard evaluates NDM snapshots against:
//! - Monotone degradation (no state upgrades)
//! - K-score thresholds for state transitions
//! - Irreversible transition enforcement (ObserveOnly → Freeze → Quarantine)
//! - Suspicion trigger tracking

use crate::types::Decision;
use crate::error::SovereigntyError;
use crate::hex_stamp;
use aln_syntax_core::schemas::ndm::{NdmSnapshot, NdmState, NdmThresholds};
use aln_syntax_core::validator::SchemaValidator;
use uuid::Uuid;
use serde_json::Value;

/// NDM state evaluation guard
pub struct NdmGuard {
    validator: SchemaValidator,
    thresholds: NdmThresholds,
}

impl NdmGuard {
    /// Create a new NDM guard
    pub fn new() -> Self {
        Self {
            validator: SchemaValidator::new(),
            thresholds: NdmThresholds::default(),
        }
    }

    /// Set custom thresholds
    pub fn with_thresholds(mut self, thresholds: NdmThresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Evaluate an NDM snapshot
    ///
    /// # Arguments
    ///
    /// * `payload` - JSON payload containing NdmSnapshot
    /// * `trace_id` - Cyberspectre trace ID for audit
    ///
    /// # Returns
    ///
    /// * `Decision` - Approved, Denied, or Degraded (with mode)
    pub fn evaluate(&self, payload: &Value, trace_id: &str) -> Decision {
        // Parse snapshot
        let snapshot: NdmSnapshot = match serde_json::from_value(payload.clone()) {
            Ok(s) => s,
            Err(e) => {
                return Decision::Denied {
                    reason: format!("Failed to parse NdmSnapshot: {}", e),
                    trace_id: trace_id.to_string(),
                    row_id: None,
                };
            }
        };

        // Validate against schema
        if let Err(e) = self.validator.validate_ndm(&snapshot) {
            return Decision::Denied {
                reason: format!("Schema validation failed: {}", e),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Verify monotone degradation (no state upgrades)
        if snapshot.current_state < snapshot.previous_state {
            return Decision::Denied {
                reason: format!(
                    "NDM state upgrade not allowed: {:?} → {:?}",
                    snapshot.previous_state, snapshot.current_state
                ),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Verify K-score matches state
        let expected_state = self.determine_state_from_k_score(snapshot.k_score);
        if snapshot.current_state != expected_state {
            return Decision::Denied {
                reason: format!(
                    "K-score {:.2} does not match state {:?}",
                    snapshot.k_score, snapshot.current_state
                ),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Check for auto-freeze threshold
        if snapshot.k_score >= self.thresholds.auto_freeze_threshold {
            return Decision::Degraded {
                mode: "Freeze".to_string(),
                reason: format!(
                    "K-score {:.2} exceeds auto-freeze threshold {:.2}",
                    snapshot.k_score, self.thresholds.auto_freeze_threshold
                ),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Check for quarantine threshold
        if snapshot.k_score >= self.thresholds.quarantine_ceiling {
            return Decision::Degraded {
                mode: "Quarantine".to_string(),
                reason: format!(
                    "K-score {:.2} exceeds quarantine threshold {:.2}",
                    snapshot.k_score, self.thresholds.quarantine_ceiling
                ),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Verify hex-stamp
        if !hex_stamp::verify_hex_stamp(&snapshot, &snapshot.hex_stamp) {
            return Decision::Denied {
                reason: "Hex-stamp verification failed".to_string(),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // All checks passed
        let row_id = Some(Uuid::new_v4().to_string());
        Decision::Approved {
            envelope: serde_json::to_vec(&snapshot).unwrap_or_default(),
            trace_id: trace_id.to_string(),
            row_id,
        }
    }

    /// Determine expected NDM state from K-score
    fn determine_state_from_k_score(&self, k_score: f64) -> NdmState {
        if k_score < self.thresholds.normal_ceiling {
            NdmState::Normal
        } else if k_score < self.thresholds.monitoring_ceiling {
            NdmState::Monitoring
        } else if k_score < self.thresholds.observe_only_ceiling {
            NdmState::ObserveOnly
        } else if k_score < self.thresholds.freeze_ceiling {
            NdmState::Freeze
        } else {
            NdmState::Quarantine
        }
    }
}

impl Default for NdmGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndm_guard_rejects_state_upgrade() {
        let guard = NdmGuard::new();
        let trace_id = Uuid::new_v4().to_string();

        // Create snapshot with invalid state upgrade (Monitoring → Normal)
        let payload = serde_json::json!({
            "session_id": Uuid::new_v4().to_string(),
            "timestamp": 1741104000,
            "k_score": 0.2,
            "r_score": 0.3,
            "e_score": 0.2,
            "current_state": "Normal",
            "previous_state": "Monitoring",
            "suspicion_triggers": [],
            "row_reference": "row:test:123",
            "cyberspectre_trace_id": "cyb:test:456",
            "hex_stamp": "0x1234567890abcdef"
        });

        let decision = guard.evaluate(&payload, &trace_id);
        
        match decision {
            Decision::Denied { reason, .. } => {
                assert!(reason.contains("state upgrade not allowed"));
            }
            _ => panic!("Expected Denied decision for state upgrade"),
        }
    }

    #[test]
    fn test_ndm_guard_triggers_auto_freeze() {
        let guard = NdmGuard::new();
        let trace_id = Uuid::new_v4().to_string();

        // Create snapshot with K-score above auto-freeze threshold
        let payload = serde_json::json!({
            "session_id": Uuid::new_v4().to_string(),
            "timestamp": 1741104000,
            "k_score": 0.75,
            "r_score": 0.3,
            "e_score": 0.2,
            "current_state": "Freeze",
            "previous_state": "ObserveOnly",
            "suspicion_triggers": ["capability_escalation_attempt"],
            "row_reference": "row:test:123",
            "cyberspectre_trace_id": "cyb:test:456",
            "hex_stamp": "0x1234567890abcdef"
        });

        let decision = guard.evaluate(&payload, &trace_id);
        
        match decision {
            Decision::Degraded { mode, .. } => {
                assert_eq!(mode, "Freeze");
            }
            _ => panic!("Expected Degraded decision for auto-freeze"),
        }
    }
}
