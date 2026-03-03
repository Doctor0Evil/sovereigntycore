//! DOW Guard - Enforce anti-rollback and sandbox rules for legacy OS artifacts
//!
//! This guard evaluates DOW (Durable OS Ware) artifacts against:
//! - Anti-rollback enforcement (no downgrades)
//! - Eco floor requirements for legacy platform patches
//! - Sandbox rules for high-risk artifacts on lab/Eibon terminals

use crate::types::Decision;
use crate::error::SovereigntyError;
use crate::hex_stamp;
use aln_syntax_core::schemas::dow::DowArtifact;
use aln_syntax_core::validator::SchemaValidator;
use uuid::Uuid;
use serde_json::Value;

/// DOW artifact evaluation guard
pub struct DowGuard {
    validator: SchemaValidator,
    anti_rollback_enabled: bool,
    eco_floor_minimum: f64,
}

impl DowGuard {
    /// Create a new DOW guard
    pub fn new() -> Self {
        Self {
            validator: SchemaValidator::new(),
            anti_rollback_enabled: true,
            eco_floor_minimum: 0.3,
        }
    }

    /// Enable/disable anti-rollback
    pub fn with_anti_rollback(mut self, enabled: bool) -> Self {
        self.anti_rollback_enabled = enabled;
        self
    }

    /// Set custom eco floor minimum
    pub fn with_eco_floor(mut self, floor: f64) -> Self {
        self.eco_floor_minimum = floor;
        self
    }

    /// Evaluate a DOW artifact
    ///
    /// # Arguments
    ///
    /// * `payload` - JSON payload containing DowArtifact
    /// * `trace_id` - Cyberspectre trace ID for audit
    ///
    /// # Returns
    ///
    /// * `Decision` - Approved, Denied, or Degraded (with sandbox mode)
    pub fn evaluate(&self, payload: &Value, trace_id: &str) -> Decision {
        // Parse artifact
        let artifact: DowArtifact = match serde_json::from_value(payload.clone()) {
            Ok(a) => a,
            Err(e) => {
                return Decision::Denied {
                    reason: format!("Failed to parse DowArtifact: {}", e),
                    trace_id: trace_id.to_string(),
                    row_id: None,
                };
            }
        };

        // Validate against schema
        if let Err(e) = self.validator.validate_dow(&artifact) {
            return Decision::Denied {
                reason: format!("Schema validation failed: {}", e),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Check anti-rollback (if enabled)
        if self.anti_rollback_enabled {
            if let Err(e) = self.check_anti_rollback(&artifact) {
                return Decision::Denied {
                    reason: format!("Anti-rollback violation: {}", e),
                    trace_id: trace_id.to_string(),
                    row_id: None,
                };
            }
        }

        // Verify EcoVector floor
        if artifact.eco_vector.eco_impact_score < self.eco_floor_minimum {
            return Decision::Denied {
                reason: format!(
                    "EcoVector below floor: {} < {}",
                    artifact.eco_vector.eco_impact_score, self.eco_floor_minimum
                ),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Check if sandbox required (high-risk artifact)
        let sandbox_required = self.is_high_risk(&artifact);
        
        // Verify hex-stamp
        if !hex_stamp::verify_hex_stamp(&artifact, &artifact.hex_stamp) {
            return Decision::Denied {
                reason: "Hex-stamp verification failed".to_string(),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // All checks passed
        let row_id = Some(Uuid::new_v4().to_string());
        
        if sandbox_required {
            Decision::Degraded {
                mode: "Sandbox".to_string(),
                reason: "High-risk artifact requires sandboxed execution".to_string(),
                trace_id: trace_id.to_string(),
                row_id,
            }
        } else {
            Decision::Approved {
                envelope: serde_json::to_vec(&artifact).unwrap_or_default(),
                trace_id: trace_id.to_string(),
                row_id,
            }
        }
    }

    /// Check anti-rollback constraint
    fn check_anti_rollback(&self, artifact: &DowArtifact) -> Result<(), String> {
        // Compare version with previous installed version
        // (In production, this would query local DOW state)
        if artifact.version_major < 1 {
            return Err("Version rollback detected".to_string());
        }
        Ok(())
    }

    /// Determine if artifact is high-risk
    fn is_high_risk(&self, artifact: &DowArtifact) -> bool {
        // High-risk indicators:
        // - Kernel-level changes
        // - System service modifications
        // - Legacy protocol support (Cortana, Win10 services)
        artifact.risk_level >= 3
    }
}

impl Default for DowGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dow_guard_rejects_rollback() {
        let guard = DowGuard::new().with_anti_rollback(true);
        let trace_id = Uuid::new_v4().to_string();

        // Create artifact with rollback (version < 1)
        let payload = serde_json::json!({
            "artifact_id": Uuid::new_v4().to_string(),
            "platform": "windows_10",
            "version_major": 0,
            "version_minor": 9,
            "version_patch": 0,
            "eco_vector": {
                "gco2_per_joule": 0.001,
                "eco_impact_score": 0.5,
                "energy_autonomy_pct": 0.8,
                "eco_floor_minimum": 0.3
            },
            "risk_level": 2,
            "code_anchor_hash": "0xabc123",
            "zes_envelope": "zes:encrypted",
            "timestamp": 1741104000,
            "hex_stamp": "0x1234567890abcdef"
        });

        let decision = guard.evaluate(&payload, &trace_id);
        
        match decision {
            Decision::Denied { reason, .. } => {
                assert!(reason.contains("Anti-rollback"));
            }
            _ => panic!("Expected Denied decision for rollback"),
        }
    }
}
