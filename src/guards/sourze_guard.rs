//! Sourze Guard - Enforce capability lattice and non-weaponization constraints
//!
//! This guard evaluates Sourze manifests against:
//! - Forbidden capability combinations (weaponization prevention)
//! - Non-weapon envelope requirements for NANOSWARM_CTRL
//! - EcoVector floor enforcement
//! - Multi-DID envelope verification

use crate::types::{Decision, AlnEnvelope};
use crate::capability_lattice::CapabilityLattice;
use crate::error::SovereigntyError;
use crate::hex_stamp;
use aln_syntax_core::schemas::sourze::{SourzeManifest, SourzeCapability, NanoswarmNonWeaponEnvelope};
use aln_syntax_core::schemas::eco::EcoVector;
use aln_syntax_core::validator::SchemaValidator;
use uuid::Uuid;
use serde_json::Value;

/// Sourze manifest evaluation guard
pub struct SourzeGuard {
    validator: SchemaValidator,
    capability_lattice: CapabilityLattice,
    eco_floor_minimum: f64,
}

impl SourzeGuard {
    /// Create a new Sourze guard
    pub fn new() -> Self {
        Self {
            validator: SchemaValidator::new(),
            capability_lattice: CapabilityLattice::new(),
            eco_floor_minimum: 0.3, // Default eco floor
        }
    }

    /// Set custom eco floor minimum
    pub fn with_eco_floor(mut self, floor: f64) -> Self {
        self.eco_floor_minimum = floor;
        self
    }

    /// Evaluate a Sourze manifest
    ///
    /// # Arguments
    ///
    /// * `payload` - JSON payload containing SourzeManifest
    /// * `trace_id` - Cyberspectre trace ID for audit
    ///
    /// # Returns
    ///
    /// * `Decision` - Approved, Denied, or Degraded
    pub fn evaluate(&self, payload: &Value, trace_id: &str) -> Decision {
        // Parse manifest
        let manifest: SourzeManifest = match serde_json::from_value(payload.clone()) {
            Ok(m) => m,
            Err(e) => {
                return Decision::Denied {
                    reason: format!("Failed to parse SourzeManifest: {}", e),
                    trace_id: trace_id.to_string(),
                    row_id: None,
                };
            }
        };

        // Validate against schema
        if let Err(e) = self.validator.validate_sourze(&manifest) {
            return Decision::Denied {
                reason: format!("Schema validation failed: {}", e),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Check capability lattice (non-weaponization)
        if let Err(e) = self.capability_lattice.validate(&manifest.capabilities) {
            return Decision::Denied {
                reason: format!("Capability lattice violation: {}", e),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Verify non-weapon envelope for NANOSWARM_CTRL
        if manifest.capabilities.contains(&SourzeCapability::NanoswarmCtrl) {
            match &manifest.non_weapon_envelope {
                Some(envelope) => {
                    if !self.validate_non_weapon_envelope(envelope) {
                        return Decision::Denied {
                            reason: "Invalid non-weapon envelope for NANOSWARM_CTRL".to_string(),
                            trace_id: trace_id.to_string(),
                            row_id: None,
                        };
                    }
                }
                None => {
                    return Decision::Denied {
                        reason: "NANOSWARM_CTRL requires non-weapon envelope".to_string(),
                        trace_id: trace_id.to_string(),
                        row_id: None,
                    };
                }
            }
        }

        // Verify EcoVector floor
        if manifest.eco_vector.eco_impact_score < self.eco_floor_minimum {
            return Decision::Denied {
                reason: format!(
                    "EcoVector below floor: {} < {}",
                    manifest.eco_vector.eco_impact_score, self.eco_floor_minimum
                ),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Verify multi-DID envelope
        if manifest.did_owner.is_empty()
            || manifest.did_host.is_empty()
            || manifest.did_auditor.is_empty()
        {
            return Decision::Denied {
                reason: "Multi-DID envelope required (owner, host, auditor)".to_string(),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // Verify hex-stamp
        if !hex_stamp::verify_hex_stamp(&manifest, &manifest.hex_stamp) {
            return Decision::Denied {
                reason: "Hex-stamp verification failed".to_string(),
                trace_id: trace_id.to_string(),
                row_id: None,
            };
        }

        // All checks passed
        let row_id = Some(Uuid::new_v4().to_string());
        Decision::Approved {
            envelope: serde_json::to_vec(&manifest).unwrap_or_default(),
            trace_id: trace_id.to_string(),
            row_id,
        }
    }

    /// Validate non-weapon envelope
    fn validate_non_weapon_envelope(&self, envelope: &NanoswarmNonWeaponEnvelope) -> bool {
        // Check for forbidden mission tags
        let forbidden_tags = [
            "kinetic_damage",
            "crowd_control",
            "surveillance_without_consent",
            "weapon_deployment",
            "offensive_operations",
        ];

        for mission in &envelope.permitted_missions {
            if forbidden_tags.iter().any(|tag| mission.contains(tag)) {
                return false;
            }
        }

        // Verify required fields
        !envelope.envelope_id.as_simple().to_string().is_empty()
            && envelope.requires_multi_sig
    }
}

impl Default for SourzeGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sourze_guard_rejects_forbidden_capabilities() {
        let guard = SourzeGuard::new();
        let trace_id = Uuid::new_v4().to_string();

        // Create manifest with forbidden combo (NANOSWARM_CTRL + NETSERVER)
        let payload = serde_json::json!({
            "manifest_id": Uuid::new_v4().to_string(),
            "did_owner": "bostrom1owner",
            "did_host": "bostrom1host",
            "did_auditor": "bostrom1auditor",
            "capabilities": ["NanoswarmCtrl", "NetServer"],
            "eco_vector": {
                "gco2_per_joule": 0.001,
                "eco_impact_score": 0.5,
                "energy_autonomy_pct": 0.8,
                "eco_floor_minimum": 0.3
            },
            "ndm_ceiling": 0.3,
            "non_weapon_envelope": null,
            "code_anchor_hash": "0xabc123",
            "zes_envelope": "zes:encrypted",
            "authorship_proof": {
                "author_dids": ["bostrom1author"],
                "row_reference": "row:authorship:123",
                "googolswarm_tx_id": "gs:tx:456",
                "git_signed_tag": "v1.0.0"
            },
            "timestamp": 1741104000,
            "hex_stamp": "0x1234567890abcdef"
        });

        let decision = guard.evaluate(&payload, &trace_id);
        
        match decision {
            Decision::Denied { reason, .. } => {
                assert!(reason.contains("Capability lattice violation"));
            }
            _ => panic!("Expected Denied decision for forbidden capability combo"),
        }
    }

    #[test]
    fn test_sourze_guard_accepts_valid_manifest() {
        let guard = SourzeGuard::new();
        let trace_id = Uuid::new_v4().to_string();

        // Create valid manifest
        let payload = serde_json::json!({
            "manifest_id": Uuid::new_v4().to_string(),
            "did_owner": "bostrom1owner",
            "did_host": "bostrom1host",
            "did_auditor": "bostrom1auditor",
            "capabilities": ["NanoswarmCtrl", "NetClient"],
            "eco_vector": {
                "gco2_per_joule": 0.001,
                "eco_impact_score": 0.5,
                "energy_autonomy_pct": 0.8,
                "eco_floor_minimum": 0.3
            },
            "ndm_ceiling": 0.3,
            "non_weapon_envelope": {
                "envelope_id": Uuid::new_v4().to_string(),
                "permitted_missions": ["ecological_restoration"],
                "forbidden_missions": ["kinetic_damage"],
                "effect_type": "eco",
                "mission_class": "restoration",
                "requires_multi_sig": true
            },
            "code_anchor_hash": "0xabc123",
            "zes_envelope": "zes:encrypted",
            "authorship_proof": {
                "author_dids": ["bostrom1author"],
                "row_reference": "row:authorship:123",
                "googolswarm_tx_id": "gs:tx:456",
                "git_signed_tag": "v1.0.0"
            },
            "timestamp": 1741104000,
            "hex_stamp": "0x1234567890abcdef"
        });

        let decision = guard.evaluate(&payload, &trace_id);
        
        match decision {
            Decision::Approved { .. } => { /* success */ }
            _ => panic!("Expected Approved decision for valid manifest"),
        }
    }
}
