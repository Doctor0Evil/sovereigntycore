//! Capability Lattice - Non-weaponization constraint enforcement
//!
//! This module defines forbidden capability combinations that prevent
//! Nanoswarm weaponization. Any Sourze manifest violating these constraints
//! is rejected at load time.

use aln_syntax_core::schemas::sourze::SourzeCapability;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Forbidden capability combination definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForbiddenCombo {
    pub combo_id: String,
    pub capabilities: Vec<SourzeCapability>,
    pub reason: String,
    pub severity: String, // "critical", "high", "medium"
}

/// Capability lattice validator
pub struct CapabilityLattice {
    forbidden_combos: Vec<ForbiddenCombo>,
}

impl CapabilityLattice {
    /// Create a new capability lattice with default forbidden combos
    pub fn new() -> Self {
        Self {
            forbidden_combos: Self::default_forbidden_combos(),
        }
    }

    /// Validate a set of capabilities against the lattice
    ///
    /// # Arguments
    ///
    /// * `capabilities` - List of capabilities to validate
    ///
    /// # Returns
    ///
    /// * `Ok(())` if valid, `Err(String)` with violation reason
    pub fn validate(&self, capabilities: &[SourzeCapability]) -> Result<(), String> {
        let cap_set: HashSet<&SourzeCapability> = capabilities.iter().collect();

        for combo in &self.forbidden_combos {
            let combo_set: HashSet<&SourzeCapability> = combo.capabilities.iter().collect();
            
            if combo_set.is_subset(&cap_set) {
                return Err(format!(
                    "Forbidden combo [{}]: {}",
                    combo.combo_id, combo.reason
                ));
            }
        }

        Ok(())
    }

    /// Get default forbidden capability combinations
    fn default_forbidden_combos() -> Vec<ForbiddenCombo> {
        use SourzeCapability::*;

        vec![
            ForbiddenCombo {
                combo_id: "weapon_ctrl_network".to_string(),
                capabilities: vec![NanoswarmCtrl, NetServer],
                reason: "Prevents remote weaponization of Nanoswarm".to_string(),
                severity: "critical".to_string(),
            },
            ForbiddenCombo {
                combo_id: "ctrl_fs_hardware".to_string(),
                capabilities: vec![NanoswarmCtrl, FsWrite, UsbHid],
                reason: "Prevents hardware takeover via swarm control".to_string(),
                severity: "critical".to_string(),
            },
            ForbiddenCombo {
                combo_id: "ctrl_fs_serial".to_string(),
                capabilities: vec![NanoswarmCtrl, FsWrite, SerialMcu],
                reason: "Prevents MCU exploitation via swarm control".to_string(),
                severity: "critical".to_string(),
            },
            ForbiddenCombo {
                combo_id: "ctrl_gpu".to_string(),
                capabilities: vec![NanoswarmCtrl, GpuCompute],
                reason: "Prevents GPU-based attack vector via swarm".to_string(),
                severity: "high".to_string(),
            },
            ForbiddenCombo {
                combo_id: "ai_network_server".to_string(),
                capabilities: vec![AiChatBridge, NetServer],
                reason: "Prevents AI tunnel exploitation".to_string(),
                severity: "high".to_string(),
            },
            ForbiddenCombo {
                combo_id: "kernel_network".to_string(),
                capabilities: vec![KernelGuard, NetServer],
                reason: "Prevents kernel-level network exploitation".to_string(),
                severity: "critical".to_string(),
            },
        ]
    }
}

impl Default for CapabilityLattice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_rejects_forbidden_combo() {
        let lattice = CapabilityLattice::new();
        
        let forbidden_caps = vec![
            SourzeCapability::NanoswarmCtrl,
            SourzeCapability::NetServer,
        ];

        let result = lattice.validate(&forbidden_caps);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("weapon_ctrl_network"));
    }

    #[test]
    fn test_lattice_accepts_safe_combo() {
        let lattice = CapabilityLattice::new();
        
        let safe_caps = vec![
            SourzeCapability::NanoswarmCtrl,
            SourzeCapability::NetClient,
        ];

        let result = lattice.validate(&safe_caps);
        assert!(result.is_ok());
    }
}
