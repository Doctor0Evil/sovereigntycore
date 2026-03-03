//! Sovereignty Core Integration Tests
//!
//! End-to-end tests for the full evaluation pipeline:
//! Envelope → Guard → Decision → ROW/RPM → Cyberspectre

use sovereigntycore::{eval_aln_envelope, Decision, AlnEnvelope, ShardKind};
use uuid::Uuid;

#[test]
fn test_full_sourze_evaluation_pipeline() {
    // Create valid Sourze manifest
    let manifest = serde_json::json!({
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

    let envelope = AlnEnvelope {
        kind: ShardKind::SourzePolicy,
        payload: manifest,
    };

    let bytes = serde_json::to_vec(&envelope).unwrap();
    let result = eval_aln_envelope(&bytes);
    let decision: Decision = serde_json::from_slice(&result).unwrap();

    match decision {
        Decision::Approved { row_id, .. } => {
            assert!(row_id.is_some());
        }
        _ => panic!("Expected Approved decision"),
    }
}

#[test]
fn test_ndm_monotone_enforcement() {
    // Create NDM snapshot with invalid state upgrade
    let snapshot = serde_json::json!({
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

    let envelope = AlnEnvelope {
        kind: ShardKind::NdmSnapshot,
        payload: snapshot,
    };

    let bytes = serde_json::to_vec(&envelope).unwrap();
    let result = eval_aln_envelope(&bytes);
    let decision: Decision = serde_json::from_slice(&result).unwrap();

    match decision {
        Decision::Denied { reason, .. } => {
            assert!(reason.contains("state upgrade"));
        }
        _ => panic!("Expected Denied decision for state upgrade"),
    }
}

#[test]
fn test_weaponization_prevention() {
    // Create manifest with forbidden capability combo
    let manifest = serde_json::json!({
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

    let envelope = AlnEnvelope {
        kind: ShardKind::SourzePolicy,
        payload: manifest,
    };

    let bytes = serde_json::to_vec(&envelope).unwrap();
    let result = eval_aln_envelope(&bytes);
    let decision: Decision = serde_json::from_slice(&result).unwrap();

    match decision {
        Decision::Denied { reason, .. } => {
            assert!(reason.contains("Capability lattice") || reason.contains("forbidden"));
        }
        _ => panic!("Expected Denied decision for weaponization attempt"),
    }
}
