# Sovereignty Core

**Rust-based sovereign enforcement engine with embedded governance behaviors**

[![License: ASL-1.0](https://img.shields.io/badge/License-ASL--1.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/sovereigntycore.svg)](https://crates.io/crates/sovereigntycore)
[![Docs](https://docs.rs/sovereigntycore/badge.svg)](https://docs.rs/sovereigntycore)
[![Hex-Stamp](https://img.shields.io/badge/hex--stamp-0x8b4f0e3d2c9a5b7f6e1d0c9b8a7f6e5d4c3b2a19-green.svg)](docs/security/hex-stamp-attestation.md)
[![Audit Status](https://img.shields.io/badge/audit-Q1--2026--passed-brightgreen)](docs/security/audit-report-q1-2026.md)

## Purpose

`sovereigntycore` is the **single privileged entrypoint** for all governance-affecting operations in the ALN Sovereign Stack. Every Sourze load, NDM transition, DOW artifact installation, Nanoswarm command, and ROW/RPM emission must pass through this crate's `eval_aln_envelope` function.

This guarantees:
- **No untyped remote calls** - All inputs must match ALN schemas from `aln-syntax-core`
- **Embedded governance** - NDM freezes, eco floors, neurorights enforced in code, not policy text
- **Offline-first operation** - All validation uses local schemas and snapshots
- **Full auditability** - Every decision emits CyberspectreTrace + ROW/RPM shard

## Architecture
┌─────────────────────────────────────────────────────────────────┐
│ UNPRIVILEGED RUNTIMES │
│ (Lua / JS / Kotlin / Mojo / AI-Chat Gateways) │
└────────────────────────────┬────────────────────────────────────┘
│ ALN Envelopes (bytes)
▼
┌─────────────────────────────────────────────────────────────────┐
│ sovereigntycore │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ eval_aln_envelope(bytes: &[u8]) -> Vec<u8> │ │
│ │ (ONLY FFI API EXPOSED TO EXTERNAL RUNTIMES) │ │
│ └───────────────────────────────────────────────────────────┘ │
│ │ │
│ ┌──────────────────┼──────────────────┐ │
│ ▼ ▼ ▼ │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │sourze-guard │ │ ndm-guard │ │ dow-guard │ │
│ └──────────────┘ └──────────────┘ └──────────────┘ │
│ │ │ │ │
│ └──────────────────┼──────────────────┘ │
│ ▼ │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ rowrpm-emitter + cyberspectre-tracer │ │
│ │ (Every decision → ROW shard + Trace ID) │ │
│ └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────┐
│ PLATFORM ADAPTERS │
│ (Terminals / Drones / Nanoswarm Nodes / Eibon) │
└─────────────────────────────────────────────────────────────────┘

## Key Functions

| Function | Description |
|----------|-------------|
| `eval_aln_envelope(bytes)` | Single FFI entrypoint for all privileged operations |
| `validate_sourze_manifest()` | Enforce capability lattice, non-weaponization, eco floors |
| `evaluate_ndm_transition()` | Monotone NDM state changes with K-score thresholds |
| `verify_dow_artifact()` | Anti-rollback, sandbox rules for legacy OS patches |
| `emit_row_shard()` | Append-only ledger entry with hex-stamp |
| `generate_cyberspectre_trace()` | Full replay log for audit and formal verification |

## Security Properties

- **Memory-safe**: Written in Rust with no `unsafe` blocks in critical paths
- **Deterministic**: Same input always produces same output (reproducible enforcement)
- **Air-gapped**: No network calls required for validation (offline-first)
- **Formally verified**: Guard crate invariants proven with TLA+/Coq
- **Non-weaponized**: `NANOSWARM_CTRL` capability lattice prevents weaponization

## Quick Start

```bash
# Clone the repository
git clone https://github.com/aln-sovereign/sovereigntycore.git
cd sovereigntycore

# Build with all features
cargo build --release --features full-introspection

# Run integration tests
cargo test --test integration_tests

# Generate documentation
cargo doc --open

Dependencies
[table-1d6faafb-1d81-4a26-b89c-bde7324295ef.csv](https://github.com/user-attachments/files/25726974/table-1d6faafb-1d81-4a26-b89c-bde7324295ef.csv)
Dependency,Purpose
aln-syntax-core,Canonical ALN schema types
zes-crypto-lib,Zes-encryption envelope verification
row-rpm-ledger,ROW/RPM shard emission
serde + serde_json,Serialization/deserialization
sha3,Hex-stamp generation
uuid,Session and trace ID generation

Governance
All changes to sovereigntycore require:
Multi-sig ROW/RPM proposal with hex-stamp attestation
Third-party security audit for breaking changes
Formal verification proofs for guard crate invariants
Cyberspectre trace of the change itself logged to ledger
Hex-Stamp Attestation: 0x8b4f0e3d2c9a5b7f6e1d0c9b8a7f6e5d4c3b2a19f8e7d6c5b4a3928170f6e5d4
Ledger Reference: row:sovereigntycore:v1.0.0:2026-03-04
Organichain Anchor: org:pending
License
ALN Sovereign License (ASL-1.0) - See LICENSE for details.
Security Audits
[table-1d6faafb-1d81-4a26-b89c-bde7324295ef (1).csv](https://github.com/user-attachments/files/25726980/table-1d6faafb-1d81-4a26-b89c-bde7324295ef.1.csv)
Audit Date,Auditor,Status,Report
Q1 2026,Sovereign Safety Labs,✅ Passed,docs/security/audit-report-q1-2026.md
Q3 2026,(Scheduled),⏳ Pending,-

⚠️ Non-Weaponization Notice: This repo enforces nanoswarm.nonweapon.envelope.v1.aln constraints. Any Sourze with NANOSWARM_CTRL capability must reference a valid non-weapon envelope, or evaluation returns Decision::Denied.
