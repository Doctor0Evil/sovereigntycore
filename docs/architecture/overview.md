# Sovereignty Core Architecture

## Overview

`sovereigntycore` is the **Enforcement Layer** of the Sovereign Spine, consuming schemas from `aln-syntax-core` and exposing the single privileged function `eval_aln_envelope(bytes) -> bytes`.

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Runtimes["Unprivileged Runtimes"]
        RL[Lua / JS / Kotlin / Mojo]
    end

    subgraph Core["sovereigntycore"]
        E0[eval_aln_envelope<br/>FFI Entrypoint]
        Gs[SourzeGuard]
        Gn[NdmGuard]
        Gd[DowGuard]
        CL[CapabilityLattice]
    end

    subgraph Audit["Audit & Evidence"]
        RowC[ROW/RPM Emitter]
        Cyb[Cyberspectre Tracer]
        L[(ROW / RPM Ledger)]
    end

    subgraph Adapters["Platform Adapters"]
        Aterm[Terminal Adapter]
        Adrone[Drone Adapter]
        Aswarm[Swarm Node Adapter]
    end

    RL -->|ALN envelopes| E0
    E0 -->|route| Gs
    E0 -->|route| Gn
    E0 -->|route| Gd
    Gs -->|validate| CL
    Gs -->|decision| RowC
    Gn -->|decision| RowC
    Gd -->|decision| RowC
    Gs -->|trace| Cyb
    Gn -->|trace| Cyb
    Gd -->|trace| Cyb
    RowC -->|append| L
    Cyb -->|trace| L
    E0 -->|approved| Aterm
    E0 -->|approved| Adrone
    E0 -->|approved| Aswarm
