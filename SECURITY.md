<!--
SPDX-FileCopyrightText: 2026 Alexei Lemos Cavalcante Ferreira <ferreira.alexei@gmail.com>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Security & Legal Scope Policy (`aimem-open-spec`)

## Reporting a Security or Protocol Defect

If you discover a bypass in the Popperian promotion gate, statutory DLP/secret-redaction pattern evasion (IBAN MOD-97, ISO 7064, API secrets), canonical SHA-256 hashing non-determinism, or parser/memory-safety issues, please report it **privately**:

- **Email:** [ferreira.alexei@gmail.com](mailto:ferreira.alexei@gmail.com)
- **Subject:** `[security][aimem-open-spec] <one-line summary>`
- **Coordinated disclosure timeline:** Default **90 days** from acknowledgement.

## Legal Terms, Privacy & Regulatory Scope

1. **Open-Standard Licensing:** Executable reference code (`src/**`, `Cargo.toml`, `.github/**`) is licensed under **GNU General Public License v3.0 or later (`GPL-3.0-or-later`)** and supplied "AS IS" without warranty per GPLv3 §§ 15–16. The open specification (`SPEC.md`) and documentation are licensed under **`CC-BY-SA-4.0`**, and metadata manifests (`CITATION.cff`, `codemeta.json`, `REUSE.toml`) under **`CC0-1.0`**.
2. **Offline Privacy & Data Sovereignty:** The reference validator executes 100% locally with zero network requests, zero telemetry, and zero generative AI or cloud LLM runtime dependencies — advancing EU Data Act portability, GDPR, Marco Civil da Internet (Art. 7), and LGPD data-minimization principles.
3. **Non-Commercial Open-Source Development Boundary (EU CRA):** This repository is maintained as an independent, non-commercial public-interest open specification and reference implementation outside commercial product placement under Regulation (EU) 2024/2847 (Cyber Resilience Act, Recital 18). Commercial integrators embedding this specification or validator assume full regulatory and civil-liability obligations in their own jurisdiction (including German BGB and Brazilian Civil Code Arts. 186/927).
4. **Clean Separation from Commercial Editions:** `aimem-open-spec` is an independent public-commons protocol and Rust reference validator with zero proprietary dependencies.
