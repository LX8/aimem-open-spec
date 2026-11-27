<!--
SPDX-FileCopyrightText: 2026 Alexei Lemos Cavalcante Ferreira <ferreira.alexei@gmail.com>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Ethics & Five-Layer Safety Scope (`aimem-open-spec`)

1. **Layer 1 — Intrinsic Harmlessness (Architectural):** A local-first Markdown/YAML + SHA-256 + W3C RO-Crate interchange specification and offline Rust validator contains no surveillance telemetry, no data exfiltration channel, and no generative AI runtime in the critical path.
2. **Layer 2 — Legal Copyleft & Open Licensing:** Specification prose is licensed under `CC-BY-SA-4.0`, Rust validator code under `GPL-3.0-or-later`, and machine-readable metadata under `CC0-1.0`, verified by FSFE **REUSE 3.3** (`REUSE.toml` + `LICENSES/`).
3. **Layer 3 — Privacy & Non-Aggression Covenant:** Statutory DLP redaction rules are designed strictly to protect user privacy and prevent accidental leakage of secrets or regulated personal identifiers at interchange boundaries.
4. **Layer 4 — Deterministic Audit Trail:** All canonical exports carry FIPS 180-4 SHA-256 provenance digests and fail-closed Popperian falsifier validation.
5. **Layer 5 — Public Oversight:** Open RFCs, reproducible offline tests, Zenodo archival releases (`doi:10.5281/zenodo.24476259`), and public GitHub CI remain openly inspectable.
