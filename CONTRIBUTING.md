<!--
SPDX-FileCopyrightText: 2026 Alexei Lemos Cavalcante Ferreira <ferreira.alexei@gmail.com>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributing to `aimem-open-spec`

Thank you for helping keep local-first knowledge storage open, portable, and offline-verifiable.

## Engineering & Compliance Invariants

1. **Zero external runtime dependencies:** Keep the reference validator clean standard-library Rust (`cargo test --release` with `RUSTFLAGS="-D warnings"`).
2. **Fail-closed negative controls:** Every protocol invariant, DLP redaction pattern, or Popperian falsifier check must include a planted-defect unit test proving rejection.
3. **REUSE 3.3 compliance:** Run `reuse lint` and ensure every added file resolves cleanly under `REUSE.toml`.
4. **Developer Certificate of Origin (DCO 1.1):** Sign off every commit (`git commit -s`) certifying your legal right to contribute under the repository's open licenses (`https://developercertificate.org/`).
5. **AI-Assisted Contribution Disclosure:** Disclose any AI coding/editing assistant used while preparing a PR and verify all invariants manually. The reference validator itself must contain zero generative AI or cloud LLM runtime components.

## Licensing

- Reference code (`src/**`, `Cargo.toml`, `.github/**`): `GPL-3.0-or-later` ([LICENSE](./LICENSE)).
- Specification & documentation (`SPEC.md`, `README.md`, `SECURITY.md`, `ETHICS.md`, `CONTRIBUTING.md`): `CC-BY-SA-4.0`.
- Metadata manifests (`CITATION.cff`, `codemeta.json`, `REUSE.toml`): `CC0-1.0`.
