# Aimem Open Local AI Memory Standard (`aimem-open-spec`)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24476260.svg)](https://doi.org/10.5281/zenodo.24476260) [![ORCID](https://img.shields.io/badge/ORCID-0009--0009--0139--3700-A6CE39)](https://orcid.org/0009-0009-0139-3700)

**An open, zero-dependency Rust reference specification, Popperian verification gate, adaptive `FP32/Q8/Q4` vector quantization codec, and reproducible compute-savings benchmark for user-owned local AI memory (`GPL-3.0-or-later`).**

> **Why this exists:** Every new AI session forgets your standards, repeats old mistakes, and wastes cloud GPU compute re-reading your context from scratch. Keeping portable, verified memory locally on your own hardware makes every project faster across any AI tool—while cutting redundant cloud token processing, electricity draw, and demand for new data centers.

---

## What Is Included (Zero External Crates · Runs Offline in Milliseconds)

| Component | Module | What It Verifies |
| :--- | :--- | :--- |
| **Protocol Specification** | [`SPEC.md`](./SPEC.md) | Portable `aimem.envelope.v1` JSON-LD / W3C `RO-Crate 1.1` memory schema, non-proprietary open standard |
| **Popperian Falsifier & DLP Gate** | [`src/lib.rs`](./src/lib.rs) | Fail-closed promotion gate rejecting missing, placeholder, or tautological falsifiers on high-confidence memories + secret/PII leakage blocker |
| **Adaptive `FP32 → Q8 → Q4` Codec** | [`src/lib.rs`](./src/lib.rs) | Storage-headroom tier selector (`>5 GiB` FP32 · `2–5 GiB` Q8 `4×` · `<2 GiB` Q4 `8×`) with real measured cosine-similarity retention and idle RAM budget (`< 25 MB`) |
| **Reproducible Token & Energy Benchmark** | [`src/lib.rs`](./src/lib.rs) | Deterministic comparison of full-context re-loading vs selective local recall (`pin_core: false`) with parameterized cloud-energy sensitivity bounds (`Wh` / `1k` tokens) |
| **Cryptographic Portability (`SHA-256`)** | [`src/lib.rs`](./src/lib.rs) | Exact `FIPS 180-4 SHA-256` content-addressed W3C `RO-Crate` manifest export for vendor-free migration across AI clients |

---

## Run & Reproduce Offline in 10 Seconds

Requires only a standard Rust toolchain (`rustc` / `cargo`). Zero network calls, zero third-party crates, zero cloud APIs:

```bash
cargo test --release
cargo run --release -- bench
cargo run --release -- quantize-demo
cargo run --release -- verify-gate
cargo run --release -- export-manifest
```

---

## Companion Open-Source Repositories

- **Epistemic & Formal-Proof Verifier (`Rust` / `Wasm`, `GPL-3.0-or-later`):** https://github.com/LX8/tupa-epistemic-verifier
- **Pharos Offline Democratic-Resilience Observatory (`GPL-3.0-or-later` / `CC BY-SA 4.0` / `CC0 1.0`):** https://github.com/LX8/pharos

## License

Free and Open Source Software licensed under **GNU General Public License v3.0 or later (`GPL-3.0-or-later`)**. Independently usable with zero commercial dependencies. See [`LICENSE`](./LICENSE).
