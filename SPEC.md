# Aimem Open Local AI Memory & Verification Protocol (`v0.1.0-draft`)

**Status:** Working Reference Draft (`GPL-3.0-or-later`, independently usable, zero commercial dependencies)  
**Author:** Alexei Lemos Cavalcante Ferreira (`ORCID: 0009-0009-0139-3700`)

---

## 1. Design Problem & Principle

Every new session with a language model starts with amnesia: the model forgets user standards, repeats previous mistakes across projects, and consumes redundant cloud GPU compute re-reading full project context from scratch.

This specification defines a **portable, user-owned, local-first AI memory format and verification protocol** built around four invariants:

1. **User Ownership & Portability:** Memories live locally in plain-text Markdown + encrypted/content-addressed storage and export deterministically as W3C Research Object Crate (`RO-Crate 1.1`) compatible manifests with `FIPS 180-4 SHA-256` digests. Switching AI models (local Ollama, Claude, Gemini, Codex, or future open weights) requires zero vendor migration.
2. **Popperian Verification Gate (Fail-Closed):** High-confidence entries (`verified`, `proven`, `consensus`) MUST carry an explicit, non-placeholder, non-tautological `falsifier` stating the empirical test or observation that would refute the entry. Entries lacking a concrete falsifier are rejected before promotion so AI mistakes cannot silently compound.
3. **Hardware-Adaptive Multi-Tier Quantization:** Embedding stores adapt automatically to host disk and memory headroom so older laptops and phones remain fast and cool without exhausting storage:
   - **`FP32` (`4 bytes/dim`, `1.0x`)**: when free headroom `> 5.0 GiB`
   - **`Q8` (`1 byte/dim`, `4.0x` reduction)**: symmetric per-vector 8-bit quantization when headroom is `2.0–5.0 GiB`
   - **`Q4` (`0.5 bytes/dim`, `8.0x` reduction)**: nibble-packed 4-bit symmetric quantization when headroom `< 2.0 GiB`
   - **Idle Embedding Arena Eviction:** local embedding runtimes release model arenas after 5 minutes of inactivity to hold idle memory footprint below `25 MB` RSS.
4. **Compute & Data-Center Reduction (`pin_core: false` + Selective Top-k Recall):** Instead of shipping an entire workspace or re-pinning static system rules on every retrieval call, clients retrieve only compact top-`k` relevant memory chunks (`pin_core: false` when static adapter instructions are already loaded).

---

## 2. Portable Memory Envelope Schema (`aimem.envelope.v1`)

| Field | Type | Required | Rule |
| :--- | :--- | :--- | :--- |
| `schema` | string | Yes | `"aimem.envelope.v1"` |
| `id` | string | Yes | Stable lowercase kebab-case identifier |
| `kind` | enum | Yes | `semantic`, `procedural`, `feedback`, `reference`, `episodic` |
| `epistemic` | enum | Yes | `speculative`, `plausible`, `belief`, `falsifiable`, `verified`, `proven`, `consensus` |
| `derivation` | enum | Yes | `measured`, `derived`, `reproduced`, `fitted`, `speculation` |
| `falsifier` | string | Conditional | **Mandatory** for `verified` / `proven` / `consensus`; rejects empty, `"none"`, `"n/a"`, `"unfalsifiable"`, `"if this is wrong"`, `"cannot be falsified"`, and `< 12`-char stubs |
| `body` | string | Yes | UTF-8 Markdown; scanned fail-closed against credential/secret/statutory-ID leakage |
| `sha256` | hex(64) | Yes | Lowercase `FIPS 180-4 SHA-256` over canonical fields |

---

## 3. Compute-Savings Accounting Model

Let $T_{\text{full}}$ be the token count of repeatedly loading full multi-project context on every turn, $T_{\text{pin}}$ be redundant re-pinned static preference tokens when `pin_core: true`, and $T_{\text{recall}}(k)$ be the compact top-$k$ retrieved memory tokens (`pin_core: false`):

$$\text{Token Reduction} = 1 - \frac{T_{\text{recall}}(k)}{T_{\text{full}}}, \qquad \Delta T_{\text{turn}} = T_{\text{full}} - T_{\text{recall}}(k).$$

Because cloud GPU energy per 1,000 input prefill tokens varies widely by model scale, hardware generation, batching, and data-center PUE, the reference CLI reports **transparent, parameterized sensitivity bounds** (`0.05 Wh` / `0.20 Wh` / `0.50 Wh` per 1,000 avoided input tokens) alongside exact deterministic token counts—never an uncalibrated single-point estimate.

---

## 4. Reference Implementation & Verification

Every invariant in this specification is executable offline via the zero-dependency Rust reference binary in [`src/lib.rs`](./src/lib.rs) and [`src/main.rs`](./src/main.rs):

```bash
cargo test --release
cargo run --release -- bench
cargo run --release -- quantize-demo
cargo run --release -- verify-gate
cargo run --release -- export-manifest
```
