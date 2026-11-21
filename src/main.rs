use aimem_open_spec::{
    cosine_similarity, dequantize_q4_packed, dequantize_q8, export_ro_crate_manifest,
    quantize_q4_packed, quantize_q8, run_compute_savings_benchmark, validate_envelope, Derivation,
    EpistemicLevel, IdleArenaState, MemoryEnvelope, MemoryKind, QuantizationTier,
    IDLE_RSS_BUDGET_MIB,
};
use std::env;
use std::process;

fn print_help() {
    println!(
        "aimem-open-spec v0.1.0 — Open Local AI Memory Standard & Benchmark (GPL-3.0-or-later)\n\
         Zero external dependencies · 100% offline deterministic Rust\n\n\
         USAGE:\n\
           aimem-open-spec bench            Run selective-recall vs always-load token & energy benchmark\n\
           aimem-open-spec quantize-demo    Demonstrate adaptive FP32/Q8/Q4 compression & idle RSS eviction\n\
           aimem-open-spec verify-gate      Run Popperian falsifier + DLP negative/positive control battery\n\
           aimem-open-spec export-manifest  Print a deterministic W3C RO-Crate 1.1 SHA-256 export manifest"
    );
}

fn cmd_bench() {
    let r = run_compute_savings_benchmark();
    println!("=== Aimem Open Standard — Reproducible Context-Token & Energy Benchmark ===");
    println!("Corpus size:                   {} project memory entries", r.corpus_docs);
    println!("Top-k local selective recall:  k = {}", r.top_k);
    println!("Recall@1 target hit:           {}", r.recall_at_1_hit);
    println!("Local retrieval latency:       {} us", r.local_retrieval_us);
    println!("Always-load context / turn:    {} tokens", r.always_load_tokens_per_turn);
    println!("Selective recall (pin=true):   {} tokens (+{} duplicate core tokens)", r.selective_tokens_pin_true, r.pin_core_overhead_tokens);
    println!("Selective recall (pin=false):  {} tokens", r.selective_tokens_pin_false);
    println!("Context token reduction:       {:.2}%", r.token_reduction_pct);
    println!("Avoided cloud tokens / 1k turns: {}", r.avoided_tokens_per_1000_turns);
    println!(
        "Parameterized cloud prefill energy saved / 1k turns (sensitivity bounds):\n  \
         - Conservative (0.05 Wh/1k tok): {:.1} Wh\n  \
         - Mid-range    (0.20 Wh/1k tok): {:.1} Wh\n  \
         - Large model  (0.50 Wh/1k tok): {:.1} Wh",
        r.energy_saved_wh_bounds_per_1000_turns[0],
        r.energy_saved_wh_bounds_per_1000_turns[1],
        r.energy_saved_wh_bounds_per_1000_turns[2],
    );
}

fn cmd_quantize_demo() {
    let dim = 384usize;
    let vec: Vec<f32> = (0..dim)
        .map(|i| (((i * 37 + 11) % 97) as f32 / 48.5) - 1.0)
        .collect();
    let fp32_bytes = dim * 4;
    let q8 = quantize_q8(&vec);
    let q4 = quantize_q4_packed(&vec);
    let cos8 = cosine_similarity(&vec, &dequantize_q8(&q8));
    let cos4 = cosine_similarity(&vec, &dequantize_q4_packed(&q4));

    let mut arena = IdleArenaState::active_default();
    let active_rss = arena.current_rss_mib();
    arena.maybe_evict(300);
    let idle_rss = arena.current_rss_mib();

    println!("=== Adaptive Multi-Tier Quantization & Idle Arena Eviction ===");
    println!("Headroom 8.0 GiB -> {} ({:.1}x)", QuantizationTier::from_free_gib(8.0).as_str(), QuantizationTier::Fp32.nominal_compression_ratio());
    println!("Headroom 3.5 GiB -> {} ({:.1}x)", QuantizationTier::from_free_gib(3.5).as_str(), QuantizationTier::Q8.nominal_compression_ratio());
    println!("Headroom 1.2 GiB -> {} ({:.1}x)", QuantizationTier::from_free_gib(1.2).as_str(), QuantizationTier::Q4.nominal_compression_ratio());
    println!("384-dim FP32 payload: {} bytes", fp32_bytes);
    println!("384-dim Q8   payload: {} bytes ({:.1}x reduction, cosine = {:.6})", q8.data.len(), fp32_bytes as f64 / q8.data.len() as f64, cos8);
    println!("384-dim Q4   payload: {} bytes ({:.1}x reduction, cosine = {:.6})", q4.packed.len(), fp32_bytes as f64 / q4.packed.len() as f64, cos4);
    println!("Embedding arena RSS:  active = {:.1} MiB -> idle after 300s = {:.1} MiB (budget < {:.1} MiB)", active_rss, idle_rss, IDLE_RSS_BUDGET_MIB);
}

fn cmd_verify_gate() {
    let valid = MemoryEnvelope {
        id: "release-profile-invariant".to_string(),
        kind: MemoryKind::Procedural,
        epistemic: EpistemicLevel::Verified,
        derivation: Derivation::Measured,
        falsifier: Some("Running cargo build --release failing or exceeding local disk budget refutes this invariant.".to_string()),
        body: "Compile Rust binaries with --release and clean intermediate build caches.".to_string(),
    };
    let mut bad_tautology = valid.clone();
    bad_tautology.id = "tautology-negative-control".to_string();
    bad_tautology.falsifier = Some("if this is wrong".to_string());

    let mut bad_secret = valid.clone();
    bad_secret.id = "dlp-negative-control".to_string();
    bad_secret.body = "Leaked key: -----BEGIN PRIVATE KEY-----".to_string();

    println!("=== Popperian Falsifier & DLP Promotion Gate ===");
    println!("Positive control (concrete falsifier): {:?}", validate_envelope(&valid).map(|h| format!("PASS sha256={}...", &h[..16])));
    println!("Negative control (tautology):          {:?}", validate_envelope(&bad_tautology));
    println!("Negative control (PEM private key):    {:?}", validate_envelope(&bad_secret));
}

fn cmd_export_manifest() {
    let samples = vec![
        MemoryEnvelope {
            id: "adaptive-quantization-policy".to_string(),
            kind: MemoryKind::Procedural,
            epistemic: EpistemicLevel::Verified,
            derivation: Derivation::Measured,
            falsifier: Some("Measuring Q8 cosine similarity below 0.99 on normalized embeddings refutes this threshold.".to_string()),
            body: "Use FP32 above 5 GiB, Q8 between 2 and 5 GiB, and Q4 below 2 GiB free headroom.".to_string(),
        },
        MemoryEnvelope {
            id: "pin-core-false-token-hygiene".to_string(),
            kind: MemoryKind::Feedback,
            epistemic: EpistemicLevel::Verified,
            derivation: Derivation::Measured,
            falsifier: Some("Measuring zero token reduction when omitting duplicated core pins refutes this rule.".to_string()),
            body: "Pass pin_core=false on selective memory queries when static adapter rules are already loaded.".to_string(),
        },
    ];
    match export_ro_crate_manifest(&samples) {
        Ok((manifest, _root)) => print!("{}", manifest),
        Err(e) => {
            eprintln!("Export rejected by gate: {:?}", e);
            process::exit(1);
        }
    }
}

fn main() {
    let arg = env::args().nth(1).unwrap_or_else(|| "help".to_string());
    match arg.as_str() {
        "bench" => cmd_bench(),
        "quantize-demo" => cmd_quantize_demo(),
        "verify-gate" => cmd_verify_gate(),
        "export-manifest" => cmd_export_manifest(),
        "-h" | "--help" | "help" => print_help(),
        other => {
            eprintln!("Unknown subcommand: '{}'\n", other);
            print_help();
            process::exit(2);
        }
    }
}
