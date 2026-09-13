//! Declaration fixtures for the hub quickstart: a willing pair
//! (EU ↔ CN, both L3 with hub transport) and a declining pair (CN
//! toward JP at L0 — the WILL gap). Seeded keys, deterministic
//! bytes, every run.
//!
//! Run: cargo run --release --example declarations -- <out-dir>
//!   willing.json — both sides' declarations for the EU ↔ CN pair
//!   declining.json — the pair whose recipient declines

use unidpp_signatif::declaration::{
    ClassPosture, HarmonizationLevel, InteropDeclaration, RecognitionMode, TransportMode,
};
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::Suite;

fn declaration(
    declarer: &str,
    counterpart: &str,
    level: HarmonizationLevel,
    seed: &str,
) -> InteropDeclaration {
    let key = KeyPair::seeded(Suite::Ed25519, seed.as_bytes()).expect("seed");
    InteropDeclaration::issue(
        declarer,
        counterpart,
        1,
        vec![ClassPosture {
            data_class: "*".into(),
            level,
            recognition: RecognitionMode::BilateralAnchors,
            transports: vec![TransportMode::Hub, TransportMode::Document],
            escalation: None,
            reciprocity: None,
        }],
        "2030-01-01T00:00:00Z",
        None,
        &key,
    )
    .expect("declaration")
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    std::fs::create_dir_all(&dir).expect("dir");

    let willing = vec![
        declaration("eu-scheme", "cn-scheme", HarmonizationLevel::L3, "decl/eu"),
        declaration("cn-scheme", "eu-scheme", HarmonizationLevel::L3, "decl/cn"),
    ];
    let declining = vec![
        declaration("eu-scheme", "jp-scheme", HarmonizationLevel::L3, "decl/eu"),
        declaration("jp-scheme", "eu-scheme", HarmonizationLevel::L0, "decl/jp"),
    ];
    std::fs::write(
        format!("{dir}/willing.json"),
        serde_json::to_string_pretty(&willing).expect("serializes"),
    )
    .expect("write");
    std::fs::write(
        format!("{dir}/declining.json"),
        serde_json::to_string_pretty(&declining).expect("serializes"),
    )
    .expect("write");
    println!("wrote {dir}/willing.json and {dir}/declining.json");
}
