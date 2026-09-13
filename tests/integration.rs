//! The hub contract over HTTP: stateless signed relay between
//! willing pairs, willingness checked both ways, refusals stated
//! with the reason, nothing retained.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::util::ServiceExt;
use unidpp_hub::{router, AppState, Config};
use unidpp_signatif::declaration::{
    ClassPosture, HarmonizationLevel, InteropDeclaration, RecognitionMode, TransportMode,
};
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::Suite;

fn app() -> Router {
    let state = AppState::new(Config {
        bind: "127.0.0.1:0".into(),
        hub_id: "hub-test".into(),
        seed: Some("hub-test-seed".into()),
    })
    .expect("state");
    router(Arc::new(state))
}

fn declaration(declarer: &str, counterpart: &str, level: HarmonizationLevel) -> InteropDeclaration {
    let key = KeyPair::seeded(Suite::Ed25519, declarer.as_bytes()).expect("seed");
    InteropDeclaration::issue(
        declarer,
        counterpart,
        1,
        vec![ClassPosture {
            data_class: "battery.dynamic-state".into(),
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

async fn body_of(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn post_json(
    app: &Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("route");
    let status = response.status();
    (status, body_of(response).await)
}

#[tokio::test]
async fn the_relay_serves_willing_pairs_statelessly() {
    let app = app();
    let eu = declaration("eu-scheme", "cn-scheme", HarmonizationLevel::L3);
    let cn = declaration("cn-scheme", "eu-scheme", HarmonizationLevel::L3);
    let evidence = "deadbeef01";

    let (status, body) = post_json(
        &app,
        "/relay",
        serde_json::json!({
            "from": "eu-scheme",
            "to": "cn-scheme",
            "data_class": "battery.dynamic-state",
            "evidence_hex": evidence,
            "declarations": [eu, cn],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let relay = &body["relay"];
    assert_eq!(relay["hub_id"], "hub-test");
    assert_eq!(relay["from"], "eu-scheme");
    assert_eq!(relay["to"], "cn-scheme");
    assert_eq!(body["evidence_hex"], evidence);

    // The relay verifies under the hub's keyring key.
    let (status, verified) = post_json(
        &app,
        "/relay/verify",
        serde_json::json!({
            "evidence_hex": evidence,
            "relay": relay.clone(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verified["verified"], true, "{verified}");

    // A tampered evidence under the same relay signature: refuses.
    let (_, tampered) = post_json(
        &app,
        "/relay/verify",
        serde_json::json!({
            "evidence_hex": "deadbeef02",
            "relay": relay.clone(),
        }),
    )
    .await;
    assert_eq!(tampered["verified"], false, "{tampered}");
}

#[tokio::test]
async fn unwillingness_is_never_brokered_around() {
    let app = app();
    // The CN side declares L0 for the class toward the EU — the WILL
    // gap. The hub refuses, both endpoints and the reason stated.
    let eu = declaration("eu-scheme", "cn-scheme", HarmonizationLevel::L3);
    let cn_declining = declaration("cn-scheme", "eu-scheme", HarmonizationLevel::L0);
    let (status, body) = post_json(
        &app,
        "/relay",
        serde_json::json!({
            "from": "eu-scheme",
            "to": "cn-scheme",
            "data_class": "battery.dynamic-state",
            "evidence_hex": "00",
            "declarations": [eu, cn_declining],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["refused"], true);
    let reason = body["error"].as_str().expect("the reason");
    assert!(
        reason.contains("WILL gap") && reason.contains("cn-scheme"),
        "the refusal names the declining side and the gap: {reason}"
    );

    // No declaration at all: absence is stated, never silence.
    let (status, body) = post_json(
        &app,
        "/relay",
        serde_json::json!({
            "from": "eu-scheme",
            "to": "jp-scheme",
            "data_class": "battery.dynamic-state",
            "evidence_hex": "00",
            "declarations": [declaration("eu-scheme", "cn-scheme", HarmonizationLevel::L3)],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let reason = body["error"].as_str().expect("the reason");
    assert!(
        reason.contains("jp-scheme") && reason.contains("no interop declaration"),
        "the absence names the silent side: {reason}"
    );
}

#[tokio::test]
async fn the_discovery_document_states_the_contract() {
    let app = app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(body["service"], "unidpp-hub");
    let contract = body["contract"].as_array().expect("contract list");
    assert!(
        contract.len() >= 4,
        "stateless, willingness, signed, no-master — the contract is the discovery document's core"
    );
}
