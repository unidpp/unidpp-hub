//! The UniDPP translation hub: a stateless signed relay between
//! willing pairs divided by protocols (SI-3's hub contract as an
//! operable service).
//!
//! The hub carries no storage — relaying is a pure function of the
//! request: the caller supplies BOTH sides' published interop
//! declarations and the evidence; the hub checks willingness (a
//! scheme that declines interop is never brokered around — the WILL
//! gap is not the hub's to bridge), signs the forwarded bytes plus
//! the relay metadata, and returns the relayed evidence. After the
//! relay the hub holds nothing (enforced structurally: there is
//! nowhere to put anything).
//!
//! No message of this service names a master; a pair that speaks
//! directly has no need of it, and a pair divided by protocols
//! loses no assurance by using it.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use unidpp_signatif::declaration::{DeclarationSet, InteropDeclaration};
use unidpp_signatif::keyring::{KeyPair, PublicKey};
use unidpp_signatif::sign::SigningDomain;
use unidpp_signatif::sign::Suite;
use unidpp_signatif::transport::{Hub, RelayedEvidence};

/// Deployment configuration (env-driven, house convention).
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub hub_id: String,
    pub seed: Option<String>,
}

impl Config {
    pub fn from_env() -> Config {
        let mut config = Config {
            bind: "127.0.0.1:8397".into(),
            hub_id: "unidpp-hub-1".into(),
            seed: None,
        };
        if let Ok(bind) = std::env::var("UNIDPP_HUB_BIND") {
            if !bind.trim().is_empty() {
                config.bind = bind;
            }
        }
        if let Ok(hub_id) = std::env::var("UNIDPP_HUB_ID") {
            if !hub_id.trim().is_empty() {
                config.hub_id = hub_id;
            }
        }
        if let Ok(seed) = std::env::var("UNIDPP_HUB_SEED") {
            if !seed.is_empty() {
                config.seed = Some(seed);
            }
        }
        config
    }
}

pub struct AppState {
    pub config: Config,
    pub key: KeyPair,
}

impl AppState {
    pub fn new(config: Config) -> Result<AppState, String> {
        let seed = config.seed.as_deref().unwrap_or("unidpp-hub");
        let key = KeyPair::seeded(Suite::Ed25519, seed.as_bytes())
            .map_err(|e| format!("hub key: {e}"))?;
        if config.seed.is_none() {
            eprintln!(
                "unidpp-hub: WARNING — keyring runs in seeded-dev mode; production \
                 deployments must set UNIDPP_HUB_SEED"
            );
        }
        Ok(AppState { config, key })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("not hex (odd length)".into());
    }
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            let hi = (bytes[i] as char).to_digit(16).ok_or("not hex")?;
            let lo = (bytes[i + 1] as char).to_digit(16).ok_or("not hex")?;
            Ok(((hi << 4) | lo) as u8)
        })
        .collect()
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    builder = builder.header("x-as-of", unidpp_model::time::Timestamp::now().to_string());
    builder
        .body(axum::body::Body::from(
            serde_json::to_string_pretty(body).expect("static response serializes"),
        ))
        .expect("static response parts are valid")
}

/// GET / — the discovery document (the family convention).
async fn discovery(State(state): State<Arc<AppState>>) -> Response {
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "service": "unidpp-hub",
            "description": "UniDPP translation hub: a stateless signed relay between willing pairs \
                            divided by protocols (the SI-3 hub contract)",
            "hub_id": state.config.hub_id,
            "endpoints": {
                "health": "GET /healthz",
                "keyring": "GET /keyring — the hub's public key (relay signatures verify under it)",
                "relay": "POST /relay {from, to, data_class, evidence_hex, declarations: [..]} — \
                          both sides' published declarations ride the request; willingness is \
                          checked both ways, the forwarded bytes are signed in the HUB-RELAY \
                          domain, nothing is retained",
                "relay_verify": "POST /relay/verify {evidence_hex, relay: {..}} — verify a relay \
                                 under this hub's key",
            },
            "contract": [
                "stateless: no storage, no journals, no posture state — the caller carries \
                 the declarations",
                "willingness both ways: a scheme that declines interop is never brokered \
                 around (the WILL gap is not the hub's to bridge)",
                "signed: every relay is signed in the HUB-RELAY domain over the forwarded \
                 bytes plus the relay metadata",
                "no master: a pair that speaks directly has no need of the hub; no message \
                 of the protocol names one",
            ],
        }),
    )
}

async fn healthz() -> Response {
    json_response(StatusCode::OK, &serde_json::json!({"status": "ok"}))
}

/// GET /keyring — the hub's public key.
async fn keyring(State(state): State<Arc<AppState>>) -> Response {
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "mode": if state.config.seed.is_some() { "declared-seed" } else { "seeded-dev" },
            "roles": {
                "relay": {
                    "suite": "ed25519",
                    "public_hex": hex(state.key.public().as_bytes()),
                }
            }
        }),
    )
}

#[derive(serde::Deserialize)]
struct RelayRequest {
    from: String,
    to: String,
    data_class: String,
    evidence_hex: String,
    /// BOTH sides' published interop declarations (the hub holds no
    /// posture state; the request is the relay's whole world).
    declarations: Vec<InteropDeclaration>,
}

/// POST /relay — check willingness both ways, forward, sign, retain
/// nothing.
async fn relay(State(state): State<Arc<AppState>>, Json(req): Json<RelayRequest>) -> Response {
    let mut set = DeclarationSet::new();
    for declaration in &req.declarations {
        set.register(declaration.clone());
    }
    let evidence = match decode_hex(req.evidence_hex.trim()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": format!("`evidence_hex`: {error}")}),
            )
        }
    };
    let hub = Hub {
        hub_id: state.config.hub_id.clone(),
    };
    match hub.relay(
        &evidence,
        &req.from,
        &req.to,
        &req.data_class,
        &set,
        &state.key,
    ) {
        Ok(relayed) => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "relay": serde_json::to_value(&relayed).expect("serializes"),
                "evidence_hex": req.evidence_hex.trim(),
            }),
        ),
        Err(error) => json_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &serde_json::json!({"error": error.to_string(), "refused": true}),
        ),
    }
}

#[derive(serde::Deserialize)]
struct RelayVerifyRequest {
    evidence_hex: String,
    relay: RelayedEvidence,
}

/// POST /relay/verify — re-verify a relay's signature under this
/// hub's key (the recipient's check, offered so any third party can
/// run it without linking the crate — though linking is equally
/// conforming).
async fn relay_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RelayVerifyRequest>,
) -> Response {
    let evidence = match decode_hex(req.evidence_hex.trim()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": format!("`evidence_hex`: {error}")}),
            )
        }
    };
    let payload = Hub::relay_payload(
        &req.relay.hub_id,
        &evidence,
        &req.relay.from,
        &req.relay.to,
        &req.relay.data_class,
    );
    let public: PublicKey = *state.key.public();
    match req
        .relay
        .signature
        .verify(SigningDomain::HubRelay, &payload, &public)
    {
        Ok(()) => json_response(
            StatusCode::OK,
            &serde_json::json!({"verified": true, "evidence_digest": hex(&req.relay.evidence_digest)}),
        ),
        Err(error) => json_response(
            StatusCode::OK,
            &serde_json::json!({"verified": false, "error": error.to_string()}),
        ),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/keyring", get(keyring))
        .route("/relay", post(relay))
        .route("/relay/verify", post(relay_verify))
        .with_state(state)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let app = Arc::new(AppState::new(config.clone()).map_err(std::io::Error::other)?);
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    eprintln!(
        "unidpp-hub listening on http://{} (hub id {})",
        config.bind, config.hub_id
    );
    axum::serve(listener, router(app)).await
}
