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
//!
//! The endpoint table is the served contract itself: every handler
//! carries its `#[utoipa::path]` declaration, the document is served
//! at `/openapi.yaml` (and `/openapi.json`), browsable at `/docs`,
//! and committed as the golden `openapi.yaml`.

use std::collections::HashMap;
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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Deployment configuration (env-driven, house convention).
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub hub_id: String,
    pub seed: Option<String>,
}

impl Config {
    /// The environment variables this service consumes. This is the
    /// deployment contract: the served contract document carries these
    /// names as `x-unidpp-env-keys`.
    pub const ENV_KEYS: &'static [&'static str] =
        &["UNIDPP_HUB_BIND", "UNIDPP_HUB_ID", "UNIDPP_HUB_SEED"];

    pub fn from_env() -> Config {
        let mut config = Config {
            bind: "127.0.0.1:8397".into(),
            hub_id: "unidpp-hub-1".into(),
            seed: None,
        };
        let mut vars: HashMap<&str, String> = HashMap::new();
        for key in Self::ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                vars.insert(*key, value);
            }
        }
        if let Some(bind) = vars.get("UNIDPP_HUB_BIND") {
            if !bind.trim().is_empty() {
                config.bind = bind.clone();
            }
        }
        if let Some(hub_id) = vars.get("UNIDPP_HUB_ID") {
            if !hub_id.trim().is_empty() {
                config.hub_id = hub_id.clone();
            }
        }
        if let Some(seed) = vars.get("UNIDPP_HUB_SEED") {
            if !seed.is_empty() {
                config.seed = Some(seed.clone());
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

/// Serve the discovery document.
#[utoipa::path(
    get,
    path = "/",
    tag = "hub",
    responses(
        (status = 200, description = "The discovery document: the service identity, the hub id, the endpoint map and the contract statements — statelessness, two-way willingness, signed relays, no master", body = Value, content_type = "application/json"),
    )
)]
async fn discovery(State(state): State<Arc<AppState>>) -> Response {
    json_response(StatusCode::OK, &discovery_document(&state.config))
}

/// The discovery document (the family convention): service identity,
/// hub id, endpoint map and the contract statements.
fn discovery_document(config: &Config) -> serde_json::Value {
    serde_json::json!({
        "service": "unidpp-hub",
        "description": "UniDPP translation hub: a stateless signed relay between willing pairs \
                        divided by protocols (the SI-3 hub contract)",
        "hub_id": config.hub_id,
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
    })
}

/// Answer the liveness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "hub",
    responses(
        (status = 200, description = "The service is serving", body = Value, content_type = "application/json"),
    )
)]
async fn healthz() -> Response {
    json_response(StatusCode::OK, &serde_json::json!({"status": "ok"}))
}

/// Serve the hub's public key.
#[utoipa::path(
    get,
    path = "/keyring",
    tag = "hub",
    responses(
        (status = 200, description = "The keyring: the relay role's suite and public key, under which every relay signature verifies, and the keyring mode", body = Value, content_type = "application/json"),
    )
)]
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

/// Relay evidence between two willing schemes.
///
/// The hub checks willingness both ways, forwards the evidence bytes,
/// signs the relay in the HUB-RELAY domain over the forwarded bytes
/// plus the relay metadata, and retains nothing.
#[utoipa::path(
    post,
    path = "/relay",
    tag = "hub",
    request_body(content = Value, description = "The relay request: `{\"from\": ..., \"to\": ..., \"data_class\": ..., \"evidence_hex\": ..., \"declarations\": [declaration, ...]}` — the declarations carry both sides' published interoperability postures, because the hub holds no posture state of its own"),
    responses(
        (status = 200, description = "The evidence is relayed: the signed relay (hub id, parties, class, evidence digest, signature) and the forwarded bytes are returned, and nothing is retained", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON syntax, or an `evidence_hex` that is not hex", body = Value, content_type = "application/json"),
        (status = 415, description = "The request carries no `application/json` content type", body = Value, content_type = "application/json"),
        (status = 422, description = "The relay is refused: a side declines the class or publishes no declaration for it; the refusal states the declining side and the gap, and carries `refused: true`", body = Value, content_type = "application/json"),
    )
)]
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

/// Verify a relayed evidence under this hub's key.
///
/// The check is the recipient's, offered by the hub itself so that
/// any third party can run the verification without linking the
/// crate; linking the crate is equally conforming.
#[utoipa::path(
    post,
    path = "/relay/verify",
    tag = "hub",
    request_body(content = Value, description = "The verification request: `{\"evidence_hex\": ..., \"relay\": {..}}` — the relay exactly as returned by `POST /relay`"),
    responses(
        (status = 200, description = "The verification verdict: `verified` is `true` and the evidence digest is stated, or `verified` is `false` and the verification error is stated; both outcomes answer 200", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON syntax, or an `evidence_hex` that is not hex", body = Value, content_type = "application/json"),
        (status = 415, description = "The request carries no `application/json` content type", body = Value, content_type = "application/json"),
        (status = 422, description = "The body does not deserialize into a relay verification request", body = Value, content_type = "application/json"),
    )
)]
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

// ---------------------------------------------------------------------------
// Interface contract
// ---------------------------------------------------------------------------

/// The routed paths, declared once. The router routes by these
/// constants, the contract document is tested against them, and no
/// route may be declared with a raw literal (the gates enforce both).
pub mod paths {
    pub const ROOT: &str = "/";
    pub const HEALTHZ: &str = "/healthz";
    pub const KEYRING: &str = "/keyring";
    pub const RELAY: &str = "/relay";
    pub const RELAY_VERIFY: &str = "/relay/verify";
    /// The contract document itself (not an operation of the API).
    pub const CONTRACT_YAML: &str = "/openapi.yaml";
}

/// The OpenAPI model: one declaration per handler (`#[utoipa::path]`),
/// from which the served contract, the golden file and Swagger UI all
/// derive.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "UniDPP hub",
        version = env!("CARGO_PKG_VERSION"),
        description = "The UniDPP translation hub is a stateless signed relay between willing pairs divided by protocols (the SI-3 hub contract as an operable service). The hub carries no storage: the caller supplies both sides' published interoperability declarations and the evidence, the hub checks willingness both ways (a scheme that declines interoperability is never brokered around — the WILL gap is not the hub's to bridge), signs the forwarded bytes plus the relay metadata in the HUB-RELAY domain, and returns the relayed evidence; after the relay the hub holds nothing. Every relay verifies under the keyring's public key, at the hub or at any third party. No message of this service names a master: a pair that speaks directly has no need of it, and a pair divided by protocols loses no assurance by using it.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(discovery, healthz, keyring, relay, relay_verify),
    tags(
        (name = "hub", description = "The hub surface: discovery, liveness, the keyring, the relay and its verification"),
    )
)]
struct ApiDoc;

/// The contract document: the OpenAPI model plus the deployment keys
/// (`x-unidpp-env-keys`). Served at `/openapi.yaml` and committed as
/// the golden `openapi.yaml`.
pub fn contract_yaml() -> String {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    doc["info"]["x-unidpp-env-keys"] = serde_json::json!(Config::ENV_KEYS);
    serde_yaml::to_string(&doc).expect("contract renders as YAML")
}

async fn openapi_yaml() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/yaml")
        .body(axum::body::Body::from(contract_yaml()))
        .expect("static response parts are valid")
}

// ---------------------------------------------------------------------------
// Server wiring
// ---------------------------------------------------------------------------

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .route(paths::ROOT, get(discovery))
        .route(paths::HEALTHZ, get(healthz))
        .route(paths::KEYRING, get(keyring))
        .route(paths::RELAY, post(relay))
        .route(paths::RELAY_VERIFY, post(relay_verify))
        .route(paths::CONTRACT_YAML, get(openapi_yaml))
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

// ---------------------------------------------------------------------------
// Contract gates
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contract_gates {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    /// The contract form of a routed path: a router tail wildcard
    /// (`{*identifier}`) is a captured parameter in the document
    /// (`{identifier}`). The hub routes no wildcard today; the
    /// normalization is kept so the gate survives one.
    fn to_doc(path: &str) -> String {
        path.replace("{*", "{")
    }

    /// The contract paths with their documented methods.
    fn documented() -> std::collections::BTreeMap<String, Vec<String>> {
        let doc: serde_json::Value =
            serde_yaml::from_str(&contract_yaml()).expect("contract parses");
        doc["paths"]
            .as_object()
            .expect("paths object")
            .iter()
            .map(|(path, item)| {
                let methods = VERBS
                    .iter()
                    .filter(|v| item.get(*v).is_some())
                    .map(|v| v.to_string())
                    .collect();
                (path.clone(), methods)
            })
            .collect()
    }

    const VERBS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

    /// The routed paths, from the constants the router routes by
    /// (the contract route itself carries no operation).
    fn routed() -> Vec<&'static str> {
        [
            paths::ROOT,
            paths::HEALTHZ,
            paths::KEYRING,
            paths::RELAY,
            paths::RELAY_VERIFY,
        ]
        .to_vec()
    }

    #[test]
    fn the_golden_matches_the_committed_contract() {
        assert_eq!(contract_yaml(), include_str!("../openapi.yaml"));
    }

    #[test]
    #[ignore = "regenerates openapi.yaml after a route change: cargo test -- --ignored export"]
    fn export_golden() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"),
            contract_yaml(),
        )
        .expect("golden written");
    }

    #[test]
    fn every_routed_path_is_documented() {
        let doc = documented();
        for path in routed() {
            let key = to_doc(path);
            assert!(
                doc.contains_key(&key),
                "routed but undocumented: {path} (contract speaks `{key}`)"
            );
        }
    }

    #[test]
    fn every_documented_path_is_routed() {
        let routed: Vec<String> = routed().iter().map(|p| to_doc(p)).collect();
        for path in documented().keys() {
            assert!(routed.contains(path), "documented but not routed: {path}");
        }
    }

    #[test]
    fn routes_are_declared_by_constant_not_literal() {
        let src = include_str!("lib.rs");
        assert_eq!(
            src.matches(".route(\"").count(),
            0,
            "route paths come from the paths:: constants"
        );
    }

    /// The `VERB /path` endpoint references embedded in the discovery
    /// document must all be contracted operations.
    #[test]
    fn discovery_names_only_contracted_endpoints() {
        let discovery = discovery_document(&Config {
            bind: "127.0.0.1:0".into(),
            hub_id: "hub-test".into(),
            seed: Some("hub-test-seed".into()),
        })
        .to_string();
        let documented: Vec<String> = documented().into_keys().collect();
        for verb in VERBS.map(str::to_uppercase) {
            let mut rest = discovery.as_str();
            while let Some(pos) = rest.find(&verb) {
                let after = &rest[pos + verb.len()..];
                rest = after;
                let Some(path) = after.strip_prefix(" /") else {
                    continue;
                };
                let taken: String = path
                    .chars()
                    .take_while(|c| !matches!(c, ' ' | '"' | '{' | '<'))
                    .collect();
                let path = taken.split('?').next().unwrap_or("").to_string();
                if path.is_empty() {
                    continue;
                }
                assert!(
                    documented.contains(&format!("/{path}")),
                    "discovery names `{verb} /{path}` — no such operation in the contract"
                );
            }
        }
    }

    /// The behavioral half: every documented operation answers
    /// anything but 405, and every undocumented method on a documented
    /// path answers 405 — on the live router (the repo's own HTTP
    /// helper, tower `oneshot`).
    #[tokio::test]
    async fn the_router_serves_the_contract_exactly() {
        let app = router(Arc::new(
            AppState::new(Config {
                bind: "127.0.0.1:0".into(),
                hub_id: "hub-test".into(),
                seed: Some("hub-test-seed".into()),
            })
            .expect("state"),
        ));
        for (path, methods) in documented() {
            let concrete = path.replace("{identifier}", "probe-x");
            for verb in VERBS {
                let request = Request::builder()
                    .method(verb.to_uppercase().as_str())
                    .uri(&concrete)
                    .header("content-type", "application/json")
                    .body(if verb == "get" {
                        Body::empty()
                    } else {
                        Body::from("{}")
                    })
                    .expect("probe request");
                let resp = app.clone().oneshot(request).await.expect("probe answered");
                let status = resp.status().as_u16();
                if methods.contains(&verb.to_string()) {
                    assert_ne!(
                        status, 405,
                        "{verb} {concrete}: the contract says routed, the router says otherwise"
                    );
                } else {
                    assert_eq!(
                        status, 405,
                        "{verb} {concrete}: served but not in the contract"
                    );
                }
            }
        }
    }
}
