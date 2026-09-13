//! Entrypoint: environment-driven configuration, then serve forever.

fn main() {
    let config = unidpp_hub::Config::from_env();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(unidpp_hub::run(config)).expect("serve");
}
