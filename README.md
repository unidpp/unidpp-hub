# unidpp-hub

The UniDPP translation hub: a stateless signed relay between
willing pairs divided by protocols — the SI-3 hub contract (spec
clause 12) as an operable service.

The hub carries no storage. Relaying is a pure function of the
request: the caller supplies both sides' published interop
declarations and the evidence; the hub checks willingness both ways
(a scheme that declines interop is never brokered around — the WILL
gap is not the hub's to bridge), signs the forwarded bytes plus the
relay metadata in the HUB-RELAY domain, and returns the relayed
evidence. No message of the protocol names a master; a pair that
speaks directly has no need of the hub.

## Run

```sh
UNIDPP_HUB_BIND=127.0.0.1:8397 \
UNIDPP_HUB_ID=unidpp-hub-1 \
UNIDPP_HUB_SEED=<production seed> \
  cargo run --release
```

Without `UNIDPP_HUB_SEED` the keyring runs in seeded-dev mode and
says so on every start.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | the discovery document (the hub contract) |
| GET | `/healthz` | health |
| GET | `/keyring` | the hub's public key (relay signatures verify under it) |
| POST | `/relay` | check willingness both ways, forward, sign, retain nothing |
| POST | `/relay/verify` | verify a relay under this hub's key |
