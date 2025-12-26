pub mod contract_bindings;
pub mod environment_deployment;

use alloy::primitives::U160;
use contract_bindings::gate_lock::GateLock::Payload;
use rand::{self, Rng};

/// generates values for smart_contract
pub fn fetch_values() -> Vec<Payload> {
    let mut rng = rand::rng();
    let iter_cnt: usize = rng.random_range(10..100);

    (0..iter_cnt)
        .map(|_| {
            let bytes: [u8; 20] = rng.random();
            Payload { firstValue: rng.random(), secondValue: U160::from_be_bytes(bytes) }
        })
        .collect::<Vec<_>>()
}
