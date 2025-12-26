use alloy::{
    dyn_abi::SolType,
    primitives::{keccak256, Address, U256},
    sol_types::{sol_data::Bool, SolCall}
};
use evm_knowledge::{
    contract_bindings::gate_lock::GateLock,
    environment_deployment::{deploy_lock_contract, spin_up_anvil_instance},
    fetch_values
};
use eyre::{bail, eyre};
use revm::{
    db::CacheDB,
    primitives::{ExecutionResult, TransactTo},
    DatabaseRef, Evm
};

/// Slot index of `valueMap` in the GateLock storage layout (_a = 0, _b = 1,
/// valueMap = 2).
const VALUE_MAP_SLOT: u64 = 2;
/// Maximum number of mapping entries we scan.
const MAX_SLOT_TRAVERSAL_STEPS: usize = 500;
/// Arbitrary caller for calling `isSolved` method.
const CALLER_BYTE: u8 = 0x42;
/// Gas limit for the transaction.
const GAS_LIMIT: u64 = 40_000_000;
/// Bit width of the first field in `Values` (uint64),
/// occupies 0-63.
const FIRST_FIELD_BITS: u32 = 64;
/// Bit width of the second field in `Values` (uint160),
/// occupies 64-223.
const SECOND_FIELD_BITS: u32 = 160;
/// Bit offset of the `isUnlocked` flag in `Values` (64 + 160)
/// , flag occupies (224-231 bits).
const UNLOCKED_FLAG_OFFSET: u32 = 224;
/// Mask for the unlocked flag
const UNLOCKED_FLAG_MASK: u8 = 255;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let controls = spin_up_anvil_instance().await?;
    let payload = fetch_values();

    let deploy_address = deploy_lock_contract(&controls, payload).await?;

    assert!(solve(deploy_address, controls).await?);
    Ok(())
}

/// Unlocks the contract and calls `isSolved` in the REVM.
///
/// 1) Traverse the list in `valueMap` and find every slot id.
/// 2) Flip the `isUnlocked` flag for each slot in the REVM cache.
/// 3) Call `isSolved` for the mutated state.
async fn solve<DB: DatabaseRef>(contract_address: Address, db: DB) -> eyre::Result<bool> {
    let mut cache = CacheDB::new(db);

    let ids = collect_slots(contract_address, &mut cache)?;
    mark_slots_unlocked(contract_address, &mut cache, &ids)?;

    let calldata = GateLock::isSolvedCall { ids }.abi_encode();

    let mut evm = Evm::builder()
        .with_db(cache)
        .modify_tx_env(move |tx| {
            tx.caller = Address::repeat_byte(CALLER_BYTE);
            tx.gas_limit = GAS_LIMIT;
            tx.transact_to = TransactTo::Call(contract_address);
            tx.data = calldata.into();
        })
        .build();

    let result_state = evm
        .transact()
        .map_err(|_| eyre::eyre!("EVM execution failed"))?;

    let solved = match result_state.result {
        ExecutionResult::Success { output, .. } => {
            Bool::abi_decode(output.into_data().as_ref(), true)?
        }
        ExecutionResult::Revert { output, .. } => {
            bail!("isSolved reverted: 0x{}", alloy::hex::encode(output))
        }
        ExecutionResult::Halt { reason, .. } => bail!("execution halted: {reason:?}")
    };

    Ok(solved)
}

/// Traverses the `valueMap` mapping starting from key 0, gathering every
/// visited slot id.
///
/// The next slot id is `firstValue` when even, otherwise `secondValue`.
/// Traversal stops when a zero is encountered or limit exceeds.
fn collect_slots<DB: DatabaseRef>(
    contract_address: Address,
    cache_db: &mut CacheDB<DB>
) -> eyre::Result<Vec<U256>> {
    let mut slots = Vec::new();
    let mut cursor = U256::ZERO;

    for _ in 0..MAX_SLOT_TRAVERSAL_STEPS {
        let storage_key = mapping_slot(cursor, VALUE_MAP_SLOT);

        let word = cache_db
            .storage_ref(contract_address, storage_key)
            .map_err(|_| eyre!("failed to read valueMap entry"))?;

        if word.is_zero() {
            break;
        }

        slots.push(cursor);

        let (first_value, second_value) = decode_payload(word);

        cursor = if first_value % 2 == 0 { U256::from(first_value) } else { second_value };
    }

    if slots.len() == MAX_SLOT_TRAVERSAL_STEPS {
        bail!("traversal exceeded the maximum steps");
    }

    Ok(slots)
}

/// Marks slots as unlocked in REVM cache.
fn mark_slots_unlocked<DB: DatabaseRef>(
    contract: Address,
    cache: &mut CacheDB<DB>,
    slots: &[U256]
) -> eyre::Result<()> {
    for slot in slots {
        let storage_key = mapping_slot(*slot, VALUE_MAP_SLOT);
        let stored_flag = cache
            .storage_ref(contract, storage_key)
            .map_err(|_| eyre!("failed to read valueMap entry for unlocking"))?;
        if is_unlocked(stored_flag) {
            continue;
        }
        let updated_flag = mark_unlocked(stored_flag);
        cache
            .insert_account_storage(contract, storage_key, updated_flag)
            .map_err(|_| eyre!("failed to override valueMap entry"))?;
    }
    Ok(())
}

/// Computes the storage slot for a Solidity mapping entry
fn mapping_slot(key: U256, slot: u64) -> U256 {
    let mut keccak_input = [0u8; 64];
    keccak_input[..32].copy_from_slice(&key.to_be_bytes::<32>());
    keccak_input[32..].copy_from_slice(&U256::from(slot).to_be_bytes::<32>());
    let hash = keccak256(keccak_input);
    U256::from_be_bytes(hash.0)
}

/// Decodes the packed `Values` struct from a raw storage word.
fn decode_payload(word: U256) -> (u64, U256) {
    let first_mask = bitmask(FIRST_FIELD_BITS);
    let second_mask = bitmask(SECOND_FIELD_BITS);

    let first = word & first_mask;
    let second = (word >> FIRST_FIELD_BITS) & second_mask;

    (first.as_limbs()[0], second)
}

fn is_unlocked(word: U256) -> bool {
    ((word >> UNLOCKED_FLAG_OFFSET) & U256::from(UNLOCKED_FLAG_MASK)) != U256::ZERO
}

fn mark_unlocked(word: U256) -> U256 {
    word | (U256::from(1u8) << UNLOCKED_FLAG_OFFSET)
}

fn bitmask(bits: u32) -> U256 {
    (U256::from(1u8) << bits) - U256::from(1u8)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, U160, U256};
    use evm_knowledge::{
        contract_bindings::gate_lock::GateLock::Payload,
        environment_deployment::{deploy_lock_contract, spin_up_anvil_instance}
    };
    use revm::{
        db::{CacheDB, EmptyDB},
        primitives::AccountInfo
    };

    use crate::{collect_slots, mapping_slot, solve, VALUE_MAP_SLOT};

    fn payload_to_slots(payloads: &[Payload]) -> Vec<U256> {
        let mut slots = Vec::with_capacity(payloads.len());
        let mut slot = U256::ZERO;

        for payload in payloads {
            slots.push(slot);

            slot = if payload.firstValue % 2 == 0 {
                U256::from(payload.firstValue)
            } else {
                let bytes = payload.secondValue.to_be_bytes::<20>();
                U256::from_be_slice(&bytes)
            };
        }

        slots
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_empty_payload() -> eyre::Result<()> {
        let controls = spin_up_anvil_instance().await?;
        let payload: Vec<Payload> = vec![];
        let slots_expected = payload_to_slots(&payload);
        let deploy_address = deploy_lock_contract(&controls, payload).await?;
        let mut cache = CacheDB::new(&controls);
        let slots = collect_slots(deploy_address, &mut cache)?;
        assert_eq!(slots, slots_expected);
        assert!(solve(deploy_address, controls).await?);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_single_payload() -> eyre::Result<()> {
        let controls = spin_up_anvil_instance().await?;
        let payload: Vec<Payload> =
            vec![Payload { firstValue: 2, secondValue: U160::from(11u64) }];
        let slots_expected = payload_to_slots(&payload);
        let deploy_address = deploy_lock_contract(&controls, payload).await?;
        let mut cache = CacheDB::new(&controls);
        let slots = collect_slots(deploy_address, &mut cache)?;
        assert_eq!(slots, slots_expected);
        assert!(solve(deploy_address, controls).await?);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multiple_payloads() -> eyre::Result<()> {
        let controls = spin_up_anvil_instance().await?;
        let payload: Vec<Payload> = vec![
            Payload { firstValue: 1, secondValue: U160::from(5u64) },
            Payload { firstValue: 4, secondValue: U160::from(7u64) },
            Payload { firstValue: 3, secondValue: U160::from(9u64) },
            Payload { firstValue: 8, secondValue: U160::from(11u64) },
            Payload { firstValue: 15, secondValue: U160::from(17u64) },
            Payload { firstValue: 6, secondValue: U160::from(19u64) },
            Payload { firstValue: 25, secondValue: U160::from(21u64) },
        ];
        // Expected traversal: 0 -> 5 -> 4 -> 9 -> 8 -> 17 -> 6
        let slots_expected = payload_to_slots(&payload);
        let deploy_address = deploy_lock_contract(&controls, payload).await?;
        let mut cache = CacheDB::new(&controls);
        let slots = collect_slots(deploy_address, &mut cache)?;
        assert_eq!(slots_expected.len(), 7);
        assert_eq!(slots, slots_expected);
        assert!(solve(deploy_address, controls).await?);
        Ok(())
    }

    #[test]
    fn test_traversal_limit_exceeded() {
        let contract = Address::repeat_byte(0x11);
        let mut cache = CacheDB::new(EmptyDB::default());
        cache.insert_account_info(contract, AccountInfo::default());

        let slot0 = mapping_slot(U256::ZERO, VALUE_MAP_SLOT);
        // Storage word encodes firstValue=1 (odd) and secondValue=0,
        // so traversal never leaves slot zero and hits the MAX_TRAVERSAL_STEPS.
        cache
            .insert_account_storage(contract, slot0, U256::from(1u64))
            .unwrap();

        let err = collect_slots(contract, &mut cache).unwrap_err();
        assert!(err.to_string().contains("traversal exceeded"), "unexpected error: {err}");
    }
}
