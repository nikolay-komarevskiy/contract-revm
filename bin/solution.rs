use alloy::primitives::Address;
use evm_knowledge::{
    environment_deployment::{deploy_lock_contract, spin_up_anvil_instance},
    fetch_values
};
use revm::DatabaseRef;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let controls = spin_up_anvil_instance().await?;
    let payload = fetch_values();

    let deploy_address = deploy_lock_contract(&controls, payload).await?;

    assert!(solve(deploy_address, controls).await?);
    Ok(())
}

// your solution goes here.
async fn solve<DB: DatabaseRef>(contract_address: Address, db: DB) -> eyre::Result<bool> {
    Ok(false)
}
