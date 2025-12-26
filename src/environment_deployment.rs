use alloy::{
    network::{Ethereum, EthereumWallet},
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, B256, U256},
    providers::{Identity, Provider, RootProvider, builder, fillers::*},
    signers::local::PrivateKeySigner,
    transports::BoxTransport
};
use eyre::bail;
use revm::{
    DatabaseRef,
    primitives::{self, Bytecode}
};

use crate::contract_bindings::{self, gate_lock::GateLock::Payload};

pub type AnvilProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>
        >,
        WalletFiller<EthereumWallet>
    >,
    RootProvider<BoxTransport>,
    BoxTransport,
    Ethereum
>;

pub async fn spin_up_anvil_instance() -> eyre::Result<AnvilControls> {
    let anvil = Anvil::new().chain_id(1).arg("--ipc").try_spawn()?;

    let sk: PrivateKeySigner = anvil.keys()[7].clone().into();

    let wallet = EthereumWallet::new(sk);

    let rpc = builder::<Ethereum>()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&anvil.ws_endpoint())
        .await?;

    Ok(AnvilControls { provider: rpc, wallet, instance: anvil })
}

pub async fn deploy_lock_contract(
    controls: &AnvilControls,
    payload: Vec<Payload>
) -> eyre::Result<Address> {
    let deploy =
        contract_bindings::gate_lock::GateLock::deploy(controls.provider.clone(), payload).await?;

    Ok(*deploy.address())
}

pub struct AnvilControls {
    pub provider: AnvilProvider,
    pub wallet:   EthereumWallet,
    pub instance: AnvilInstance
}

impl DatabaseRef for AnvilControls {
    type Error = eyre::Error;

    fn basic_ref(
        &self,
        address: Address
    ) -> Result<Option<revm::primitives::AccountInfo>, Self::Error> {
        let acc = async_to_sync(self.provider.get_account(address).latest().into_future())?;
        let code = async_to_sync(self.provider.get_code_at(address).latest().into_future())?;
        let code = Some(Bytecode::new_raw(code));

        Ok(Some(revm::primitives::AccountInfo {
            code_hash: acc.code_hash,
            balance: acc.balance,
            nonce: acc.nonce,
            code
        }))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let acc = async_to_sync(self.provider.get_storage_at(address, index).into_future())?;
        Ok(acc)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let acc = async_to_sync(
            self.provider
                .get_block_by_number(
                    alloy::rpc::types::BlockNumberOrTag::Number(number),
                    alloy::rpc::types::BlockTransactionsKind::Hashes
                )
                .into_future()
        )?;

        let Some(block) = acc else { bail!("failed to load block") };
        Ok(block.header.hash)
    }

    fn code_by_hash_ref(&self, _: B256) -> Result<primitives::Bytecode, Self::Error> {
        panic!("This should not be called, as the code is already loaded");
    }
}

pub fn async_to_sync<F: Future>(f: F) -> F::Output {
    let handle = tokio::runtime::Handle::try_current().expect("No tokio runtime found");
    tokio::task::block_in_place(|| handle.block_on(f))
}
