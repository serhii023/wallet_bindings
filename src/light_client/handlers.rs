use eyre::eyre;
use futures::{TryStreamExt, future::err};
use pczt::Pczt;
use prost::Message;
use rand_core::OsRng;
use safer_ffi::derive_ReprC;
use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use tokio::{fs::File, io::AsyncWriteExt, task::JoinHandle};
use tonic::{
    client,
    transport::{Channel, ClientTlsConfig},
};
use tracing::{debug, error, info};
use zcash_address::ZcashAddress;

use zcash_client_backend::{
    data_api::{
        self, Account, AccountBirthday, AccountPurpose, WalletRead, WalletWrite,
        chain::{BlockSource, ChainState, scan_cached_blocks},
        scanning::{ScanPriority, ScanRange},
        wallet::{
            ConfirmationsPolicy, create_pczt_from_proposal,
            extract_and_store_transaction_from_pczt, input_selection::GreedyInputSelector,
            propose_transfer,
        },
    },
    fees::{DustOutputPolicy, zip317::SingleOutputChangeStrategy},
    keys::UnifiedFullViewingKey,
    proto::service::{
        self, BlockId, BlockRange, ChainSpec, compact_tx_streamer_client::CompactTxStreamerClient,
    },
    wallet::OvkPolicy,
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::{
    BlockDb, FsBlockDb, FsBlockDbError, WalletDb, chain, chain::BlockMeta, util::SystemClock,
    wallet,
};
use zcash_protocol::{ShieldedProtocol, value::Zatoshis};

use orchard::circuit::VerifyingKey;
use rand::rngs::ThreadRng;
use rusqlite::Connection;
use zcash_primitives::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
    transaction::{
        TxVersion, fees::zip317::FeeRule, sighash::SignableInput, sighash_v5::v5_signature_hash,
        txid::TxIdDigester,
    },
};

use zcash_client_backend::data_api::chain::error::Error as ChainError;

use crate::light_client::sync::Server;

const BLOCKS_FOLDER: &str = "blocks";
const BATCH_SIZE: u32 = 10_000;

/// The enumeration of known Zcash networks.
#[derive_ReprC]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Zcash Mainnet.
    MainNetwork = 0,
    /// Zcash Testnet.
    TestNetwork,
}

impl Network {
    pub fn as_paramether(&self) -> zcash_primitives::consensus::Network {
        self.into()
    }
}

impl From<&Network> for zcash_primitives::consensus::Network {
    fn from(value: &Network) -> Self {
        match value {
            Network::MainNetwork => Self::MainNetwork,
            Network::TestNetwork => Self::TestNetwork,
        }
    }
}

pub(crate) fn init_wallet_db<F: AsRef<Path>>(path: F, network: Network) -> eyre::Result<()> {
    let mut wallet_db = WalletDb::for_path(
        path,
        network.as_paramether(),
        SystemClock,
        rand::rngs::OsRng,
    )?;
    wallet::init::init_wallet_db(&mut wallet_db, None)?;

    Ok(())
}

pub(crate) fn init_cache_database<F: AsRef<Path>>(cache_file: F) -> eyre::Result<()> {
    let mut block_db = BlockDb::for_path(cache_file)?;
    chain::init::init_cache_database(&mut block_db)?;

    Ok(())
}

pub(crate) fn init_blockmeta_db<F: AsRef<Path>>(fsblockdb_root: F) -> eyre::Result<FsBlockDb> {
    let mut block_meta_db =
        FsBlockDb::for_path(fsblockdb_root).map_err(|err| eyre!("{:?}", err))?;
    chain::init::init_blockmeta_db(&mut block_meta_db)?;

    Ok(block_meta_db)
}

pub(crate) async fn import_account_ufvk<'a, F: AsRef<Path>, P: Parameters>(
    db_path: F,
    params: &P,
    server: Server<'a>,
    account_name: &str,
    encoded_ufvk: &str,
    birthday_height: u64,
) -> eyre::Result<()> {
    let mut wallet_db = WalletDb::for_path(db_path, params, SystemClock, rand::rngs::OsRng)?;

    let ufvk = UnifiedFullViewingKey::decode(params, encoded_ufvk)
        .map_err(|err| eyre!("Invalid UFVK: {err:?}"))?;

    let mut client = server.connect_direct().await?;

    let request = service::BlockId {
        height: birthday_height,
        hash: vec![],
    };
    let response_state = client
        .get_tree_state(request)
        .await
        .unwrap()
        .into_inner()
        .to_chain_state()
        .unwrap();

    let birthday = AccountBirthday::from_parts(response_state, None);

    let purpose = AccountPurpose::ViewOnly;
    wallet_db.import_account_ufvk(account_name, &ufvk, &birthday, purpose, None)?;

    Ok(())
}

pub(crate) async fn create_orchard_transaction<F: AsRef<Path>, P: Parameters>(
    path: F,
    params: &P,
    encoded_ufvk: &str,
    amount_zatoshis: u64,
    recipient_address: &str,
    // memo: Option<&[u8]>,
    memo: &[u8],
) -> eyre::Result<Pczt> {
    let change_memo = None;

    let mut wallet_db = WalletDb::for_path(path, params, SystemClock, rand::rngs::OsRng)?;

    let ufvk = UnifiedFullViewingKey::decode(params, encoded_ufvk)
        .map_err(|err| eyre!("Invalid UFVK: {err:?}"))?;

    let recipient_address = ZcashAddress::from_str(recipient_address)
        .map_err(|err| eyre!("Invalid unified address: {err:?}"))?;

    let memo = if memo.is_empty() {
        None
    } else {
        Some(MemoBytes::from_bytes(memo)?)
    };

    let Some(account) = wallet_db.get_account_for_ufvk(&ufvk)? else {
        return Err(eyre!("Unknown ufvk".to_string()));
    };

    let account_id = account.id();
    let amount = Zatoshis::from_u64(amount_zatoshis)?;
    let transaction_request =
        match Payment::new(recipient_address, amount, memo, None, None, vec![]) {
            Some(payment) => TransactionRequest::new(vec![payment]).unwrap(),
            None => TransactionRequest::empty(),
        };

    let change_strategy = SingleOutputChangeStrategy::new(
        FeeRule::standard(),
        change_memo,
        ShieldedProtocol::Orchard,
        DustOutputPolicy::default(),
    );
    let proposal =
        propose_transfer::<_, _, _, _, zcash_client_sqlite::wallet::commitment_tree::Error>(
            &mut wallet_db,
            params,
            account_id,
            &GreedyInputSelector::default(),
            &change_strategy,
            transaction_request,
            ConfirmationsPolicy::default(),
        )
        .unwrap();

    let pczt = create_pczt_from_proposal::<_, _, (), _, (), _>(
        &mut wallet_db,
        params,
        account_id,
        OvkPolicy::Sender,
        &proposal,
    )
    .unwrap();

    Ok(pczt)
}

pub(crate) async fn broadcast_transaction<'a, P: Parameters + Send + 'static, F: AsRef<Path>>(
    server: Server<'a>,
    pczt_bytes: &[u8],
    path: F,
    params: &P,
) -> eyre::Result<()> {
    let mut client = server.connect_direct().await?;
    let pczt = Pczt::parse(pczt_bytes).map_err(|err| eyre!("Failed to parse Pczt: {err:?}"))?;
    let mut wallet_db = WalletDb::for_path(path, params, SystemClock, rand::rngs::OsRng)?;

    // Extract the final transaction and store it in wallet_db
    let txid = extract_and_store_transaction_from_pczt::<_, ()>(
        &mut wallet_db,
        pczt,
        None,
        Some(&VerifyingKey::build()),
    )
    .map_err(|err| eyre!("Failed to extract and store transaction from PCZT: {err:?}",))?;

    info!("Transaction created: {}", txid);

    // Broadcast transaction to the network
    let tx = wallet_db
        .get_transaction(txid)?
        .ok_or(eyre!("Failed to retreive just stored transaction"))?;
    let txid = tx.txid();

    let raw_tx = {
        let mut raw_tx = service::RawTransaction::default();
        tx.write(&mut raw_tx.data).unwrap();
        raw_tx
    };

    let response = client.send_transaction(raw_tx).await?.into_inner();

    if response.error_code != 0 {
        error!(code = ?response.error_code, message = ?response.error_message, "SendFailed");
        Err(eyre!(
            "SendFailed: code: {}, reason: {}",
            response.error_code,
            response.error_message
        ))
    } else {
        info!(txid = ?txid, "Transaction sent");
        Ok(())
    }
}
