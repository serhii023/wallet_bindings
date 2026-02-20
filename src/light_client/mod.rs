use eyre::eyre;
use orchard::keys::SpendValidatingKey;
use pczt::Pczt;
use rand::thread_rng;
use reddsa::frost::redpallas::keys::PublicKeyPackage;
use safer_ffi::{derive_ReprC, ffi_export, prelude::*};
use std::{
    ffi::{CString, c_int},
    path::Path,
};
use tokio_util::sync::CancellationToken;
use tracing::error;
use zcash_client_sqlite::{FsBlockDb, WalletDb, util::SystemClock};
use zcash_protocol::consensus::Parameters;

pub mod handlers;
pub mod sync;
pub mod zcash_sign;

use crate::{
    RUNTIME,
    errors::ExecutionError,
    light_client::{self, zcash_sign::IndexedAlpha},
};
use handlers::Network;
use sync::Server;

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct LightClientConfig {
    wallet_db: safer_ffi::String,
    cache_root_folder: safer_ffi::String,
}

#[ffi_export]
pub fn random_spending_key() -> [u8; 32] {
    zcash_sign::random_spending_key(&mut thread_rng())
}

#[ffi_export]
pub fn ufvk_from_sk_pkp(
    network: Network,
    sk: [u8; 32],
    pkp: &safer_ffi::Vec<u8>,
    ufvk: &mut char_p::Box,
) -> c_int {
    let encoded_ufvk = match zcash_sign::ufvk_from_sk_pkp(sk, &pkp.to_vec()) {
        Ok(public_package) => public_package,
        Err(err) => {
            error!(err = ?err, "failed to create ufvk from spending key and public key package");
            return -1;
        }
    }
    .encode(&network.as_paramether());

    match encoded_ufvk.try_into() {
        Ok(encoded_ufvk) => *ufvk = encoded_ufvk,
        Err(err) => {
            error!(err = ?err);
            return -1;
        }
    };

    0
}

#[ffi_export]
pub fn init_wallet_db(path: char_p::Ref<'_>, network: Network) -> c_int {
    let path_str: &str = path.to_str();

    match handlers::init_wallet_db(path_str, network) {
        Ok(_) => 0,
        Err(err) => {
            error!(err = ?err, "init_wallet_db failed");
            -1
        }
    }
}

#[ffi_export]
pub fn init_blockmeta_db(fsblockdb_root: char_p::Ref<'_>) -> c_int {
    let fsblockdb_root_str: &str = fsblockdb_root.to_str();

    match handlers::init_blockmeta_db(fsblockdb_root_str) {
        Ok(_) => 0,
        Err(err) => {
            error!(err = ?err, "init_blockmeta_db failed");
            -1
        }
    }
}

#[ffi_export]
pub fn import_account_ufvk(
    db_path: char_p::Ref<'_>,
    network: Network,
    host: char_p::Ref<'_>,
    port: u16,
    account_name: char_p::Ref<'_>,
    encoded_ufvk: char_p::Ref<'_>,
    birthday_height: u64,
) -> c_int {
    let server = Server::new(host.to_str(), port);

    match RUNTIME.block_on(handlers::import_account_ufvk(
        db_path.to_str(),
        &network.as_paramether(),
        server,
        account_name.to_str(),
        encoded_ufvk.to_str(),
        birthday_height,
    )) {
        Ok(_) => {}
        Err(err) => {
            error!(err = ?err, "import_account_ufvk failed");
            return -1;
        }
    }

    0
}

#[ffi_export]
pub fn run_sync(
    host: char_p::Ref<'_>,
    port: u16,
    fsblockdb_root: char_p::Ref<'_>,
    network: Network,
    db_path: char_p::Ref<'_>,
) -> c_int {
    let server = Server::new(host.to_str(), port);
    let mut cancelation = CancellationToken::new();

    match RUNTIME.block_on(sync::run(
        network,
        fsblockdb_root.to_str(),
        db_path.to_str(),
        server,
        &mut cancelation,
    )) {
        Ok(_) => 0,
        Err(err) => {
            error!(error = ?err, "run_sync failed");
            -1
        }
    }
}

#[ffi_export]
pub fn create_orchard_transaction(
    network: Network,
    db_path: char_p::Ref<'_>,
    encoded_ufvk: char_p::Ref<'_>,
    amount_zatoshis: u64,
    recipient_address: char_p::Ref<'_>,
    memo: safer_ffi::bytes::Bytes<'_>,
    serialized_pczt: &mut safer_ffi::Vec<u8>,
) -> c_int {
    let pczt = match RUNTIME.block_on(handlers::create_orchard_transaction(
        db_path.to_str(),
        &network.as_paramether(),
        encoded_ufvk.to_str(),
        amount_zatoshis,
        recipient_address.to_str(),
        memo.as_slice(),
    )) {
        Ok(pczt) => pczt,
        Err(err) => {
            error!(error = ?err);
            return -1;
        }
    };

    *serialized_pczt = pczt.serialize().into();

    0
}

#[ffi_export]
pub fn read_pczt_signining_inputs(
    serialized_pczt: &safer_ffi::Vec<u8>,
    sighash: &mut safer_ffi::Vec<u8>,
    alphas: &mut safer_ffi::Vec<IndexedAlpha>,
) -> c_int {
    let (_sighash, _alphas) =
        match zcash_sign::read_pczt_signining_inputs(&serialized_pczt.to_vec()) {
            Ok(res) => res,
            Err(err) => {
                error!(error = ?err);
                return -1;
            }
        };

    *sighash = _sighash.into();
    *alphas = _alphas.into();

    0
}

#[ffi_export]
pub fn write_pczt_signing_outputs(
    serialized_pczt: &safer_ffi::Vec<u8>,
    sighash: &safer_ffi::Vec<u8>,
    signatures: &safer_ffi::Vec<safer_ffi::Vec<u8>>,
    signed_pczt: &mut safer_ffi::Vec<u8>,
) -> c_int {
    let signatures = signatures
        .iter()
        .map(|signature| signature.to_vec())
        .collect::<Vec<_>>();

    *signed_pczt = match zcash_sign::write_pczt_signing_outputs(
        &serialized_pczt.to_vec(),
        &sighash.to_vec(),
        &signatures,
    ) {
        Ok(signed_pczt) => signed_pczt.into(),
        Err(err) => {
            error!(error = ?err);
            return -1;
        }
    };

    0
}

#[ffi_export]
pub fn broadcast_transaction(
    serialized_pczt: &safer_ffi::Vec<u8>,
    host: char_p::Ref<'_>,
    port: u16,
    db_path: char_p::Ref<'_>,
    network: Network,
) -> c_int {
    let server = Server::new(host.to_str(), port);

    match RUNTIME.block_on(handlers::broadcast_transaction(
        server,
        &serialized_pczt.to_vec(),
        db_path.to_str(),
        &network.as_paramether(),
    )) {
        Ok(_) => {}
        Err(err) => {
            error!(error = ?err);
            return -1;
        }
    };

    0
}
