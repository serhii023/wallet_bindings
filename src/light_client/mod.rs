use safer_ffi::{derive_ReprC, ffi_export, prelude::*};
use std::{ffi::c_int, path::Path};
use tokio_util::sync::CancellationToken;
use tracing::error;
use zcash_client_sqlite::{FsBlockDb, WalletDb, util::SystemClock};

pub mod handlers;
pub mod sync;
pub mod zcash_sign;

use crate::{RUNTIME, errors::ExecutionError};
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
            error!(err = ?err, "init_wallet_db failed");
            -1
        }
    }
}

#[ffi_export]
pub fn import_account_ufvk() -> c_int {
    todo!()
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
            error!(error = ?err);
            -1
        }
    }
}

#[ffi_export]
pub fn send_from_orchard() -> c_int {
    todo!()
}

#[ffi_export]
pub fn read_pczt_signining_inputs() -> c_int {
    todo!()
}

#[ffi_export]
pub fn write_pczt_signing_outputs() -> c_int {
    todo!()
}
