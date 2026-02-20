use once_cell::sync::Lazy;
use std::sync::Once;

use safer_ffi::{derive_ReprC, ffi_export};
use tokio::runtime::Runtime;

pub mod errors;
pub mod light_client;
pub mod orchard;

static RUNTIME: Lazy<Runtime> =
    Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

#[derive_ReprC]
#[repr(u8)]
pub enum LogLevel {
    Off = 0,
    Error,
    Warning,
    Info,
    Debug,
}

#[ffi_export]
pub fn init_rust_logging(level: LogLevel) {
    use tracing::Level;

    let level = match level {
        LogLevel::Off => return,
        LogLevel::Error => Level::ERROR,
        LogLevel::Warning => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
    };

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt().with_max_level(level).init();
    });
}

// The following function is only necessary for the header generation.
#[cfg(feature = "headers")]
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("include/rust_points.h")?
        .generate()
}

#[cfg(test)]
mod tests {
    use eyre::eyre;
    use safer_ffi::{char_p::char_p_ref, prelude::*};
    use std::{
        env,
        ffi::CString,
        fs,
        path::{Path, PathBuf},
        ptr::NonNull,
    };
    use tracing::{info, warn};

    use crate::{
        LogLevel, init_rust_logging, light_client,
        orchard::frost_rerandomized::{IdentifiedData, KeyPackage, TrustedShares},
    };

    const TEST_DIR: &str = "test_data";

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
            let path = path.as_ref().to_path_buf();

            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    // impl Drop for TestDir {
    //     fn drop(&mut self) {
    //         if self.path.exists() {
    //             let _ = fs::remove_dir_all(&self.path);
    //         }
    //     }
    // }

    #[derive(Debug, Clone)]
    struct TestConfig {
        pub encoded_ufvk: String,
        pub host: String,
        pub port: u16,
        pub receiver_address: String,
        pub birthday_height: u64,
        pub db_path: String,
        pub fsblockdb_root: String,
    }

    impl TestConfig {
        fn new(
            encoded_ufvk: String,
            host: String,
            port: u16,
            receiver_address: String,
            birthday_height: u64,
            db_path: String,
            fsblockdb_root: String,
        ) -> Self {
            Self {
                encoded_ufvk,
                host,
                port,
                receiver_address,
                birthday_height,
                db_path,
                fsblockdb_root,
            }
        }

        fn from_env() -> eyre::Result<Self> {
            let encoded_ufvk = env::var("ENCODED_UFVK")?;
            let host = env::var("HOST")?;
            let port: u16 = env::var("PORT")?.parse()?;
            let receiver_address = env::var("RECEIVER_ADDRESS")?;
            let birthday_height: u64 = env::var("BIRTHDAY_HEIGHT")?.parse()?;
            let db_path = env::var("DB_PATH")?;
            let fsblockdb_root = env::var("FSBLOCKDB_ROOT")?;

            Ok(Self::new(
                encoded_ufvk,
                host,
                port,
                receiver_address,
                birthday_height,
                db_path,
                fsblockdb_root,
            ))
        }
    }

    // TODO: fix test
    // #[test]
    fn test_randomized_frost_for_pczt() -> eyre::Result<()> {
        init_rust_logging(LogLevel::Info);

        let max_signers = 5;
        let min_signers = 3;
        let network = light_client::handlers::Network::TestNetwork;

        let (trusted_public_key_package, trusted_key_packages) =
            examle_trusted_key_gen(max_signers, min_signers);
        let sk = light_client::random_spending_key();
        let mut ufvk = "".to_string().try_into().unwrap();
        let err =
            light_client::ufvk_from_sk_pkp(network, sk, &trusted_public_key_package, &mut ufvk);
        assert_eq!(err, 0);
        info!(ufvk = ?hex::encode(&ufvk.to_string()));

        dotenvy::dotenv().ok();
        init_rust_logging(LogLevel::Info);

        let mut config = TestConfig::from_env()?;
        config.encoded_ufvk = ufvk.to_string();
        info!(config = ?config);

        let pczt = create_pczt(&config)?;

        let mut sighash = safer_ffi::Vec::EMPTY;
        let mut alphas = safer_ffi::Vec::EMPTY;
        let res = light_client::read_pczt_signining_inputs(&pczt, &mut sighash, &mut alphas);
        assert_eq!(res, 0);

        info!(sighash = ?sighash);

        info!("Sign with trusted setup...");
        let signature = randomized_frost_sign_verify(
            trusted_public_key_package,
            trusted_key_packages,
            &sighash,
        )?;

        // DKGPublicKeyPackage, DKGKeyPackages := ExamplekeyGen(max_signers, min_signers)
        // info!("Sign with DKG keys...");
        // RandomizedFrost(DKGPublicKeyPackage, DKGKeyPackages)

        Ok(())
    }

    #[test]
    fn test_randomized_frost() -> eyre::Result<()> {
        init_rust_logging(LogLevel::Info);

        let max_signers = 5;
        let min_signers = 3;

        let (trusted_public_key_package, trusted_key_packages) =
            examle_trusted_key_gen(max_signers, min_signers);
        info!("Sign with trusted setup...");
        let msg = b"Some message";
        randomized_frost_sign_verify(trusted_public_key_package, trusted_key_packages, msg)?;

        // DKGPublicKeyPackage, DKGKeyPackages := ExamplekeyGen(max_signers, min_signers)
        // info!("Sign with DKG keys...");
        // RandomizedFrost(DKGPublicKeyPackage, DKGKeyPackages)

        Ok(())
    }

    fn examle_trusted_key_gen(
        max_signers: u16,
        min_signers: u16,
    ) -> (safer_ffi::Vec<u8>, Vec<IdentifiedData<KeyPackage>>) {
        let mut gen_result = TrustedShares::default();
        let err = crate::orchard::frost_rerandomized::frost_randomized_keygen_dealer(
            max_signers,
            min_signers,
            &mut gen_result,
        );
        assert_eq!(err, 0, "Fail to generate keys with dealer");

        let pk = gen_result.public_key_package;
        let key_packages = gen_result.key_packages.to_vec();

        return (pk, key_packages);
    }

    fn randomized_frost_sign_verify(
        public_key_package: safer_ffi::Vec<u8>,
        key_packages: Vec<IdentifiedData<KeyPackage>>,
        msg: &[u8],
    ) -> eyre::Result<safer_ffi::Vec<u8>> {
        let mut sig_nonces = Vec::with_capacity(key_packages.len());
        let mut sig_commitments = Vec::with_capacity(key_packages.len());
        let mut sig_identified_commitments = Vec::with_capacity(key_packages.len());

        for (i, key_package) in key_packages.iter().enumerate() {
            let id = (i + 1) as u16;

            let mut sig_nonce = safer_ffi::Vec::EMPTY;
            let mut sig_commitment = safer_ffi::Vec::EMPTY;
            let mut sig_identified_commitment = IdentifiedData {
                identifier: Default::default(),
                data: safer_ffi::Vec::EMPTY,
            };

            let err = crate::orchard::frost_rerandomized::frost_randomized_commit(
                id,
                &key_package.data(),
                &mut sig_nonce,
                &mut sig_commitment,
                &mut sig_identified_commitment,
            );
            assert_eq!(err, 0);

            sig_nonces.push(sig_nonce);
            sig_commitments.push(sig_commitment);
            sig_identified_commitments.push(sig_identified_commitment);
        }

        let mut signing_package = safer_ffi::Vec::EMPTY;
        let err = crate::orchard::frost_rerandomized::frost_randomized_signing_package_new(
            &sig_identified_commitments.into(),
            &msg.to_vec().into(),
            &mut signing_package,
        );
        assert_eq!(err, 0, "Fail to create new signing package for signature");

        let randomizer = crate::orchard::frost_rerandomized::frost_randomized_new_randomizer();

        let mut signature_packages = Vec::new();
        let mut identified_signature_packages = Vec::new();
        for i in 0..key_packages.len() {
            let mut signature_package = safer_ffi::Vec::EMPTY;
            let mut identified_signature_package = IdentifiedData {
                identifier: Default::default(),
                data: safer_ffi::Vec::EMPTY,
            };

            let err = crate::orchard::frost_rerandomized::frost_randomized_sign_package(
                &signing_package,
                &sig_nonces[i],
                &key_packages[i].data(),
                &randomizer,
                &mut signature_package,
                &mut identified_signature_package,
            );
            assert_eq!(err, 0, "fail to sign the package");

            signature_packages.push(signature_package);
            identified_signature_packages.push(identified_signature_package);
        }

        let gathered_signatures = identified_signature_packages.into();
        let mut aggregated_signature = safer_ffi::Vec::EMPTY;
        let err = crate::orchard::frost_rerandomized::frost_randomized_aggregate(
            &signing_package,
            &gathered_signatures,
            &public_key_package,
            &randomizer,
            &mut aggregated_signature,
        );
        assert_eq!(err, 0);

        let err = crate::orchard::frost_rerandomized::frost_randomized_verify(
            &msg.to_vec().into(),
            &aggregated_signature,
            &public_key_package,
            &randomizer,
        );
        assert_eq!(err, 0, "Verification failed");

        info!("Verification sucsessfull");

        Ok(aggregated_signature)
    }

    #[test]
    fn test_lightwallet_workflow() -> eyre::Result<()> {
        dotenvy::dotenv().ok();
        init_rust_logging(LogLevel::Info);

        let config = TestConfig::from_env()?;
        info!(config = ?config);

        let pczt = create_pczt(&config)?;

        let mut sighash = safer_ffi::Vec::EMPTY;
        let mut alphas = safer_ffi::Vec::EMPTY;
        let res = light_client::read_pczt_signining_inputs(&pczt, &mut sighash, &mut alphas);
        assert_eq!(res, 0);

        info!(sighash = ?sighash);

        Ok(())
    }

    fn create_pczt(config: &TestConfig) -> eyre::Result<safer_ffi::Vec<u8>> {
        let _test_dir = TestDir::new(TEST_DIR)?;

        let db_path = std::ffi::CString::new(format!("{}/{}", TEST_DIR, config.db_path.clone()))?;
        let db_path = char_p::Ref::try_from(db_path.as_c_str())?;

        let host = std::ffi::CString::new(config.host.clone())?;
        let host = char_p::Ref::try_from(host.as_c_str())?;

        let encoded_ufvk = std::ffi::CString::new(config.encoded_ufvk.clone())?;
        let encoded_ufvk = char_p::Ref::try_from(encoded_ufvk.as_c_str())?;

        let recipient_address = std::ffi::CString::new(config.receiver_address.clone())?;
        let recipient_address = char_p::Ref::try_from(recipient_address.as_c_str())?;

        let amount_zatoshis = 2;

        let memo = safer_ffi::bytes::Bytes::from_slice(b"some message");

        fs::create_dir_all(&format!("{}/{}", TEST_DIR, config.fsblockdb_root.clone()))?;
        let fsblockdb_root =
            std::ffi::CString::new(format!("{}/{}", TEST_DIR, config.fsblockdb_root.clone()))?;
        let fsblockdb_root = char_p::Ref::try_from(fsblockdb_root.as_c_str())?;

        let network = light_client::handlers::Network::TestNetwork;

        let res = light_client::init_wallet_db(db_path, network);
        assert_eq!(res, 0);

        let res = light_client::init_blockmeta_db(fsblockdb_root);
        assert_eq!(res, 0);

        let account_name = std::ffi::CString::new("alice".to_string())?;
        let account_name = char_p::Ref::try_from(account_name.as_c_str())?;
        let res = light_client::import_account_ufvk(
            db_path,
            network,
            host,
            config.port,
            account_name,
            encoded_ufvk,
            config.birthday_height,
        );
        // assert_eq!(res, 0);
        if res != 0 {
            warn!("Account ufvk already imported");
        }

        let res = light_client::run_sync(host, config.port, fsblockdb_root, network, db_path);
        assert_eq!(res, 0);

        let mut serialized_pczt = safer_ffi::Vec::EMPTY;
        let res = light_client::create_orchard_transaction(
            network,
            db_path,
            encoded_ufvk,
            amount_zatoshis,
            recipient_address,
            memo,
            &mut serialized_pczt,
        );
        assert_eq!(res, 0);

        Ok(serialized_pczt)
    }
}
