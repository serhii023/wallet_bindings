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
    use safer_ffi::{char_p::char_p_ref, prelude::*};
    use std::{
        env,
        ffi::CString,
        fs,
        path::{Path, PathBuf},
    };
    use tracing::info;

    use crate::{LogLevel, init_rust_logging, light_client};

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

    #[test]
    fn test_lightwallet_workflow() -> eyre::Result<()> {
        dotenvy::dotenv().ok();
        init_rust_logging(LogLevel::Debug);

        let config = TestConfig::from_env()?;
        info!(config = ?config);

        let test_dir = TestDir::new(TEST_DIR);

        let db_path = std::ffi::CString::new(format!("{}/{}", TEST_DIR, config.db_path.clone()))?;
        let db_path = char_p::Ref::try_from(db_path.as_c_str())?;

        let host = std::ffi::CString::new(config.host.clone())?;
        let host = char_p::Ref::try_from(host.as_c_str())?;

        fs::create_dir_all(&format!("{}/{}", TEST_DIR, config.fsblockdb_root.clone()))?;
        let fsblockdb_root =
            std::ffi::CString::new(format!("{}/{}", TEST_DIR, config.fsblockdb_root.clone()))?;
        let fsblockdb_root = char_p::Ref::try_from(fsblockdb_root.as_c_str())?;

        let network = light_client::handlers::Network::TestNetwork;

        let res = light_client::init_wallet_db(db_path, network);
        assert_eq!(res, 0);

        let res = light_client::init_blockmeta_db(fsblockdb_root);
        assert_eq!(res, 0);

        let res = light_client::run_sync(host, config.port, fsblockdb_root, network, db_path);
        assert_eq!(res, 0);

        Ok(())
    }
}
