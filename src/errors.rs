use frost_core::Ciphersuite;
use reddsa::frost::redpallas::PallasBlake2b512;
use std::ffi::c_int;
use thiserror::Error;

#[repr(i8)]
#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Failed serialization: {0}")]
    Serialization(String),
    #[error("Verification failed")]
    Verification,
    #[error("reddsa error: {0}")]
    Reddsa(#[from] reddsa::Error),
    #[error("frost_core error: {0}")]
    FrostCore(#[from] frost_core::Error<PallasBlake2b512>),
    #[error("frost_core field error: {0}")]
    FrostCoreFieldError(#[from] frost_core::FieldError),
}

impl From<ExecutionError> for c_int {
    fn from(err: ExecutionError) -> c_int {
        match err {
            ExecutionError::Serialization(_) => -1,
            ExecutionError::Verification => -2,
            ExecutionError::Reddsa(_) => -3,
            ExecutionError::FrostCore(_) => -4,
            ExecutionError::FrostCoreFieldError(_) => -4,
        }
    }
}
