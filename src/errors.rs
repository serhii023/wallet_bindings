use frost_core::Ciphersuite;
use std::ffi::c_int;
use thiserror::Error;

#[repr(i8)]
#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Failed to deserialize data")]
    Deserialization,
    #[error("Verification failed")]
    Verification,
}

impl From<reddsa::Error> for ExecutionError {
    fn from(_value: reddsa::Error) -> Self {
        Self::Deserialization
    }
}

impl<C: Ciphersuite> From<frost_core::Error<C>> for ExecutionError {
    fn from(_value: frost_core::Error<C>) -> Self {
        Self::Deserialization
    }
}

impl From<frost_core::FieldError> for ExecutionError {
    fn from(_value: frost_core::FieldError) -> Self {
        Self::Deserialization
    }
}

impl From<ExecutionError> for c_int {
    fn from(err: ExecutionError) -> c_int {
        match err {
            ExecutionError::Deserialization => -1,
            ExecutionError::Verification => -2,
        }
    }
}
