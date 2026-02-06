use std::ffi::c_int;
use thiserror::Error;

#[repr(i8)]
#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Failed to deserialize data")]
    Deserialization
}

impl From<reddsa::Error> for ExecutionError {
    fn from(_value: reddsa::Error) -> Self {
        Self::Deserialization
    }
}

impl From<ExecutionError> for c_int {
    fn from(err: ExecutionError) -> c_int {
        match err {
            ExecutionError::Deserialization => -1
        }
    }
}