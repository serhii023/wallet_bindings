use safer_ffi::{self};
use ::safer_ffi::prelude::*;
use rand::thread_rng;
use std::ffi::c_int;
use safer_ffi::slice::slice_raw;
// use reddsa::{Signature, SigningKey, VerificationKey, orchard};
// use serde::{Serialize};

use crate::errors::ExecutionError;

type OrchardSignature = reddsa::Signature<reddsa::orchard::Binding>;
type OrchardSigningKey = reddsa::SigningKey<reddsa::orchard::Binding>;
type OrchardVerificationKey = reddsa::VerificationKey<reddsa::orchard::Binding>;
type Result<T> = std::result::Result<T, ExecutionError>;

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
/// Wrapper for orchard signing key
pub struct SigningKey{
    bytes: [u8; 32]
}

impl SigningKey {
    pub fn key(&self) -> Result<OrchardSigningKey> {
        Ok(OrchardSigningKey::try_from(self.bytes)?)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let sig = self.key()?.sign(thread_rng(), &msg);

        Ok(Signature { bytes: sig.into() })
    }

    pub fn verification_key(&self) -> Result<VerificationKey> {
        let sk = self.key()?;
        let pk = reddsa::VerificationKey::<reddsa::orchard::Binding>::from(&sk);
    
        Ok(VerificationKey { bytes: pk.into() })
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct VerificationKey{
    bytes: [u8; 32]
}

impl VerificationKey {
    pub fn key(&self) -> Result<OrchardVerificationKey> {
        Ok(OrchardVerificationKey::try_from(self.bytes)?)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        Ok(self.key()?.verify(
            msg,
            &OrchardSignature::from(signature.bytes)
        )?)
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Signature{
    bytes: [u8; 64]
}

#[ffi_export]
pub fn new_signing_key() -> SigningKey {
    let sk = reddsa::SigningKey::<reddsa::orchard::Binding>::new(thread_rng());

    SigningKey { bytes: sk.into() }
}

#[ffi_export]
pub fn verification_key(sk: &SigningKey, vk: *mut VerificationKey) -> c_int {
    match sk.verification_key() {
        Ok(verification_key) => {
            unsafe { *vk = verification_key }
            0
        },
        Err(err) => c_int::from(err)
    }
}

#[ffi_export]
pub fn sign_message(sk: SigningKey, msg: slice_raw<u8>, sig: &mut Signature) -> c_int {
    let msg_slice = unsafe { msg.as_ref() }.as_slice();

    match sk.sign(msg_slice) {
        Ok(signature) => {
            // unsafe { *sig = signature; }
            *sig = signature;
            return 0
        },
        Err(err) => {
            c_int::from(err)
        }
    }
}

#[ffi_export]
pub fn verify(pk: VerificationKey, msg: slice_raw<u8>, signature: &Signature) -> c_int {
    let msg_slice = unsafe { msg.as_ref() }.as_slice();

    match pk.verify(msg_slice, &signature) {
        Ok(_) => 0,
        Err(err) => c_int::from(err)
    }
}

#[test]
fn example() -> Result<()> {
    let msg = b"Hello!";

    // Generate a secret key and sign the message
    let sk = OrchardSigningKey::new(thread_rng());
    println!("sk: {:?}", sk);
    let sk_bytes: [u8; 32] = sk.into();

    let sk = OrchardSigningKey::try_from(sk_bytes).unwrap();
    println!("sk_bytes: {:?}", sk_bytes);
    let sig = sk.sign(thread_rng(), msg);

    // Types can be converted to raw byte arrays using From/Into
    let sig_bytes: [u8; 64] = sig.into();
    let pk_bytes: [u8; 32] = reddsa::VerificationKey::from(&sk).into();

    // Deserialize and verify the signature.
    let sig: reddsa::Signature<reddsa::orchard::Binding> = sig_bytes.into();
    assert!(
    reddsa::VerificationKey::try_from(pk_bytes)
        .and_then(|pk| pk.verify(msg, &sig))
        .is_ok()
    );

    Ok(())
}