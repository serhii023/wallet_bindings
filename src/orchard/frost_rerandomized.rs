use core::slice;
use frost_core::{
    Field, Scalar, Signature, SigningPackage,
    keys::{SigningShare, VerifiableSecretSharingCommitment, VerifyingShare},
    round1::NonceCommitment,
    serialization::SerializableScalar,
};
use frost_rerandomized::{RandomizedParams, Randomizer, frost_core::VerifyingKey};
use futures::io::Empty;
use rand::thread_rng;
use reddsa::frost::redpallas::{
    Identifier, PallasBlake2b512,
    keys::{self, IdentifierList},
    round1, round2,
};
use reddsa::frost::redpallas::{PallasGroup, PallasScalarField};
use safer_ffi::{prelude::*, slice::slice_raw};
use serde::{Deserialize, Serialize};
use std::ffi::c_int;
use std::{
    clone,
    collections::{BTreeMap, HashMap},
};
use tracing::error;

use crate::errors::ExecutionError;

// type OrchardSignature = reddsa::Signature<reddsa::orchard::Binding>;
// type OrchardSigningKey = reddsa::SigningKey<reddsa::orchard::Binding>;
// type OrchardVerificationKey = reddsa::VerificationKey<reddsa::orchard::Binding>;
type OrchardSigningPackage = reddsa::frost::redpallas::SigningPackage;
type OrchardRandomizedParams = frost_rerandomized::RandomizedParams<PallasBlake2b512>;
type OrchardPublicKeyPackage = keys::PublicKeyPackage;
type Result<T> = std::result::Result<T, ExecutionError>;

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct SecretShare {
    bytes: safer_ffi::Vec<u8>,
}

impl TryFrom<&keys::SecretShare> for SecretShare {
    type Error = ExecutionError;

    fn try_from(share: &keys::SecretShare) -> Result<SecretShare> {
        Ok(SecretShare {
            bytes: share.serialize()?.into(),
        })
    }
}

impl TryFrom<&SecretShare> for keys::SecretShare {
    type Error = ExecutionError;

    fn try_from(share: &SecretShare) -> Result<keys::SecretShare> {
        Ok(keys::SecretShare::deserialize(&share.bytes)?)
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KeyPackage {
    bytes: safer_ffi::Vec<u8>,
}

impl TryFrom<&keys::KeyPackage> for KeyPackage {
    type Error = ExecutionError;

    fn try_from(share: &keys::KeyPackage) -> Result<KeyPackage> {
        Ok(KeyPackage {
            bytes: share.serialize()?.into(),
        })
    }
}

impl TryFrom<&KeyPackage> for keys::KeyPackage {
    type Error = ExecutionError;

    fn try_from(share: &KeyPackage) -> Result<keys::KeyPackage> {
        Ok(keys::KeyPackage::deserialize(&share.bytes)?)
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
/// Wrapper for orchard signing key
pub struct TrustedShares {
    pub key_packages: safer_ffi::Vec<IdentifiedData<KeyPackage>>,
    pub public_key_package: safer_ffi::Vec<u8>,
}

impl Default for TrustedShares {
    fn default() -> Self {
        Self {
            key_packages: safer_ffi::Vec::EMPTY,
            public_key_package: safer_ffi::Vec::EMPTY,
        }
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IdentifiedData<T> {
    pub identifier: [u8; 32],
    pub data: T,
}

impl<T> IdentifiedData<T> {
    pub fn new(id: &Identifier, data: T) -> Self {
        Self {
            identifier: id.to_scalar().into(),
            data,
        }
    }

    pub fn into_parts(&self) -> Result<(Identifier, T)>
    where
        T: Clone,
    {
        let id: frost_core::Identifier<PallasBlake2b512> =
            Identifier::deserialize(&self.identifier)?;

        Ok((id, self.data.clone()))
    }

    pub fn id(&self) -> Result<Identifier> {
        Ok(Identifier::deserialize(&self.identifier)?)
    }

    pub fn data(&self) -> &T {
        &self.data
    }
}

impl<T> From<(&Identifier, T)> for IdentifiedData<T> {
    fn from((id, data): (&Identifier, T)) -> Self {
        Self::new(id, data)
    }
}

impl<T: Default> Default for IdentifiedData<T> {
    fn default() -> Self {
        Self {
            identifier: Default::default(),
            data: Default::default(),
        }
    }
}

#[ffi_export]
pub fn identified_data_id_as_u16(data: &IdentifiedData<safer_ffi::Vec<u8>>) -> u16 {
    u16::from_le_bytes([data.identifier[0], data.identifier[1]])
}

#[ffi_export]
pub fn identified_data_new_u16(
    id: u16,
    data: &safer_ffi::Vec<u8>,
    identified_data: &mut IdentifiedData<safer_ffi::Vec<u8>>,
) -> c_int {
    match Identifier::try_from(id) {
        Ok(identifier) => {
            *identified_data = IdentifiedData::new(&identifier, data.clone());
            0
        }
        Err(err) => {
            eprintln!("{}", err.to_string());
            c_int::from(ExecutionError::from(err))
        }
    }
}

impl<T: Clone> TryFrom<&IdentifiedData<T>> for (Identifier, T) {
    type Error = ExecutionError;

    fn try_from(value: &IdentifiedData<T>) -> Result<Self> {
        let id = Identifier::deserialize(&value.identifier)?;

        Ok((id, value.data.clone()))
    }
}

#[ffi_export]
pub fn frost_randomized_keygen_dealer(
    max_signers: u16,
    min_signers: u16,
    trusted_share: &mut TrustedShares,
) -> c_int {
    match inner_frost_randomized_keygen_dealer(max_signers, min_signers) {
        Ok(shares) => {
            *trusted_share = shares;
            0
        }
        Err(err) => c_int::from(err),
    }
}

fn inner_frost_randomized_keygen_dealer(
    max_signers: u16,
    min_signers: u16,
) -> Result<TrustedShares> {
    let mut rng = thread_rng();
    let (shares, pubkey) =
        keys::generate_with_dealer(max_signers, min_signers, IdentifierList::Default, &mut rng)?;

    let mut shares_list = Vec::new();
    for (_, share) in shares {
        let identifier = share.identifier().to_scalar().into();
        let package = KeyPackage::try_from(&keys::KeyPackage::try_from(share)?)?;
        shares_list.push(IdentifiedData {
            identifier,
            data: package,
        });
    }

    Ok(TrustedShares {
        key_packages: shares_list.into(),
        public_key_package: pubkey.serialize()?.into(),
    })
}

#[ffi_export]
/// Round1: Generate one nonce and one `SigningCommitments`` instance for each participant.
pub fn frost_randomized_commit(
    identifier: u16,
    key_package: &KeyPackage,
    signing_nonces: &mut safer_ffi::Vec<u8>,
    signing_commitments: &mut safer_ffi::Vec<u8>,
    identified_signing_commitments: &mut IdentifiedData<safer_ffi::Vec<u8>>,
) -> c_int {
    match inner_frost_randomized_commit(identifier, key_package) {
        Ok((nonces, commitments, identified_commitments)) => {
            *signing_nonces = nonces.into();
            *signing_commitments = commitments.into();
            *identified_signing_commitments = identified_commitments;
            0
        }
        Err(err) => c_int::from(err),
    }
}

fn inner_frost_randomized_commit(
    identifier: u16,
    key_package: &KeyPackage,
) -> Result<(Vec<u8>, Vec<u8>, IdentifiedData<safer_ffi::Vec<u8>>)> {
    // let secret_share = keys::SecretShare::deserialize(&secret_share.bytes)?;
    // let identifier: [u8; 32] = secret_share.identifier().clone().to_scalar().into();
    let identifier = Identifier::try_from(identifier)?;

    let key_package = keys::KeyPackage::try_from(key_package)?;
    let (nonce, commitment) = round1::commit(
        // participant_identifier,
        key_package.signing_share(),
        &mut thread_rng(),
    );

    let commitment_bytes = commitment.serialize()?;

    let identified_commitments = IdentifiedData::new(&identifier, commitment_bytes.clone().into());

    Ok((nonce.serialize()?, commitment_bytes, identified_commitments))
}

#[ffi_export]
/// Round1: Generate signing package for the given message and user secret share.
pub fn frost_randomized_signing_package_new(
    signing_commitments: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    // message: slice_raw<u8>,
    message: &safer_ffi::Vec<u8>,
    signature_package: &mut safer_ffi::Vec<u8>,
) -> c_int {
    match inner_frost_randomized_signing_package_new(signing_commitments, message) {
        Ok(sig_package) => {
            *signature_package = sig_package.into();
            0
        }
        Err(err) => c_int::from(err),
    }
}

fn inner_frost_randomized_signing_package_new(
    signing_commitments: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    message: &safer_ffi::Vec<u8>,
) -> Result<Vec<u8>> {
    let mut comms = BTreeMap::new();
    for entry in signing_commitments.as_ref().iter() {
        let (id, comm_bytes) = <(Identifier, safer_ffi::Vec<u8>)>::try_from(entry)?;
        let commitment = round1::SigningCommitments::deserialize(&comm_bytes)?;
        comms.insert(id, commitment);
    }

    let package = OrchardSigningPackage::new(comms, &message.to_vec());

    Ok(package.serialize()?)
}

#[ffi_export]
/// Generate new `randomizer`.
pub fn frost_randomized_new_randomizer() -> [u8; 32] {
    PallasScalarField::random(&mut thread_rng()).into()
}

#[ffi_export]
/// Round2: Generate user's signature share.
pub fn frost_randomized_sign_package(
    signing_package: &safer_ffi::Vec<u8>,
    nonces_to_use: &safer_ffi::Vec<u8>,
    key_package: &KeyPackage,
    randomizer: &[u8; 32],
    signature_share: &mut safer_ffi::Vec<u8>,
    identified_signature_share: &mut IdentifiedData<safer_ffi::Vec<u8>>,
) -> c_int {
    match internal_frost_randomized_sign_package(
        signing_package,
        nonces_to_use,
        key_package,
        randomizer,
    ) {
        Ok((share, identified_share)) => {
            *signature_share = share.into();
            *identified_signature_share = identified_share;
            0
        }
        Err(err) => {
            eprintln!("{}", err.to_string());
            c_int::from(err)
        }
    }
}

fn internal_frost_randomized_sign_package(
    signing_package: &safer_ffi::Vec<u8>,
    nonces_to_use: &safer_ffi::Vec<u8>,
    key_package: &KeyPackage,
    randomizer: &[u8; 32],
) -> Result<(Vec<u8>, IdentifiedData<safer_ffi::Vec<u8>>)> {
    let key_package = keys::KeyPackage::try_from(key_package)?;
    let id: [u8; 32] = key_package.identifier().to_scalar().into();
    let signature_share = round2::sign(
        &SigningPackage::deserialize(signing_package)?,
        &round1::SigningNonces::deserialize(nonces_to_use)?,
        &key_package,
        Randomizer::from_scalar(PallasScalarField::deserialize(randomizer)?),
    )?;

    let serialized_signature_share = signature_share.serialize();
    let identified_signature = IdentifiedData {
        identifier: id,
        data: serialized_signature_share.clone().into(),
    };

    Ok((serialized_signature_share, identified_signature))
}

#[ffi_export]
/// Round2: Generate user's signature share.
pub fn frost_randomized_aggregate(
    signing_package: &safer_ffi::Vec<u8>,
    signature_shares: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    pubkeys: &safer_ffi::Vec<u8>,
    randomizer: &[u8; 32],
    signature: &mut safer_ffi::Vec<u8>,
) -> c_int {
    match inner_frost_randomized_aggregate(signing_package, signature_shares, pubkeys, randomizer) {
        Ok(sig) => {
            *signature = sig.into();
            0
        }
        Err(err) => c_int::from(err),
    }
}

fn inner_frost_randomized_aggregate(
    signing_package: &safer_ffi::Vec<u8>,
    signature_shares: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    pubkeys: &safer_ffi::Vec<u8>,
    randomizer: &[u8; 32],
) -> Result<Vec<u8>> {
    let public_package = OrchardPublicKeyPackage::deserialize(&pubkeys)?;
    let randomized_params = RandomizedParams::from_randomizer(
        public_package.verifying_key(),
        Randomizer::from_scalar(PallasScalarField::deserialize(randomizer)?),
    );

    let mut shares = BTreeMap::new();
    for entry in signature_shares.iter() {
        let (id, share) = entry.into_parts()?;
        shares.insert(id, round2::SignatureShare::deserialize(&share)?);
    }

    let signature = frost_rerandomized::aggregate(
        &OrchardSigningPackage::deserialize(signing_package)?,
        &shares,
        &public_package,
        &randomized_params,
    )?;

    Ok(signature.serialize()?)
}

#[ffi_export]
/// Round2: Generate user's signature share.
pub fn frost_randomized_verify(
    message: &safer_ffi::Vec<u8>,
    group_signature: &safer_ffi::Vec<u8>,
    public_key_package: &safer_ffi::Vec<u8>,
    randomizer: &[u8; 32],
) -> c_int {
    match internal_frost_randomized_verify(message, group_signature, public_key_package, randomizer)
    {
        Ok(_) => 0,
        Err(err) => {
            error!(error = ?err);
            return c_int::from(err);
        }
    }
}

fn internal_frost_randomized_verify(
    message: &safer_ffi::Vec<u8>,
    group_signature: &safer_ffi::Vec<u8>,
    public_key_package: &safer_ffi::Vec<u8>,
    randomizer: &[u8; 32],
) -> Result<()> {
    let randomizer_params = OrchardRandomizedParams::from_randomizer(
        OrchardPublicKeyPackage::deserialize(&public_key_package)?.verifying_key(),
        Randomizer::from_scalar(PallasScalarField::deserialize(&randomizer)?),
    );

    let signature = Signature::deserialize(group_signature)?;

    if randomizer_params
        .randomized_verifying_key()
        .verify(&message.to_vec(), &signature)
        .is_err()
    {
        return Err(ExecutionError::Verification);
    }

    Ok(())
}
