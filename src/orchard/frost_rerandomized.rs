use core::slice;
use frost_core::{
    Field, Signature,
    frost::{
        keys::{SigningShare, VerifiableSecretSharingCommitment, VerifyingShare},
        round1::NonceCommitment,
    },
};
use frost_rerandomized::frost_core::VerifyingKey;
use rand::thread_rng;
use reddsa::frost::redpallas::{
    Identifier, PallasBlake2b512, SigningPackage,
    keys::{self, IdentifierList},
    round1, round2,
};
use reddsa::frost::redpallas::{PallasGroup, PallasScalarField};
use safer_ffi::{prelude::*, slice::slice_raw};
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_int;

use crate::errors::ExecutionError;

// type OrchardSignature = reddsa::Signature<reddsa::orchard::Binding>;
// type OrchardSigningKey = reddsa::SigningKey<reddsa::orchard::Binding>;
type OrchardVerificationKey = reddsa::VerificationKey<reddsa::orchard::Binding>;
type OrchardSigningPackage = reddsa::frost::redpallas::SigningPackage;
type OrchardRandomizedParams = frost_rerandomized::RandomizedParams<PallasBlake2b512>;
type Result<T> = std::result::Result<T, ExecutionError>;

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct SecretShare {
    identifier: [u8; 32],
    secret: [u8; 32],
    commitment: safer_ffi::Vec<[u8; 32]>,
}

impl From<keys::SecretShare> for SecretShare {
    fn from(share: keys::SecretShare) -> SecretShare {
        let identifier: [u8; 32] = share.identifier().serialize();
        let secret = share.secret().serialize();
        let commitment = share.commitment().serialize().into();

        SecretShare {
            identifier,
            secret,
            commitment,
        }
    }
}

impl TryFrom<&SecretShare> for keys::SecretShare {
    type Error = ExecutionError;

    fn try_from(share: &SecretShare) -> Result<keys::SecretShare> {
        let identifier = Identifier::deserialize(&share.identifier)?;
        let value = SigningShare::deserialize(share.secret)?;
        let commitment = VerifiableSecretSharingCommitment::deserialize(share.commitment.to_vec())?;

        Ok(keys::SecretShare::new(identifier, value, commitment))
    }
}

impl SecretShare {
    pub fn randomized_commit(&self) -> Result<(SigningNonces, SigningCommitments)> {
        let secret_share = keys::SecretShare::try_from(self)?;
        let key_package = keys::KeyPackage::try_from(secret_share)?;

        let (nonce, commitment) = round1::commit(
            // participant_identifier,
            key_package.secret_share(),
            &mut thread_rng(),
        );

        Ok((
            SigningNonces::from(nonce),
            SigningCommitments::from(commitment),
        ))
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct SigningCommitments {
    hiding: [u8; 32],
    binding: [u8; 32],
}

impl From<round1::SigningCommitments> for SigningCommitments {
    fn from(commitment: round1::SigningCommitments) -> SigningCommitments {
        SigningCommitments {
            hiding: commitment.hiding().serialize(),
            binding: commitment.binding().serialize(),
        }
    }
}

impl TryFrom<&SigningCommitments> for round1::SigningCommitments {
    type Error = ExecutionError;

    fn try_from(commitment: &SigningCommitments) -> Result<round1::SigningCommitments> {
        Ok(round1::SigningCommitments::new(
            NonceCommitment::deserialize(commitment.hiding)?,
            NonceCommitment::deserialize(commitment.binding)?,
        ))
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct SigningCommitmentsEntry {
    identifier: [u8; 32],           // Serialized Identifier
    commitment: SigningCommitments, // Your commitment struct
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct SigningNonces {
    hiding: [u8; 32],
    binding: [u8; 32],
}

impl From<round1::SigningNonces> for SigningNonces {
    fn from(nonce: round1::SigningNonces) -> SigningNonces {
        SigningNonces {
            hiding: nonce.hiding().serialize(),
            binding: nonce.binding().serialize(),
        }
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct PublicKeyPackage {
    /// Sequence of (member index,  public key) pairs.
    signer_pubkeys: safer_ffi::Vec<[[u8; 32]; 2]>,
    /// Group public key.
    group_public: [u8; 32],
}

impl From<keys::PublicKeyPackage> for PublicKeyPackage {
    fn from(package: keys::PublicKeyPackage) -> PublicKeyPackage {
        let group_public = package.group_public().serialize();

        let mut pubkeys_list = Vec::new();
        for (i, pubkey) in package.signer_pubkeys() {
            pubkeys_list.push([i.serialize(), pubkey.serialize()]);
        }

        PublicKeyPackage {
            signer_pubkeys: pubkeys_list.into(),
            group_public,
        }
    }
}

impl TryFrom<&PublicKeyPackage> for keys::PublicKeyPackage {
    type Error = ExecutionError;

    fn try_from(package: &PublicKeyPackage) -> Result<keys::PublicKeyPackage> {
        let group_public = VerifyingKey::deserialize(package.group_public)?;

        let pubkeys_raw_list = package.signer_pubkeys.to_vec();
        let mut signer_pubkeys = HashMap::new();
        for [i_bytes, key_bytes] in pubkeys_raw_list {
            signer_pubkeys.insert(
                Identifier::deserialize(&i_bytes)?,
                VerifyingShare::deserialize(key_bytes)?,
            );
        }

        println!("wtf");

        Ok(keys::PublicKeyPackage::new(signer_pubkeys, group_public))
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
/// Wrapper for orchard signing key
pub struct TrustedShares {
    shares: safer_ffi::Vec<SecretShare>,
    public_key_package: PublicKeyPackage,
}

#[ffi_export]
pub fn frost_randomized_keygen_dealer(
    max_signers: u16,
    min_signers: u16,
    trusted_share: &mut TrustedShares,
) -> c_int {
    let mut rng = thread_rng();
    let (shares, pubkeys) = match keys::generate_with_dealer(
        max_signers,
        min_signers,
        IdentifierList::Default,
        &mut rng,
    ) {
        Ok((shares, pubkeys)) => (shares, pubkeys),
        Err(err) => return c_int::from(ExecutionError::from(err)),
    };

    let mut shares_list = Vec::new();
    for (_, share) in shares {
        shares_list.push(SecretShare::from(share));
    }

    *trusted_share = TrustedShares {
        shares: shares_list.into(),
        public_key_package: PublicKeyPackage::from(pubkeys),
    };

    0
}

#[ffi_export]
/// Round1: Generate one nonce and one `SigningCommitments`` instance for each participant.
pub fn frost_randomized_commit(
    secret_share: &SecretShare,
    signing_nonces: &mut SigningNonces,
    signing_commitments: &mut SigningCommitments,
) -> c_int {
    match secret_share.randomized_commit() {
        Ok((nonces, commitments)) => {
            *signing_nonces = nonces;
            *signing_commitments = commitments;
            0
        }
        Err(err) => c_int::from(err),
    }
}

#[ffi_export]
/// Round1: Generate signing package for the given message and user secret share.
pub fn frost_randomized_signing_package_new(
    signing_commitments: safer_ffi::Vec<SigningCommitmentsEntry>,
    message: slice_raw<u8>,
) -> c_int {
    match internal_frost_randomized_signing_package_new(signing_commitments, message) {
        Ok(signature_package) => 0,
        Err(err) => c_int::from(err),
    }
}

fn internal_frost_randomized_signing_package_new(
    signing_commitments: safer_ffi::Vec<SigningCommitmentsEntry>,
    message: slice_raw<u8>,
) -> Result<OrchardSigningPackage> {
    let mut comms = BTreeMap::new();
    for entry in signing_commitments.as_ref().iter() {
        let identifier = Identifier::deserialize(&entry.identifier)?;
        let commitment = round1::SigningCommitments::try_from(&entry.commitment)?;
        comms.insert(identifier, commitment);
    }

    let package = OrchardSigningPackage::new(comms, &unsafe { message.as_ref() });

    todo!()
    // Ok(())
}

#[ffi_export]
/// Generate new `randomizer`.
pub fn frost_randomized_new_randomizer() -> [u8; 32] {
    PallasScalarField::random(&mut thread_rng()).into()
}

#[ffi_export]
/// Round2: Generate user's signature share.
pub fn frost_randomized_sign_package() -> c_int {
    todo!()
}

#[ffi_export]
/// Round2: Generate user's signature share.
pub fn frost_randomized_aggregate(
    signing_package: bool,
    signature_shares_map: bool,
    pubkeys: bool,
    randomizer_params: bool,
) -> c_int {
    todo!()
}

#[ffi_export]
/// Round2: Generate user's signature share.
pub fn frost_randomized_verify(
    message: slice_raw<u8>,
    group_signature: [u8; 64],
    public_key_package: &PublicKeyPackage,
    randomizer: [u8; 32],
) -> c_int {
    match internal_frost_randomized_verify(message, group_signature, public_key_package, randomizer)
    {
        Ok(_) => 0,
        Err(err) => c_int::from(err),
    }
}

fn internal_frost_randomized_verify(
    message: slice_raw<u8>,
    group_signature: [u8; 64],
    public_key_package: &PublicKeyPackage,
    randomizer: [u8; 32],
) -> Result<()> {
    let randomizer_params = OrchardRandomizedParams::from_randomizer(
        &keys::PublicKeyPackage::try_from(public_key_package)?,
        PallasScalarField::deserialize(&randomizer)?,
    );

    let signature = Signature::deserialize(group_signature)?;

    if randomizer_params
        .randomized_group_public_key()
        .verify(&unsafe { message.as_ref() }, &signature)
        .is_err()
    {
        return Err(ExecutionError::Verification);
    }

    Ok(())
}
