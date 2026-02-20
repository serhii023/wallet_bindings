use std::error::Error;

use eyre::eyre;
use pczt::{Pczt, roles::low_level_signer::Signer};
use rand::{Rng, thread_rng};
use rand_core::{CryptoRng, RngCore};

use halo2_proofs::pasta::group::ff::PrimeField;
use orchard::{
    primitives::redpallas::{self, SpendAuth},
    value::NoteValue,
};
use reddsa::frost::redpallas::keys::PublicKeyPackage;
use safer_ffi::derive_ReprC;
use zcash_primitives::transaction::{TxVersion, sighash_v5::v5_signature_hash};
use zcash_primitives::transaction::{sighash::SignableInput, txid::TxIdDigester};

use orchard::keys::{FullViewingKey, SpendValidatingKey, SpendingKey};
use zcash_keys::keys::UnifiedFullViewingKey;

/// The enumeration of known Zcash networks.
#[derive_ReprC]
#[repr(C)]
#[derive(Clone, Debug)]
pub struct IndexedAlpha {
    pub idx: usize,
    pub alpha: safer_ffi::Vec<u8>,
}

impl IndexedAlpha {
    pub fn new(idx: usize, alpha: Vec<u8>) -> Self {
        Self {
            idx,
            alpha: alpha.into(),
        }
    }
}

/// New ufvk from spending key `sk` and public key package `pkp`
pub fn ufvk_from_sk_pkp(sk: [u8; 32], pkp: &[u8]) -> eyre::Result<UnifiedFullViewingKey> {
    let vk_bytes = PublicKeyPackage::deserialize(pkp)?
        .verifying_key()
        .serialize()?;
    let ak = SpendValidatingKey::from_bytes(&vk_bytes).ok_or(eyre!("Invalid ak"))?;

    let sk = SpendingKey::from_bytes(sk)
        .into_option()
        .ok_or(eyre!("invalid spend authorizing key"))?;

    let fvk = FullViewingKey::from_sk_ak(&sk, ak.clone());
    let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk)?;

    Ok(ufvk)
}

pub(crate) fn random_spending_key(rng: &mut impl RngCore) -> [u8; 32] {
    let sk = loop {
        let random_bytes = rng.r#gen::<[u8; 32]>();
        let sk = SpendingKey::from_bytes(random_bytes).into_option();
        if let Some(sk) = sk {
            break *sk.to_bytes();
        }
    };

    sk
}

/// Return the sighash and alphas (randomizers) from the PCZT.
pub fn read_pczt_signining_inputs(pczt_bytes: &[u8]) -> eyre::Result<(Vec<u8>, Vec<IndexedAlpha>)> {
    let pczt = Pczt::parse(pczt_bytes).map_err(|err| eyre!("Failed to parse Pczt: {err:?}"))?;

    let sighash = match pczt.clone().into_effects() {
        None => Err(eyre!(
            "Not enough information to build the transaction's effects"
        ))?,
        Some(tx_data) => {
            let txid_parts = tx_data.digest(TxIdDigester);
            if matches!(tx_data.version(), TxVersion::V5)
                && (tx_data.sapling_bundle().is_some() || tx_data.orchard_bundle().is_some())
            {
                v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
            } else {
                Err(eyre!(
                    "Only version 5 transactions with shielded components are supported"
                ))?
            }
        }
    }
    .as_bytes()
    .to_vec();

    let signer = Signer::new(pczt.clone());
    let mut alphas = vec![];
    signer
        .sign_orchard_with(|_pczt, bundle, _| {
            alphas = bundle
                .actions()
                .iter()
                .enumerate()
                // TODO: remove unwrap
                .filter_map(|(idx, a)| {
                    // TODO: improve dummy detection (check rk instead)
                    if a.spend().value().unwrap() != NoteValue::default() {
                        Some(IndexedAlpha::new(
                            idx,
                            a.spend().alpha().unwrap().to_repr().to_vec(),
                        ))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            Ok::<_, orchard::pczt::ParseError>(())
        })
        .map_err(|err| eyre!("{:?}", err))?;

    Ok((sighash, alphas))
}

pub fn write_pczt_signing_outputs(
    pczt_bytes: &[u8],
    sighash: &[u8],
    signatures: &[Vec<u8>],
) -> eyre::Result<Vec<u8>> {
    let pczt = Pczt::parse(pczt_bytes).map_err(|err| eyre!("Failed to parse Pczt: {err:?}"))?;

    let signatures = signatures
        .iter()
        .map(|sig_bytes| {
            let sig_array: [u8; 64] = sig_bytes
                .clone()
                .try_into()
                .map_err(|_| eyre!("Signature must be exactly 64 bytes long"))?;
            Ok(redpallas::Signature::<SpendAuth>::from(sig_array))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()
        .map_err(|err| eyre!("{:?}", err))?;

    let signer = Signer::new(pczt.clone());
    let signer = signer
        .sign_orchard_with(|_pczt, bundle, _| {
            bundle
                .actions_mut()
                .iter_mut()
                // TODO: remove unwrap
                .filter(|a| {
                    // TODO: improve dummy detection (check rk instead)
                    a.spend().value().unwrap() != NoteValue::default()
                })
                .zip(signatures.iter())
                .for_each(|(action, signature)| {
                    action
                        .apply_signature(sighash.try_into().unwrap(), signature.clone())
                        .unwrap();
                });
            Ok::<_, orchard::pczt::ParseError>(())
        })
        .map_err(|e| eyre!("Error signing: {:?}", e))?;
    let pczt = signer.finish();

    Ok(pczt.serialize())
}
