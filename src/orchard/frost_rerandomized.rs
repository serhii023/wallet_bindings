// use std::collections::BTreeMap;

// use reddsa::frost::redpallas::{PallasBlake2b512, round1, round2, keys, SigningPackage, PallasGroup, PallasScalarField, Identifier};
// use pasta_curves::pallas;

// #[unsafe(no_mangle)]
// pub extern "C" fn sign(
//     signing_commitments: BTreeMap<Identifier, round1::SigningCommitments>,
//     message: &[u8],
//     signer_nonces: &round1::SigningNonces,
//     key_package: &keys::KeyPackage,
//     randomizer: &pallas::Point,
// ) -> Result<round2::SignatureShare> {    
//     let signing_package = &SigningPackage::new(signing_commitments, message);

//     let share = round2::sign(
//         signing_package,
//         signer_nonces,
//         key_package,
//         randomizer,
//     ).map_err(|err| anyhow!("failed to sign the package: {}", err.to_string()))?;

//     Ok(share)
// }

