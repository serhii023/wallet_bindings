use frost_core::keys::dkg::round1::Package;
use rand::thread_rng;
use reddsa::frost::redpallas::keys::dkg;
use safer_ffi::{derive_ReprC, ffi_export};
use std::{collections::BTreeMap, ffi::c_int};

use crate::{
    errors::ExecutionError,
    orchard::frost_rerandomized::{IdentifiedData, KeyPackage},
};

type Result<T> = std::result::Result<T, ExecutionError>;
type Part1SecretPackage = dkg::round1::SecretPackage;
type Part1Package = dkg::round1::Package;
type Part2SecretPackage = dkg::round2::SecretPackage;
type Part2Package = dkg::round2::Package;
type Part3SecretPackage = reddsa::frost::redpallas::keys::KeyPackage;
type Part3Package = reddsa::frost::redpallas::keys::PublicKeyPackage;

#[ffi_export]
pub fn frost_dkg_part1(
    participant_identifier: u16,
    max_signers: u16,
    min_signers: u16,
    // Returns
    round1_secret_package: &mut safer_ffi::Vec<u8>,
    round1_package: &mut IdentifiedData<safer_ffi::Vec<u8>>,
) -> c_int {
    match inner_frost_dkg_part1(participant_identifier, max_signers, min_signers) {
        Ok((secret_package, package)) => {
            *round1_secret_package = secret_package.into();
            *round1_package = package;
            0
        }
        Err(err) => {
            eprintln!("{}", err.to_string());
            c_int::from(err)
        }
    }
}

fn inner_frost_dkg_part1(
    participant_identifier: u16,
    max_signers: u16,
    min_signers: u16,
) -> Result<(Vec<u8>, IdentifiedData<safer_ffi::Vec<u8>>)> {
    let mut rng = thread_rng();
    let id = participant_identifier.try_into()?;

    let (round1_secret_package, round1_package) =
        dkg::part1(id, max_signers, min_signers, &mut rng)?;

    Ok((
        round1_secret_package.serialize()?,
        IdentifiedData::from((&id, round1_package.serialize()?.into())),
    ))
}

#[ffi_export]
pub fn frost_dkg_part2(
    round1_secret_package: &safer_ffi::Vec<u8>,
    round1_packages: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    // Returns
    round2_secret_package: &mut safer_ffi::Vec<u8>,
    round2_packages: &mut safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
) -> c_int {
    match inner_frost_dkg_part2(round1_secret_package, round1_packages) {
        Ok((secret_package, packages)) => {
            *round2_secret_package = secret_package.into();
            *round2_packages = packages.into();
            0
        }
        Err(err) => {
            eprintln!("{}", err.to_string());
            c_int::from(err)
        }
    }
}

fn inner_frost_dkg_part2(
    round1_secret_package: &safer_ffi::Vec<u8>,
    round1_packages: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
) -> Result<(Vec<u8>, Vec<IdentifiedData<safer_ffi::Vec<u8>>>)> {
    let mut deserialized_packages = BTreeMap::new();
    for package in round1_packages.to_vec().into_iter() {
        deserialized_packages.insert(package.id()?, Part1Package::deserialize(package.data())?);
    }

    let (round2_secret_package, round2_packages) = dkg::part2(
        Part1SecretPackage::deserialize(&round1_secret_package)?,
        &deserialized_packages,
    )?;

    let mut serialized_packages = Vec::with_capacity(round2_packages.len());
    for (id, package) in round2_packages {
        serialized_packages.push(IdentifiedData::from((&id, package.serialize()?.into())));
    }

    Ok((round2_secret_package.serialize()?, serialized_packages))
}

#[ffi_export]
pub fn frost_dkg_part3(
    round2_secret_package: &safer_ffi::Vec<u8>,
    round1_packages: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    round2_packages: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    // Return
    key_package: &mut IdentifiedData<KeyPackage>,
    pubkey_package: &mut safer_ffi::Vec<u8>,
) -> c_int {
    match inner_frost_dkg_part3(round2_secret_package, round1_packages, round2_packages) {
        Ok((key, pubkey)) => {
            *key_package = key.into();
            *pubkey_package = pubkey.into();
            0
        }
        Err(err) => {
            eprintln!("{}", err.to_string());
            c_int::from(err)
        }
    }
}

fn inner_frost_dkg_part3(
    round2_secret_package: &safer_ffi::Vec<u8>,
    round1_packages: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
    round2_packages: &safer_ffi::Vec<IdentifiedData<safer_ffi::Vec<u8>>>,
) -> Result<(IdentifiedData<KeyPackage>, Vec<u8>)> {
    let mut round1_deserialized_packages = BTreeMap::new();
    for package in round1_packages.as_ref().iter() {
        round1_deserialized_packages
            .insert(package.id()?, Part1Package::deserialize(package.data())?);
    }

    let mut round2_deserialized_packages = BTreeMap::new();
    for package in round2_packages.as_ref().iter() {
        round2_deserialized_packages
            .insert(package.id()?, Part2Package::deserialize(package.data())?);
    }

    let part2_secret_package = Part2SecretPackage::deserialize(round2_secret_package)?;
    let id = part2_secret_package.identifier();

    let (key_package, pubkey_package) = dkg::part3(
        &part2_secret_package,
        &round1_deserialized_packages,
        &round2_deserialized_packages,
    )?;

    Ok((
        IdentifiedData::new(id, KeyPackage::try_from(&key_package)?),
        pubkey_package.serialize()?,
    ))
}
