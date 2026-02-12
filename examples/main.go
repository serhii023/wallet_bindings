package main

/*
#cgo LDFLAGS: -L../target/release -lwallet_bindings

#include "../include/rust_points.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"
import "fmt"
import "unsafe"

func main() {
	// RedDsaSignature()

	max_signers := 5
	min_signers := 3

	trustedPublicKeyPackage, trustedKeyPackages := ExamleTrustedKeyGen(max_signers, min_signers)
	fmt.Println("Signature with trusted setup:")
	RandomizedFrost(trustedPublicKeyPackage, trustedKeyPackages)

	DKGPublicKeyPackage, DKGKeyPackages := ExamplekeyGen(max_signers, min_signers)
	fmt.Println("Signature with DKG keys:")
	RandomizedFrost(DKGPublicKeyPackage, DKGKeyPackages)
}

// Standart RedDSA signature
func RedDsaSignature() {
	sk := C.new_signing_key()
	fmt.Printf("sk: %#v", sk)

	msg := []byte("Some message")
	slice := C.slice_raw_uint8_t{
		ptr: (*C.uint8_t)(unsafe.Pointer(&msg[0])),
		len: C.size_t(len(msg)),
	}

	var sig C.Signature_t
	err := C.sign_message(sk, slice, &sig)

	fmt.Println(
		"signature:", sig,
		"for message:", slice,
		"with error:", err,
	)

	var pk C.VerificationKey_t
	err = C.verification_key(&sk, &pk)

	fmt.Println(
		"pk:", pk,
		"error:", err,
	)

	err = C.verify(pk, slice, &sig)
	if err == 0 {
		fmt.Println("Verification successful")
	} else {
		fmt.Println("Verification failed")
	}
}

func GetShares(shares *C.Vec_IdentifiedData_KeyPackage_t) []C.IdentifiedData_KeyPackage_t {
	length := int(shares.len)
	ptr := shares.ptr

	return unsafe.Slice(ptr, length)
}

func GetIdentifiedDataSlice(shares *C.Vec_IdentifiedData_Vec_uint8_t) []C.IdentifiedData_Vec_uint8_t {
	length := int(shares.len)
	ptr := shares.ptr

	return unsafe.Slice(ptr, length)
}

func GetCVec(shares []C.IdentifiedData_Vec_uint8_t) C.Vec_IdentifiedData_Vec_uint8_t {
	if len(shares) == 0 {
		return C.Vec_IdentifiedData_Vec_uint8_t{ptr: nil, len: 0}
	}

	size := C.size_t(len(shares)) * C.size_t(unsafe.Sizeof(shares[0]))
	cShares := C.malloc(size)

	C.memcpy(cShares, unsafe.Pointer(&shares[0]), size)

	return C.Vec_IdentifiedData_Vec_uint8_t{
		ptr: (*C.IdentifiedData_Vec_uint8_t)(cShares),
		len: C.size_t(len(shares)),
	}
}

func ExamleTrustedKeyGen(max_signers int, min_signers int) (C.Vec_uint8_t, []C.IdentifiedData_KeyPackage_t) {
	var genResult C.TrustedShares_t
	if err := C.frost_randomized_keygen_dealer(C.uint16_t(max_signers), C.uint16_t(min_signers), &genResult); err != 0 {
		panic("Fail to generate keys with dealer")
	}

	pk := genResult.public_key_package
	keyPackages := GetShares(&genResult.key_packages)

	return pk, keyPackages
}

func RandomizedFrost(publicKeyPackage C.Vec_uint8_t, keyPackages []C.IdentifiedData_KeyPackage_t) {
	sigNonces := make([]C.Vec_uint8_t, len(keyPackages))
	sigCommitments := make([]C.Vec_uint8_t, len(keyPackages))
	sigIdentifiedCommitments := make([]C.IdentifiedData_Vec_uint8_t, len(keyPackages))
	for i, keyPackage := range keyPackages {
		id := C.uint16_t(i + 1)
		C.frost_randomized_commit(id, &keyPackage.data, &sigNonces[i], &sigCommitments[i], &sigIdentifiedCommitments[i])
	}

	msg := []byte("Some message")
	messageSlice := C.slice_raw_uint8_t{
		ptr: (*C.uint8_t)(unsafe.Pointer(&msg[0])),
		len: C.size_t(len(msg)),
	}

	var signingPackage C.Vec_uint8_t
	if err := C.frost_randomized_signing_package_new(
		GetCVec(sigIdentifiedCommitments),
		messageSlice,
		&signingPackage,
	); err != 0 {
		panic("Fail to create new signing package for signature")
	}

	randomizer := C.frost_randomized_new_randomizer()

	signaturePackages := make([]C.Vec_uint8_t, len(keyPackages))
	identifiedSignaturePackages := make([]C.IdentifiedData_Vec_uint8_t, len(keyPackages))
	for i := range len(keyPackages) {
		if err := C.frost_randomized_sign_package(&signingPackage, &sigNonces[i], &keyPackages[i].data, &randomizer, &signaturePackages[i], &identifiedSignaturePackages[i]); err != 0 {
			panic("fail to sign the package")
		}
	}

	gatheredSignatures := GetCVec(identifiedSignaturePackages)
	var aggregatedSignature C.Vec_uint8_t
	C.frost_randomized_aggregate(&signingPackage, &gatheredSignatures, &publicKeyPackage, &randomizer, &aggregatedSignature)

	if err := C.frost_randomized_verify(messageSlice, &aggregatedSignature, &publicKeyPackage, &randomizer); err != 0 {
		panic("Verification failed")
	}

	fmt.Println("Verification sucsessfull")
}

func ExamplekeyGen(maxSigners int, minSigners int) (C.Vec_uint8_t, []C.IdentifiedData_KeyPackage_t) {
	cMaxSigners := C.uint16_t(maxSigners)
	cMinSigners := C.uint16_t(minSigners)

	////////////////////////////////////////////////////////////////////////////
	// Key generation, Round 1
	////////////////////////////////////////////////////////////////////////////

	fmt.Println("Key generation, Round 1")

	round1SecretPackages := make(map[int]C.Vec_uint8_t)
	receivedRound1Packages := make(map[int][]C.IdentifiedData_Vec_uint8_t)

	for participantIndex := range maxSigners {
		var round1SecretPackage C.Vec_uint8_t
		var round1Package C.IdentifiedData_Vec_uint8_t

		if err := C.frost_dkg_part1(
			C.uint16_t(participantIndex+1),
			cMaxSigners,
			cMinSigners,
			&round1SecretPackage,
			&round1Package,
		); err != 0 {
			panic(fmt.Sprintf("Failed dkg part1 for participant: %d", participantIndex))
		}

		round1SecretPackages[participantIndex] = round1SecretPackage

		var idData C.IdentifiedData_Vec_uint8_t
		if err := C.identified_data_new_u16(C.uint16_t(participantIndex+1), &round1Package.data, &idData); err != 0 {
			panic("Failed to create identified data")
		}

		for receiverParticipantIndex := range maxSigners {
			if receiverParticipantIndex == participantIndex {
				continue
			}

			receivedRound1Packages[receiverParticipantIndex] = append(receivedRound1Packages[receiverParticipantIndex], idData)
		}
	}

	////////////////////////////////////////////////////////////////////////////
	// Key generation, Round 2
	////////////////////////////////////////////////////////////////////////////

	fmt.Println("Key generation, Round 2")

	round2SecretPackages := make(map[int]C.Vec_uint8_t)
	receivedRound2Packages := make(map[int][]C.IdentifiedData_Vec_uint8_t)

	for participant_index := range maxSigners {
		round1SecretPackage := round1SecretPackages[participant_index]
		round1Packages := GetCVec(receivedRound1Packages[participant_index])

		var round2SecretPackage C.Vec_uint8_t
		var round2Packages C.Vec_IdentifiedData_Vec_uint8_t
		if err := C.frost_dkg_part2(&round1SecretPackage, &round1Packages, &round2SecretPackage, &round2Packages); err != 0 {
			panic(fmt.Sprintf("Failed dkg part2 for participant: %d", participant_index))
		}

		round2SecretPackages[participant_index] = round2SecretPackage

		for _, round2Package := range GetIdentifiedDataSlice(&round2Packages) {
			var idData C.IdentifiedData_Vec_uint8_t
			if err := C.identified_data_new_u16(C.uint16_t(participant_index+1), &round2Package.data, &idData); err != 0 {
				panic("Failed to create identified data")
			}

			receiverIdentifier := int(C.identified_data_id_as_u16(&round2Package)) - 1
			if receiverIdentifier < 0 {
				panic("Failed to correctly retreive participant id")
			}

			receivedRound2Packages[receiverIdentifier] = append(receivedRound2Packages[receiverIdentifier], idData)
		}
	}

	////////////////////////////////////////////////////////////////////////////
	// Key generation, final computation
	////////////////////////////////////////////////////////////////////////////
	fmt.Println("Key generation, final computation")

	keyPackages := make([]C.IdentifiedData_KeyPackage_t, maxSigners)
	pubkeyPackages := make(map[int]C.Vec_uint8_t)

	for participantIndex := range maxSigners {
		round2Secret_package := round2SecretPackages[participantIndex]
		round1Packages := GetCVec(receivedRound1Packages[participantIndex])
		round2Packages := GetCVec(receivedRound2Packages[participantIndex])

		var keyPackage C.IdentifiedData_KeyPackage_t
		var pubkeyPackage C.Vec_uint8_t

		if err := C.frost_dkg_part3(
			&round2Secret_package,
			&round1Packages,
			&round2Packages,
			&keyPackage,
			&pubkeyPackage,
		); err != 0 {
			panic(fmt.Sprintf("Failed dkg part3 for participant: %d", participantIndex))
		}

		keyPackages[participantIndex] = keyPackage
		pubkeyPackages[participantIndex] = pubkeyPackage
	}

	return pubkeyPackages[0], keyPackages
}
