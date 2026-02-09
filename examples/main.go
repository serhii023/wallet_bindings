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
	RandomizedFrost()
}

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

func GetShares(shares *C.Vec_IdentifiedData_SecretShare_t) []C.IdentifiedData_SecretShare_t {
	length := int(shares.len)
	ptr := shares.ptr

	return unsafe.Slice(ptr, length)
}

// func GetCVec(shares []C.IdentifiedData_Vec_uint8_t) C.Vec_IdentifiedData_Vec_uint8_t {
// 	if len(shares) == 0 {
// 		return C.Vec_IdentifiedData_Vec_uint8_t{ptr: nil, len: 0}
// 	}

// 	ptr := &shares[0]

// 	return C.Vec_IdentifiedData_Vec_uint8_t{
// 		ptr: ptr,
// 		len: C.size_t(len(shares)),
// 	}
// }

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


func RandomizedFrost() {
	max_signers := C.uint16_t(5)
	min_signers := C.uint16_t(3)

	var gen_result C.TrustedShares_t
	if err := C.frost_randomized_keygen_dealer(max_signers, min_signers, &gen_result); err != 0 {
		panic("Fail to generate keys with dealer")
	}

	pk := gen_result.public_key_package
	shares := GetShares(&gen_result.shares)
	share := &shares[1]

	fmt.Println(
		"pk:", pk,
		"share:", share,
	)

	sigNonces := make([]C.Vec_uint8_t, len(shares))
	sigCommitments := make([]C.Vec_uint8_t, len(shares))
	sigIdentifiedCommitments := make([]C.IdentifiedData_Vec_uint8_t, len(shares))
	for i, share := range shares {
		C.frost_randomized_commit(&share.data, &sigNonces[i], &sigCommitments[i], &sigIdentifiedCommitments[i])
	}

	fmt.Println(
		"sigNonces:", sigNonces,
		"sigCommitments:", sigCommitments,
		"sigIdentifiedCommitments:", sigIdentifiedCommitments,
	)

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

	fmt.Println(
		"messageSlice:", messageSlice,
		"signingPackage:", signingPackage,
		"randomizer:", randomizer,
	)

	signaturePackages := make([]C.Vec_uint8_t, len(shares))
	identifiedSignaturePackages := make([]C.IdentifiedData_Vec_uint8_t, len(shares))
	for i := range len(shares) {
		if err := C.frost_randomized_sign_package(&signingPackage, &sigNonces[i], &shares[i].data, &randomizer, &signaturePackages[i], &identifiedSignaturePackages[i]); err != 0 {
			panic("fail to sign the package")
		}

		fmt.Println(
			"signaturePackages[i]:", signaturePackages[i],
			"&identifiedSignaturePackages[i]:", identifiedSignaturePackages[i],
		)
	}

	gatheredSignatures := GetCVec(identifiedSignaturePackages)
	fmt.Println("signaturePackages:", signaturePackages, "gatheredSignatures:", gatheredSignatures)

	var aggregatedSignature C.Vec_uint8_t
	C.frost_randomized_aggregate(&signingPackage, &gatheredSignatures, &pk, &randomizer, &aggregatedSignature)

	fmt.Println("aggregatedSignature:", aggregatedSignature)

	if err := C.frost_randomized_verify(messageSlice, &aggregatedSignature, &pk, &randomizer); err != 0 {
		panic("Verification failed")
	}

	fmt.Println("Verification sucsessfull")

}
