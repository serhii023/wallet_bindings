package main

/*
#cgo LDFLAGS: -L../target/release -lwallet_bindings

#include "../include/rust_points.h"
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

func GetShares(shares *C.Vec_SecretShare_t) []C.SecretShare_t {
    length := int(shares.len)
    ptr := shares.ptr
    
	// var slice []C.SecretShare_t
	// slice = (*[1 << 30]C.SecretShare_t)(unsafe.Pointer(ptr))[:length:length]
	// return slice

    return unsafe.Slice(ptr, length)
}

func RandomizedFrost() {
	max_signers := C.uint16_t(5);
    min_signers := C.uint16_t(3);

	var gen_result C.TrustedShares_t
	if err := C.frost_randomized_keygen_dealer(max_signers, min_signers, &gen_result); err != 0 {
		panic("Fail to generate keys with dealer")
	}
	
	pk := gen_result.pubkeys
	shares := GetShares(&gen_result.shares)
	share := &shares[1]

	fmt.Println(
		"pk:", pk,
		"share:", share,
	)

	var sigNonces C.SigningNonces_t
	var sigCommitments C.SigningCommitments_t
	C.frost_randomized_commit(share, &sigNonces, &sigCommitments)

	fmt.Println(
		"sigNonces:", sigNonces,
		"sigCommitments:", sigCommitments,
	)
}