package main

/*
#cgo LDFLAGS: -L../target/release -lwallet_bindings

#include "../include/rust_points.h"
*/
import "C"
import "fmt"
import "unsafe"

func main() {
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
