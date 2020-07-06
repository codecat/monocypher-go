package monocypher

// Source: https://github.com/demonshreder/monocypher-go
// Modified heavily because it had some problems
// Also updated to latest monocypher

// #cgo CFLAGS: -std=c99
// #include "monocypher.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"
import "unsafe"

// SignMessage signs a message with your secret key. The generated signature is returned.
func SignMessage(message, secretKey, publicKey []byte) []byte {
	/*
		void crypto_sign(
			uint8_t        signature [64],
			const uint8_t  secret_key[32],
			const uint8_t  public_key[32], // optional, may be 0
			const uint8_t *message, size_t message_size
		);
	*/

	CSign := (*C.uint8_t)(C.CBytes(make([]uint8, 64)))
	defer C.free(unsafe.Pointer(CSign))

	CSecKey := (*C.uint8_t)(C.CBytes([]uint8(secretKey)))
	defer C.free(unsafe.Pointer(CSecKey))

	CPubKey := (*C.uint8_t)(C.CBytes([]uint8(publicKey)))
	defer C.free(unsafe.Pointer(CPubKey))

	CMessage := (*C.uint8_t)(C.CBytes(message))
	defer C.free(unsafe.Pointer(CMessage))

	CSize := (C.size_t)(len(message))

	// C Method call
	C.crypto_sign(CSign, CSecKey, CPubKey, CMessage, CSize)

	// Converting CTypes back to Go
	return C.GoBytes(unsafe.Pointer(CSign), C.int(64))
}

// CheckMessageSignature checks the message and its corresponding public key and signature for validity.
func CheckMessageSignature(message, publicKey, signature []byte) bool {
	/*
		int crypto_check(
			const uint8_t  signature [64],
			const uint8_t  public_key[32],
			const uint8_t *message, size_t message_size
		);
	*/

	CSign := (*C.uint8_t)(C.CBytes(signature))
	defer C.free(unsafe.Pointer(CSign))

	CPubKey := (*C.uint8_t)(C.CBytes([]uint8(publicKey)))
	defer C.free(unsafe.Pointer(CPubKey))

	CMessage := (*C.uint8_t)(C.CBytes(message))
	defer C.free(unsafe.Pointer(CMessage))

	CSize := (C.size_t)(len(message))

	// C Method call
	CResult := C.int(0)
	CResult = C.crypto_check(CSign, CPubKey, CMessage, CSize)

	// Converting CTypes back to Go
	var GResult []byte = C.GoBytes(unsafe.Pointer(&CResult), C.int(1))
	return GResult[0] == 0
}
