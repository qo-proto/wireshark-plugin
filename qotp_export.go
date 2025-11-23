package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/qo-proto/qotp"
)

const Version = "1.0.0"

var sharedSecrets = make(map[uint64][]byte)

//export SetSharedSecretHex
func SetSharedSecretHex(connId C.ulonglong, secretHex *C.char) C.int {
	secretBytes, err := hex.DecodeString(C.GoString(secretHex))
	if err != nil {
		return -1
	}
	sharedSecrets[uint64(connId)] = secretBytes
	return 0
}

//export GetVersion
func GetVersion() *C.char {
	return C.CString(Version)
}

//export DecryptDataPacket
func DecryptDataPacket(
	encryptedData *C.char,
	encryptedLen C.int,
	connId C.ulonglong,
	isSender C.int,
	epoch C.ulonglong,
	output *C.char,
	outputMaxLen C.int) (result C.int) {

	// Recover from panics to avoid crashing Wireshark
	defer func() {
		if r := recover(); r != nil {
			result = -4 // Return -4 for panic/crash
		}
	}()

	secret, ok := sharedSecrets[uint64(connId)]
	if !ok {
		fmt.Printf("[qotp_crypto] Key not found for connId=%d\n", connId)
		return -1
	}

	encBytes := C.GoBytes(unsafe.Pointer(encryptedData), encryptedLen)
	fmt.Printf("[qotp_crypto] Decrypt attempt: connId=%d, len=%d, isSender=%v, epoch=%d\n",
		connId, len(encBytes), isSender != 0, epoch)

	// Basic length validation before attempting decryption
	if len(encBytes) < 30 { // Minimum: SnSize(6) + nonceRand(24)
		fmt.Printf("[qotp_crypto] Length too short: %d < 30\n", len(encBytes))
		return -2
	}

	decrypted, err := qotp.DecryptDataForPcap(encBytes, isSender != 0, uint64(epoch), secret)
	if err != nil {
		fmt.Printf("[qotp_crypto] DecryptDataForPcap failed: %v\n", err)
		return -2
	}

	fmt.Printf("[qotp_crypto] Decryption SUCCESS! Decrypted %d bytes\n", len(decrypted))

	if len(decrypted) > int(outputMaxLen) {
		return -3
	}

	for i := 0; i < len(decrypted); i++ {
		*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(output)) + uintptr(i))) = C.char(decrypted[i])
	}

	return C.int(len(decrypted))
}

func main() {
	// Required for buildmode=c-shared
}
