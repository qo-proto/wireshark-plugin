package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/qo-proto/qh"
	"github.com/qo-proto/qotp"
)

const Version = "1.0.0"

//var sharedSecrets = make(map[uint64][]byte)
type ConnSecrets struct {
	sharedSecret   []byte // PFS secret
	sharedSecretId []byte // non-PFS secret
}

var connSecrets = make(map[uint64]*ConnSecrets)

//export SetSharedSecretHex
func SetSharedSecretHex(connId C.ulonglong, secretHex *C.char) C.int {
	secretBytes, err := hex.DecodeString(C.GoString(secretHex))
	if err != nil {
		fmt.Printf("[qotp_crypto] SetSharedSecretHex ERROR: invalid hex string for connId=%d\n", connId)
		return -1
	}
	//sharedSecrets[uint64(connId)] = secretBytes
	secrets, ok := connSecrets[uint64(connId)]
	if !ok {
		secrets = &ConnSecrets{}
		connSecrets[uint64(connId)] = secrets
	}
	secrets.sharedSecret = secretBytes
	fmt.Printf("[qotp_crypto] SetSharedSecretHex: connId=%016x, secret=%s... (len=%d)\n",
		uint64(connId), C.GoString(secretHex)[:min(16, len(C.GoString(secretHex)))], len(secretBytes))
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//export SetSharedSecretIdHex
func SetSharedSecretIdHex(connId C.ulonglong, secretHex *C.char) C.int {
	secretBytes, err := hex.DecodeString(C.GoString(secretHex))
	if err != nil {
		fmt.Printf("[qotp_crypto] SetSharedSecretIdHex ERROR: invalid hex string for connId=%d\n", connId)
		return -1
	}

	secrets, ok := connSecrets[uint64(connId)]
	if !ok {
		secrets = &ConnSecrets{}
		connSecrets[uint64(connId)] = secrets
	}
	secrets.sharedSecretId = secretBytes
	fmt.Printf("[qotp_crypto] SetSharedSecretIdHex: connId=%016x, secretId=%s... (len=%d)\n",
		uint64(connId), C.GoString(secretHex)[:min(16, len(C.GoString(secretHex)))], len(secretBytes))
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

	//secret, ok := sharedSecrets[uint64(connId)]
	secrets, ok := connSecrets[uint64(connId)]
	if !ok {
		fmt.Printf("[qotp_crypto] Key NOT FOUND for connId=%016x\n", uint64(connId))
		for cid := range connSecrets {
			fmt.Printf("%016x ", cid)
		}
		fmt.Printf("\n")
		return -1
	}

	encBytes := C.GoBytes(unsafe.Pointer(encryptedData), encryptedLen)

	// Detect packet type from header byte
	var msgType string
	if len(encBytes) > 0 {
		headerByte := encBytes[0]
		msgTypeNum := headerByte >> 5
		msgTypes := []string{"InitSnd", "InitRcv", "InitCryptoSnd", "InitCryptoRcv", "Data"}
		if int(msgTypeNum) < len(msgTypes) {
			msgType = msgTypes[msgTypeNum]
		} else {
			msgType = fmt.Sprintf("Unknown(%d)", msgTypeNum)
		}
	}

	fmt.Printf("[qotp_crypto] Decrypt: connId=%016x type=%s len=%d isSender=%v epoch=%d\n",
		uint64(connId), msgType, len(encBytes), isSender != 0, epoch)

	// Basic length validation before attempting decryption
	if len(encBytes) < 30 { // Minimum: SnSize(6) + nonceRand(24)
		fmt.Printf("[qotp_crypto] Length too short: %d < 30\n", len(encBytes))
		return -2
	}

	//decrypted, err := qotp.DecryptDataForPcap(encBytes, isSender != 0, uint64(epoch), secret)
	decrypted, err := qotp.DecryptPcap(
		encBytes,
		isSender != 0,
		uint64(epoch),
		secrets.sharedSecret,
		secrets.sharedSecretId,
	)

	if err != nil {
		fmt.Printf("[qotp_crypto] DecryptDataForPcap failed: %v\n", err)
		return -2
	}

	fmt.Printf("[qotp_crypto] Decryption SUCCESS! Decrypted %d bytes\n", len(decrypted))

	if len(decrypted) > int(outputMaxLen) {
		return -3
	}

	/*for i := 0; i < len(decrypted); i++ {
		*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(output)) + uintptr(i))) = C.char(decrypted[i])
	}*/
	copy(unsafe.Slice((*byte)(unsafe.Pointer(output)), outputMaxLen)[:len(decrypted)], decrypted)

	return C.int(len(decrypted))
}

func main() {
	// Required for buildmode=c-shared
}

//export GetQhMethodsJSON
func GetQhMethodsJSON() *C.char {
	methods := []string{
		qh.GET.String(),
		qh.POST.String(),
		qh.PUT.String(),
		qh.PATCH.String(),
		qh.DELETE.String(),
		qh.HEAD.String(),
		qh.OPTIONS.String(),
	}

	data, err := json.Marshal(methods)
	if err != nil {
		return nil
	}

	return C.CString(string(data))
}

//export GetQhStatusMapJSON
func GetQhStatusMapJSON() *C.char {
	data, err := json.Marshal(qh.CompactToStatus)
	if err != nil {
		return nil
	}

	return C.CString(string(data))
}

//export GetQhRequestHeadersJSON
func GetQhRequestHeadersJSON() *C.char {
	data, err := json.Marshal(qh.RequestHeaderStaticTable)
	if err != nil {
		return nil
	}

	return C.CString(string(data))
}

//export GetQhResponseHeadersJSON
func GetQhResponseHeadersJSON() *C.char {
	data, err := json.Marshal(qh.
		ResponseHeaderStaticTable)
	if err != nil {
		return nil
	}

	return C.CString(string(data))
}
