package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"unsafe"
	"fmt"
	"errors"

	"github.com/qo-proto/qotp"
)

const Version = "1.0.0"

type ConnSecrets struct {
	sharedSecret   []byte // PFS secret
	sharedSecretId []byte // non-PFS secret
}

var connSecrets = make(map[uint64]*ConnSecrets)

//export SetSharedSecretHex
func SetSharedSecretHex(connId C.ulonglong, secretHex *C.char) C.int {
	secretBytes, err := hex.DecodeString(C.GoString(secretHex))
	if err != nil {
		return -1
	}
	
	secrets, ok := connSecrets[uint64(connId)]
	if !ok {
		secrets = &ConnSecrets{}
		connSecrets[uint64(connId)] = secrets
	}
	secrets.sharedSecret = secretBytes
	return 0
}

//export SetSharedSecretIdHex
func SetSharedSecretIdHex(connId C.ulonglong, secretHex *C.char) C.int {
	secretBytes, err := hex.DecodeString(C.GoString(secretHex))
	if err != nil {
		return -1
	}
	
	secrets, ok := connSecrets[uint64(connId)]
	if !ok {
		secrets = &ConnSecrets{}
		connSecrets[uint64(connId)] = secrets
	}
	secrets.sharedSecretId = secretBytes
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
	outputMaxLen C.int) C.int {

	secrets, ok := connSecrets[uint64(connId)]
	if !ok {
		return -1
	}

	encBytes := C.GoBytes(unsafe.Pointer(encryptedData), encryptedLen)
	decrypted, err := decryptAnyForPcap(
		encBytes,
		isSender != 0,
		uint64(epoch),
		secrets.sharedSecret,
		secrets.sharedSecretId,
		uint64(connId),
	)
	if err != nil {
		return -2
	}

	if len(decrypted) > int(outputMaxLen) {
		return -3
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(output)), outputMaxLen)[:len(decrypted)], decrypted)

	return C.int(len(decrypted))
}

func main() {
	// Required for buildmode=c-shared
}

func decryptAnyForPcap(encData []byte, isSender bool, epoch uint64, sharedSecret []byte, sharedSecretId []byte, connId uint64) ([]byte, error) {
	if len(encData) < qotp.MinPacketSize {
		return nil, fmt.Errorf("packet too small: needs at least %v bytes", qotp.MinPacketSize)
	}

	header := encData[0]
	version := header & 0x1F
	if version != qotp.CryptoVersion {
		return nil, errors.New("unsupported protocol version")
	}

	msgType := qotp.CryptoMsgType(header >> 5)

	switch msgType {
	case qotp.InitSnd:
		// No encrypted payload, only public keys
		return []byte{}, nil

	case qotp.InitCryptoSnd:
		if sharedSecretId == nil {
			return nil, errors.New("sharedSecretId required for InitCryptoSnd")
		}
		return qotp.DecryptInitCryptoSndForPcap(encData, sharedSecretId)

	case qotp.InitRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitRcv")
		}
		return qotp.DecryptInitRcvForPcap(encData, sharedSecret)

	case qotp.InitCryptoRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitCryptoRcv")
		}
		return qotp.DecryptInitCryptoRcvForPcap(encData, sharedSecret)

	case qotp.Data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for Data")
		}
		// Use the existing function
		packetConnId := qotp.Uint64(encData[qotp.HeaderSize : qotp.HeaderSize+qotp.ConnIdSize])
		if connId != 0 && packetConnId != connId {
			return nil, fmt.Errorf("connection ID mismatch: expected %d, got %d", connId, packetConnId)
		}
		return qotp.DecryptDataForPcap(encData[qotp.HeaderSize+qotp.ConnIdSize:], isSender, epoch, sharedSecret)

	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}
}