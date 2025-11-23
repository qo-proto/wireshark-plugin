package qotp

import (
	"crypto/ecdh"
)

// DecryptDataForPcap decrypts a QOTP Data packet for Wireshark/pcap analysis.
// This uses sharedSecret which is the ephemeral shared secret (PFS).
func DecryptDataForPcap(encData []byte, isSenderOnInit bool, epoch uint64, sharedSecret []byte) ([]byte, error) {
	msg, err := decryptData(encData, isSenderOnInit, epoch, sharedSecret)
	if err != nil {
		return nil, err
	}
	return msg.PayloadRaw, nil
}

// DecryptInitCryptoSndForPcap decrypts InitCryptoSnd packets using the identity shared secret (non-PFS).
// This uses sharedSecretId which is computed as ECDH(prvKeyEpSnd, pubKeyIdRcv).
// Note: This requires the receiver's private identity key to decrypt.
func DecryptInitCryptoSndForPcap(encData []byte, prvKeyIdRcv *ecdh.PrivateKey, mtu int) ([]byte, error) {
	_, _, msg, err := decryptInitCryptoSnd(encData, prvKeyIdRcv, mtu)
	if err != nil {
		return nil, err
	}
	return msg.PayloadRaw, nil
}

// DecryptInitRcvForPcap decrypts InitRcv packets using the ephemeral shared secret (PFS).
// This requires the sender's ephemeral private key.
func DecryptInitRcvForPcap(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) ([]byte, error) {
	_, _, _, msg, err := decryptInitRcv(encData, prvKeyEpSnd)
	if err != nil {
		return nil, err
	}
	return msg.PayloadRaw, nil
}

// DecryptInitCryptoRcvForPcap decrypts InitCryptoRcv packets using the ephemeral shared secret (PFS).
// This requires the sender's ephemeral private key.
func DecryptInitCryptoRcvForPcap(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) ([]byte, error) {
	_, _, msg, err := decryptInitCryptoRcv(encData, prvKeyEpSnd)
	if err != nil {
		return nil, err
	}
	return msg.PayloadRaw, nil
}
