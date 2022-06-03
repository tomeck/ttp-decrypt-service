package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

func decryptECB(ct, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Unpad(pt) // unpad plaintext after decryption
	if err != nil {
		panic(err.Error())
	}
	return pt
}

func DecryptAes128Ecb(data, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}

// Encrypt plaintext (pt) with the specified key in AES-CBC mode
func EncryptAESWithCBC(pt, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	ct := make([]byte, len(pt))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, pt)

	return ct
}

// Encrypt plaintext (pt) with the specified key in AES-ECB mode
func EncryptAESWithECB(pt, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBEncrypter(block)
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

// Shift bytes by one bit to the left, return the resultant bytes
func shiftBytesLeft(a []byte) (dst []byte) {

	n := len(a)
	dst = make([]byte, n)
	for i := 0; i < n-1; i++ {
		dst[i] = a[i] << 1
		dst[i] = (dst[i] & 0xfe) | (a[i+1] >> 7)
	}
	dst[n-1] = a[n-1] << 1
	return dst
}

// stores (a xor b) in dst, stopping when the end of any slice is reached
func XorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}

	if n == 0 {
		return nil
	}

	dst := make([]byte, n)

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

// Derive two subkeys from an AES key. Each subkey is 16 bytes
func DeriveAesCmacSubkeys(K []byte) (K1, K2 []byte, err error) {

	// [1] AES encrypt the 16-byte all-zero input data hex 0000000000000000 - 0000000000000000 with K,
	// yielding the 16-byte output, which we will call S.
	s1data, _ := hex.DecodeString("00000000000000000000000000000000")
	r64, _ := hex.DecodeString("00000000000000000000000000000087")

	s := EncryptAESWithECB(s1data, K)

	// [2] If the most significant (left-most) bit of S is 1, then calculate
	// K1 = (S << 1)  R128, where S << 1 means the data string S shifted one bit left
	// (that is, multiplied by two, without carry).
	//
	// Otherwise, if the most significant bit of S is 0, then calculate K1 = S << 1,
	if s[0]&byte(0b10000000) == byte(0b10000000) {
		K1 = XorBytes(shiftBytesLeft(s), r64)
	} else {
		K1 = shiftBytesLeft(s)
	}

	// [3] If the most significant (left-most) bit of K1 is 1, then calculate K2 = (K1 << 1)  R128,
	//
	// Otherwise, if the most significant bit of K1 is 0, then calculate K2=K1<<1.
	if K1[0]&byte(0b10000000) == byte(0b10000000) {
		K2 = XorBytes(shiftBytesLeft(K1), r64)
	} else {
		K2 = shiftBytesLeft(K1)
	}

	return K1, K2, nil
}

// Derive Key Block Encryption and Authentication Keys
func DeriveKeyblockKeys(KBPK []byte) (KBEK, KBAK []byte, err error) {

	// [1] Setup key derivation data
	/*
	   # Key Derivation data
	   # byte 0 = a counter increment for each block of kbpk, start at 1
	   # byte 1-2 = key usage indicator
	   #   - 0000 = encryption
	   #   - 0001 = MAC
	   # byte 3 = separator, set to 0
	   # byte 4-5 = algorithm indicator
	   #   - 0002 = AES-128
	   #   - 0003 = AES-192
	   #   - 0004 = AES-256
	   # byte 6-7 = key length in bits
	   #   - 0080 = AES-128
	   #   - 00C0 = AES-192
	   #   - 0100 = AES-256
	*/
	kd_input, _ := hex.DecodeString("01000000000200808000000000000000")

	// var calls_to_cmac [2]int
	if len(KBPK) == 16 {
		// Adjust for AES 128 bit
		kd_input[4] = 0x00
		kd_input[5] = 0x02
		kd_input[6] = 0x00
		kd_input[7] = 0x80
		// calls_to_cmac[0] = 1
	} else {
		panic("Only 16 byte KBPKs are supported currently")
	}
	// TODO JTE add support for AES 192 and 256
	// } else if len(KBPK) == 24 {
	// 	// Adjust for AES 192 bit
	// 	kd_input[4:6] = 0x0003
	// 	kd_input[6:8] = 0x00C0
	// 	calls_to_cmac[0] = 1
	// 	calls_to_cmac[1] = 2
	// } else  {
	// 	// Adjust for AES 256 bit
	// 	kd_input[4:6] = 0x0004
	// 	kd_input[6:8] = 0x0100
	// 	calls_to_cmac[0] = 1
	// 	calls_to_cmac[1] = 2
	// }

	// [2] Derive subkeys
	_, K2, _ := DeriveAesCmacSubkeys(KBPK)

	// [3] Produce the same number of keying material as the key's length.
	// Each call to CMAC produces 128 bits of keying material.
	// 	AES-128 -> 1 call to CMAC  -> AES-128 KBEK/KBAK
	// 	AES-196 -> 2 calls to CMAC -> AES-196 KBEK/KBAK (out of 256 bits of data)
	// 	AES-256 -> 2 calls to CMAC -> AES-256 KBEK/KBAK

	// Counter is incremented for each call to CMAC
	kd_input[0] = 1

	// Generate the Decryption key
	kd_input[1] = 0x00
	kd_input[2] = 0x00

	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	KBEK = EncryptAESWithCBC(XorBytes(kd_input, K2), KBPK, iv)

	// Generate the Authentication key
	kd_input[1] = 0x00
	kd_input[2] = 0x01
	KBAK = EncryptAESWithCBC(XorBytes(kd_input, K2), KBPK, iv)

	//TODO JTE TESTING - using values from Python code
	// KBEK, _ = hex.DecodeString("6479fe6b7c473786456d2a92ea5bba7e")
	// KBAK, _ = hex.DecodeString("85fa1011b33779965e094eaeb8c49955")

	return KBEK, KBAK, nil
}

// Return the IV from the Keyblock
func ivFromTR31KeyBlock(keyBlock string) []byte {

	// In a Tr-31 keyblock, the MAC is the IV
	// Since the MAC is the last 16 bytes let's return that
	keyBlockBytes, _ := hex.DecodeString(keyBlock[len(keyBlock)-32:])
	return keyBlockBytes
}

// Return the encrypted key from the Keyblock
func encryptedKeyFromTR31KeyBlock(keyBlock string) []byte {

	// In a Tr-31 keyblock, the key is everything beyond the first 16 bytes
	// excluding the trailing 16-byte MAC

	// Extract that slice and get its bytes
	encryptedKeyBytes, _ := hex.DecodeString(keyBlock[16:])
	return encryptedKeyBytes[:len(encryptedKeyBytes)-16] // omit header and MAC
}
