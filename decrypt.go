package gocipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
)

func decryptDES(encryptedBase64 string, key []byte) (string, error) {
	if len(key) != blockSizeDES {
		return "", errors.New("invalid key size, must be 8 bytes for DES")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSizeDES {
		block.Decrypt(plaintext[i:i+blockSizeDES], ciphertext[i:i+blockSizeDES])
	}

	return unpad(plaintext)
}

func decryptAES_CBC(encryptedBase64 string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid key size, must be 32 bytes for AES-256-CBC")
	}

	data, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", errors.New("invalid ciphertext")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext)
}

func decryptAES_GCM(encryptedBase64 string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid key size, must be 32 bytes for AES-256-GCM")
	}

	data, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	if len(data) < 12 {
		return "", errors.New("invalid ciphertext")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
func decrypt3DES(encryptedBase64 string, key []byte) (string, error) {
	if len(key) != 24 {
		return "", errors.New("invalid key size, must be 24 bytes for 3DES")
	}

	data, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	if len(data) < block.BlockSize() {
		return "", errors.New("invalid ciphertext")
	}

	iv := data[:block.BlockSize()]
	ciphertext := data[block.BlockSize():]

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext)
}
