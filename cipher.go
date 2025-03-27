package gocipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func encryptDES(plaintext string, key []byte) (string, error) {
	if len(key) != blockSizeDES {
		return "", errors.New("invalid key size, must be 8 bytes for DES")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	paddedText := pad([]byte(plaintext), blockSizeDES)
	ciphertext := make([]byte, len(paddedText))

	for i := 0; i < len(paddedText); i += blockSizeDES {
		block.Encrypt(ciphertext[i:i+blockSizeDES], paddedText[i:i+blockSizeDES])
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

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

func encryptAES_CBC(plaintext string, key []byte) (string, error) {
	if len(key) != 32 { // AES-256 키는 32바이트
		return "", errors.New("invalid key size, must be 32 bytes for AES-256-CBC")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	paddedText := pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))

	mode.CryptBlocks(ciphertext, paddedText)

	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...)), nil
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

func encryptAES_GCM(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid key size, must be 32 bytes for AES-256-GCM")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12) // GCM 표준 nonce 크기
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
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

func encrypt3DES(plaintext string, key []byte) (string, error) {
	if len(key) != 24 { // 3DES 키는 24바이트
		return "", errors.New("invalid key size, must be 24 bytes for 3DES")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	paddedText := pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(paddedText))

	mode.CryptBlocks(ciphertext, paddedText)

	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...)), nil
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
