package gocipher

import (
	"bytes"
	"errors"
)

// Encrypt encrypts the given plaintext using the specified algorithm and key.
// Supported algorithms: DES, 3DES, AES (CBC & GCM).
//
// Parameters:
// - algorithm: The encryption algorithm to use (e.g., AlgorithmDES, Algorithm3DES, AESModeCBC, AESModeGCM).
// - plaintext: The input string to be encrypted.
// - key: The encryption key (size depends on the algorithm).
//
// Returns:
// - A base64-encoded encrypted string.
// - An error if the encryption fails or if the algorithm is unsupported.
func Encrypt(algorithm Algorithm, plaintext string, key []byte) (string, error) {
	switch algorithm {
	case AlgorithmDES:
		return encryptDES(plaintext, key)
	case Algorithm3DES:
		return encrypt3DES(plaintext, key)
	case AESModeCBC:
		return encryptAES_CBC(plaintext, key)
	case AESModeGCM:
		return encryptAES_GCM(plaintext, key)
	default:
		return "", errors.New("unsupported encryption algorithm")
	}
}

// Decrypt decrypts the given encrypted base64 string using the specified algorithm and key.
// Supported algorithms: DES, 3DES, AES (CBC & GCM).
//
// Parameters:
// - algorithm: The encryption algorithm used to encrypt the data (e.g., AlgorithmDES, Algorithm3DES, AESModeCBC, AESModeGCM).
// - encryptedBase64: The base64-encoded encrypted data to be decrypted.
// - key: The encryption key used to encrypt the data.
//
// Returns:
// - The original plaintext string if decryption is successful.
// - An error if the decryption fails or if the algorithm is unsupported.
func Decrypt(algorithm Algorithm, encryptedBase64 string, key []byte) (string, error) {
	switch algorithm {
	case AlgorithmDES:
		return decryptDES(encryptedBase64, key)
	case Algorithm3DES:
		return decrypt3DES(encryptedBase64, key)
	case AESModeCBC:
		return decryptAES_CBC(encryptedBase64, key)
	case AESModeGCM:
		return decryptAES_GCM(encryptedBase64, key)
	default:
		return "", errors.New("unsupported decryption algorithm")
	}
}

func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte) (string, error) {
	length := len(src)
	if length == 0 {
		return "", errors.New("invalid padding: empty data")
	}
	padding := int(src[length-1])
	if padding > length || padding == 0 {
		return "", errors.New("invalid padding")
	}
	return string(src[:(length - padding)]), nil
}
