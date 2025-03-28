package gocipher

type Algorithm string

const (
	AlgorithmDES      Algorithm = "DES"
	Algorithm3DES     Algorithm = "3DES"
	AlgorithmChaCha20 Algorithm = "ChaCha20"
	AlgorithmRSA      Algorithm = "RSA"

	AESModeECB Algorithm = "AES-ECB"
	AESModeCBC Algorithm = "AES-256-CBC"
	AESModeCFB Algorithm = "AES-256-CFB"
	AESModeOFB Algorithm = "AES-256-OFB"
	AESModeGCM Algorithm = "AES-256-GCM"
)

const (
	blockSizeDES      = 8
	blockSizeAES      = 16
	blockSize3DES     = 8
	blockSizeChaCha20 = 32
)
