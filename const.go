package gocipher

const (
	AlgorithmDES      = "DES"
	Algorithm3DES     = "3DES"
	AlgorithmChaCha20 = "ChaCha20"
	AlgorithmRSA      = "RSA"

	AESModeECB = "AES-ECB"
	AESModeCBC = "AES-256-CBC"
	AESModeCFB = "AES-256-CFB"
	AESModeOFB = "AES-256-OFB"
	AESModeGCM = "AES-256-GCM"
)

const (
	blockSizeDES      = 8
	blockSizeAES      = 16
	blockSize3DES     = 8
	blockSizeChaCha20 = 32
)
