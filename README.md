# gocipher

- - -
```
It's annoying to implement encryption and decryption, 
so I implemented it in advance

암호화 복호화 구현이 귀찮아서 미리 만들어놓음
```

## Require
`golang >=1.24`

- - - 
## Supported Algorithms
`DES, 3DES, AES-256-CBC, AES-256-GCM`

## Install
```shell
go get -u github.com/seanlee0923/gocipher
```

## Usage

```golang
encStr, err := gocipher.Encrypt(gocipher.AlgorithmDES, "String that you want to encrypt", []byte("12345678"))
if err != nil {
   // handle err
}

decStr, err := gocipher.Decrypt(gocipher.AlgorithmDES, encStr, []byte("12345678"))
if err != nil {
	// handle err
}
```