package kit

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

// Base64 encode
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//Base64 decode
func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// MD5-32
func Md532(data string) []byte {
	h := md5.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA-1
func SHA1(data string) []byte {
	h := sha1.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA-256
func SHA256(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA-384
func SHA384(data string) []byte {
	h := sha512.New384()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA-512
func SHA512(data string) []byte {
	h := sha512.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// HmacSha256
func HmacSha256(publicKey, privateKey string) []byte {
	mac := hmac.New(sha256.New, []byte(privateKey))
	mac.Write([]byte(publicKey))
	return mac.Sum(nil)
}

// HmacSha1
func HmacSha1(publicKey, privateKey string) []byte {
	mac := hmac.New(sha1.New, []byte(privateKey))
	mac.Write([]byte(publicKey))
	return mac.Sum(nil)
}

// Pbkdf2Sha256
func Pbkdf2Sha256(data, salt string, iterations int) string {
	dk := pbkdf2.Key([]byte(data), []byte(salt), iterations, 32, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", iterations, salt, base64.StdEncoding.EncodeToString(dk))
}

// RSA encrypt
func RSAEncrypt(source []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubk := pubInterface.(*rsa.PublicKey)
	segment := (pubk.N.BitLen() + 7) / 8
	hash := crypto.SHA256

	var start, end int

	// preventing message too long
	if segment < 2*hash.Size()+2 {
		fmt.Printf("your key length is too short, minimum recommend: %d", 2*hash.Size()+2)
		os.Exit(0)
	}

	var data []byte
	for i := range source {
		start = i * segment / 2
		if start+segment/2 < len(source) {
			end = start + segment/2
		} else {
			end = len(source)
		}

		byteSequence := source[start:end]
		segmentEncrypt, err := rsa.EncryptOAEP(hash.New(), rand.Reader, pubk, byteSequence, nil)
		if err != nil {
			fmt.Printf("oaep encrypt: %s", err)
			os.Exit(0)
		}

		data = append(data, segmentEncrypt...)
		if end == len(source) {
			break
		}
	}
	return data, nil
}

// RSA decrypt
func RSADecrypt(source []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}

	prik, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	segment := (prik.PublicKey.N.BitLen() + 7) / 8
	hash := crypto.SHA256

	var start, end int

	// preventing message too long
	if segment < 2*hash.Size()+2 {
		fmt.Printf("your key length is too short, minimum recommend: %d", 2*hash.Size()+2)
		os.Exit(0)
	}
	var data []byte
	for i := range source {
		start = i * segment
		if start+segment < len(source) {
			end = start + segment
		} else {
			end = len(source)
		}
		segmentEncrypt := source[start:end]
		segmentDecrypt, err := rsa.DecryptOAEP(hash.New(), rand.Reader, prik, segmentEncrypt, nil)
		if err != nil {
			fmt.Printf("oaep decrypt: %s, start %d, end %d", err, start, end)
			os.Exit(0)
		}
		data = append(data, segmentDecrypt...)
		if end == len(source) {
			break
		}
	}
	return data, nil
}

// RSA sign
func RSASign(origdata string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}

	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	digest := SHA256(origdata)
	body, err := rsa.SignPKCS1v15(rand.Reader, privInterface, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}
	return Base64Encode(body), nil
}

// RSA verify
func RSAVerify(origdata, ciphertext string, publicKey []byte) (bool, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	digest := SHA256(origdata)
	body, err := Base64Decode(ciphertext)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, body)
	if err != nil {
		return false, err
	}
	return true, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}

// aes-cbc encrypt
func AESCBCEncrypt(plaintext, key []byte) ([]byte, error) {

	plaintext = PKCS5Padding(plaintext, aes.BlockSize)

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	salt := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	dk := pbkdf2.Key(key, salt, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return append(ciphertext, salt...), nil
}

// aes-cbc decrypt
func AESCBCDecrypt(ciphertext, key []byte) ([]byte, error) {

	salt := ciphertext[len(ciphertext)-12:]
	ciphertext = ciphertext[:len(ciphertext)-12]
	dk := pbkdf2.Key(key, salt, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)
	return ciphertext, nil
}

// aes-gcm encrypt
func AESGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	salt := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	dk := pbkdf2.Key(key, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, salt, plaintext, nil)
	// Append the salt to the end of file
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

// aes-gcm decrypt
func AESGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	salt := ciphertext[len(ciphertext)-12:]
	dk := pbkdf2.Key(key, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, salt, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
