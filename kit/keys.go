package kit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// Generate new RSA keypair
func Generate(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Stringify private key

func Stringify(privateKey *rsa.PrivateKey) (string, string, error) {
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	return string(pem.EncodeToMemory(&privateKeyBlock)), string(pem.EncodeToMemory(&publicKeyBlock)), nil
}

// save  key

func SaveKey(privateKey *rsa.PrivateKey) error {
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}

	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}

	err = pem.Encode(file, privateKeyBlock)
	if err != nil {
		return err
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}

	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}

	err = pem.Encode(file, publicKeyBlock)
	if err != nil {
		return err
	}
	return nil
}

// Decode Key
func DecodePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(key))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return privateKey, err
}
