package kit

import (
	"testing"
	"fmt"
	"bytes"
)

var (
	key  = "1234567"
	text = "test"
)

func TestAES_CBC(t *testing.T) {
	ciphertext, err := AESCBCEncrypt([]byte(text), []byte(key))
	if err != nil {
		t.Error(err.Error())
	}
	plaintext, err := AESCBCDecrypt(ciphertext, []byte(key))
	if err != nil {
		t.Error(err.Error())
	}
	if !bytes.Equal(plaintext, []byte(text)) {
		fmt.Println(string(text))
		t.Error()
	}

}


func TestAES_GCM(t *testing.T) {
	ciphertext, err := AESGCMEncrypt([]byte(text), []byte(key))
	if err != nil {
		t.Error(err.Error())
	}
	plaintext, err := AESGCMDecrypt(ciphertext, []byte(key))
	if err != nil {
		t.Error(err.Error())
	}
	if !bytes.Equal(plaintext, []byte(text)) {
		fmt.Println(string(text))
		t.Error()
	}

}