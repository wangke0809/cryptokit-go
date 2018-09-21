package kit

import (
	"testing"
)

func TestKey(t *testing.T) {

	privateKey,err := Generate(2048)
	if err != nil {
		t.Error(err)
	}

	pri,pub,err := Stringify(privateKey)
	if err != nil {
		t.Error(err)
	}
	t.Log(pri,pub)
	SaveKey(privateKey)
}
