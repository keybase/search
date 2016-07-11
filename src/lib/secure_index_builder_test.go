package secureIndexBuilder

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCreateSecureIndexBuilder(t *testing.T) {
	numKeys := uint(100)
	lenSalt := uint(8)
	salts := GenerateSalts(numKeys, lenSalt)
	sIB1 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts)
	sIB2 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts)
	if sIB1.hash == nil || sIB2.hash == nil {
		t.Fatalf("hash function is not set correctly")
	}
	if sIB1.numKeys != uint(len(sIB1.keys)) || sIB2.numKeys != uint(len(sIB2.keys)) {
		t.Fatalf("numKeys not set up correctly")
	}
	if sIB1.numKeys != sIB2.numKeys {
		t.Fatalf("the two instances have different numbers of keys")
	}
	for i := uint(0); i < sIB1.numKeys; i++ {
		if !bytes.Equal(sIB1.keys[i], sIB2.keys[i]) {
			t.Fatalf("the two instances have different keys")
		}
	}
}
