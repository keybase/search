package indexer

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCreateSecureIndexBuilder(t *testing.T) {
	numKeys := uint(100)
	lenSalt := uint(8)
	size := uint(100000)
	salts := GenerateSalts(numKeys, lenSalt)
	sIB1 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	sIB2 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	if sIB1.hash == nil || sIB2.hash == nil {
		t.Fatalf("hash function is not set correctly")
	}
	if sIB1.numKeys != uint(len(sIB1.keys)) || sIB2.numKeys != uint(len(sIB2.keys)) {
		t.Fatalf("numKeys not set up correctly")
	}
	if sIB1.numKeys != sIB2.numKeys {
		t.Fatalf("the two instances have different numbers of keys")
	}
	if sIB1.size != size || sIB2.size != size {
		t.Fatalf("the sizes of the indexes not set up correctly")
	}
	for i := uint(0); i < sIB1.numKeys; i++ {
		if !bytes.Equal(sIB1.keys[i], sIB2.keys[i]) {
			t.Fatalf("the two instances have different keys")
		}
	}
	trapdoors1 := sIB1.trapdoorFunc("test")
	trapdoors2 := sIB2.trapdoorFunc("test")
	if sIB1.numKeys != uint(len(trapdoors1)) || sIB2.numKeys != uint(len(trapdoors2)) {
		t.Fatalf("incorrect number of trapdoor functions")
	}
	for i := uint(0); i < sIB1.numKeys; i++ {
		if !bytes.Equal(trapdoors1[i], trapdoors2[i]) {
			t.Fatalf("the two instances have different trapdoor functions")
		}
	}
	trapdoors1dup := sIB1.trapdoorFunc("test")
	for i := uint(0); i < sIB1.numKeys; i++ {
		if !bytes.Equal(trapdoors1[i], trapdoors1dup[i]) {
			t.Fatalf("trapdoor functions not deterministic")
		}
	}
}
