package indexer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"github.com/golang-collections/go-datastructures/bitarray"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

// Tests the constructor for `SecureIndexBuilder`.  Makes sure that all the
// fields are properly generated or calculated.
func TestCreateSecureIndexBuilder(t *testing.T) {
	numKeys := uint(100)
	lenSalt := uint(8)
	size := uint64(100000)
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

// Helper function that checks if a word is contained in the bloom filter.
func bfContainsWord(bf bitarray.BitArray, sIB *SecureIndexBuilder, docID uint, word string) bool {
	trapdoors := sIB.trapdoorFunc(word)
	for _, trapdoor := range trapdoors {
		mac := hmac.New(sIB.hash, trapdoor)
		mac.Write([]byte(string(docID)))
		// Ignore the error as we need to truncate the 256-bit hash into 64 bits
		codeword, _ := binary.Uvarint(mac.Sum(nil))
		if bit, _ := bf.GetBit(codeword % sIB.size); !bit {
			return false
		}
	}
	return true
}

// Tests the `BuildBloomFilter` function.  Checks that the bloom filter is
// deterministic, is relevant to the document ID, and contains all words in the
// file.
func TestBuildBloomFilter(t *testing.T) {
	numKeys := uint(13)
	lenSalt := uint(8)
	size := uint64(1900000)
	salts := GenerateSalts(numKeys, lenSalt)
	sIB := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	doc, err := ioutil.TempFile("", "bfTest")
	docContent := "This is a test file. It has a pretty random content."
	docWords := strings.Split(docContent, " ")
	docID := uint(42)
	if err != nil {
		t.Errorf("cannot create the temporary test file for `TestBuildBloomFilter`")
	}
	defer os.Remove(doc.Name()) // clean up
	if _, err := doc.Write([]byte(docContent)); err != nil {
		t.Errorf("cannot write to the temporary test file for `TestBuildBloomFilter")
	}
	// Rewinds the file
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf1 := sIB.buildBloomFilter(docID, doc)
	// Rewinds the file again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf2 := sIB.buildBloomFilter(docID, doc)
	// Rewinds the file yet again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf3 := sIB.buildBloomFilter(docID+1, doc)
	if !bf1.Equals(bf2) {
		t.Fatalf("the two bloom filters are different.  `buildBloomFilter` is likely non-deterministic")
	}
	if bf1.Equals(bf3) {
		t.Fatalf("the same document with different ids produces the same bloom filter")
	}
	for _, word := range docWords {
		if !bfContainsWord(bf1, sIB, docID, word) {
			t.Fatalf("one or more of the words is not present in the bloom filter")
		}
	}
}
