package libsearch

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/jxguan/go-datastructures/bitarray"
)

// Tests the constructor for `SecureIndexBuilder`.  Makes sure that all the
// fields are properly generated or calculated.
func TestCreateSecureIndexBuilder(t *testing.T) {
	numKeys := 100
	lenSalt := 8
	size := uint64(100000)
	salts, err := GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib1 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	sib2 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	if sib1.hash == nil || sib2.hash == nil {
		t.Fatalf("hash function is not set correctly")
	}
	if sib1.size != size || sib2.size != size {
		t.Fatalf("the sizes of the indexes not set up correctly")
	}
	if len(sib1.keys) != len(sib2.keys) {
		t.Fatalf("the two indexers have different numbers of keys")
	}
	for i := 0; i < len(sib1.keys); i++ {
		if !bytes.Equal(sib1.keys[i], sib2.keys[i]) {
			t.Fatalf("the two instances have different keys")
		}
	}
	trapdoors1 := sib1.trapdoorFunc("test")
	trapdoors2 := sib2.trapdoorFunc("test")
	if len(sib1.keys) != len(trapdoors1) || len(sib2.keys) != len(trapdoors2) {
		t.Fatalf("incorrect number of trapdoor functions")
	}
	for i := 0; i < len(sib1.keys); i++ {
		if !bytes.Equal(trapdoors1[i], trapdoors2[i]) {
			t.Fatalf("the two instances have different trapdoor functions")
		}
	}
	trapdoors1dup := sib1.trapdoorFunc("test")
	for i := 0; i < len(sib1.keys); i++ {
		if !bytes.Equal(trapdoors1[i], trapdoors1dup[i]) {
			t.Fatalf("trapdoor functions not deterministic")
		}
	}
}

// Helper function that checks if a word is contained in the bloom filter.
func bfContainsWord(bf bitarray.BitArray, sib *SecureIndexBuilder, nonce uint64, word string) bool {
	trapdoors := sib.trapdoorFunc(word)
	for _, trapdoor := range trapdoors {
		mac := hmac.New(sib.hash, trapdoor)
		mac.Write(big.NewInt(int64(nonce)).Bytes())
		// Ignore the error as we need to truncate the 256-bit hash into 64 bits
		codeword, _ := binary.Uvarint(mac.Sum(nil))
		if bit, _ := bf.GetBit(codeword % sib.size); !bit {
			return false
		}
	}
	return true
}

// Tests the `buildBloomFilter` function.  Checks that the bloom filter is
// deterministic, is relevant to the document ID, and contains all words in the
// file.
func TestBuildBloomFilter(t *testing.T) {
	numKeys := 13
	lenSalt := 8
	size := uint64(1900000)
	salts, err := GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	doc, err := ioutil.TempFile("", "bfTest")
	docContent := "This is a test file. It has a pretty random content."
	docWords := strings.Split(docContent, " ")
	nonce := uint64(42)
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
	bf1, count := sib.buildBloomFilter(nonce, doc)
	// Rewinds the file again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf2, _ := sib.buildBloomFilter(nonce, doc)
	// Rewinds the file yet again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf3, _ := sib.buildBloomFilter(nonce+1, doc)
	if !bf1.Equals(bf2) {
		t.Fatalf("the two bloom filters are different.  `buildBloomFilter` is likely non-deterministic")
	}
	if bf1.Equals(bf3) {
		t.Fatalf("the same document with different ids produces the same bloom filter")
	}
	if count != int64(len(docWords)-1) {
		t.Fatalf("the number of unique words is not correct")
	}
	for _, word := range docWords {
		if !bfContainsWord(bf1, sib, nonce, word) {
			t.Fatalf("one or more of the words is not present in the bloom filter")
		}
	}
}

// Tests the `blindBloomFilter` function.  Checks that bits are being uiformly
// randomly blinded.
func TestBlindBloomFilter(t *testing.T) {
	numKeys := 1
	lenSalt := 8
	size := uint64(1900000)
	salts, err := GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	bf := bitarray.NewSparseBitArray()
	err = sib.blindBloomFilter(bf, 1000000)
	if err != nil {
		t.Fatalf("error when blinding the bloom filter: %s", err)
	}
	if bf.Capacity() <= uint64(1899968) {
		t.Fatalf("the blinding process is almost certainly not uniformly random (or you are just very lucky, which happens with a probability of 0.000005%%)")
	}
	if len(bf.ToNums()) <= 770000 {
		t.Fatalf("the blinding process has way too many collisions and is almost certainly not uniformly random")
	}
}

// Tests the `BuildSecureIndex` function.  Makes sure that all the words can be found
// in the index and that the index has been randomly blinded.
func TestBuildSecureIndex(t *testing.T) {
	numKeys := 13
	lenSalt := 8
	size := uint64(1900000)
	salts, err := GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	doc, err := ioutil.TempFile("", "indexTest")
	docContent := "This is a test file. It has a pretty random content."
	docWords := strings.Split(docContent, " ")
	if err != nil {
		t.Errorf("cannot create the temporary test file for `TestBuildSecureIndex`")
	}
	defer os.Remove(doc.Name()) // clean up
	if _, err := doc.Write([]byte(docContent)); err != nil {
		t.Errorf("cannot write to the temporary test file for `TestBuildSecureIndex")
	}
	// Rewinds the file
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildSecureIndex")
	}
	index1, err := sib.BuildSecureIndex(doc, int64(len(docContent)))
	if err != nil {
		t.Fatalf("error when building the secure index: %s", err)
	}
	// Rewinds the file again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildSecureIndex")
	}
	index2, err := sib.BuildSecureIndex(doc, int64(len(docContent)))
	if err != nil {
		t.Fatalf("error when building the secure index: %s", err)
	}
	// Rewinds the file yet again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildSecureIndex")
	}
	if index1.BloomFilter.Equals(index2.BloomFilter) {
		t.Fatalf("the two indexes for the same document are the same.  They are not likely blinded and nonce is not properly used")
	}
	if index1.Size != size {
		t.Fatalf("the size in the index is not set up correctly")
	}
	for _, word := range docWords {
		if !bfContainsWord(index1.BloomFilter, sib, index1.Nonce, word) {
			t.Fatalf("one or more of the words is not present in the index")
		}
	}
}
