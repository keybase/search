package indexer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"github.com/jxguan/go-datastructures/bitarray"
	"io/ioutil"
	"os"
	"search/util"
	"strings"
	"testing"
)

// Tests the constructor for `SecureIndexBuilder`.  Makes sure that all the
// fields are properly generated or calculated.
func TestCreateSecureIndexBuilder(t *testing.T) {
	numKeys := 100
	lenSalt := 8
	size := uint64(100000)
	salts, err := util.GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib1 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	sib2 := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	if sib1.hash == nil || sib2.hash == nil {
		t.Fatalf("hash function is not set correctly")
	}
	if sib1.numKeys != len(sib1.keys) || sib2.numKeys != len(sib2.keys) {
		t.Fatalf("numKeys not set up correctly")
	}
	if sib1.numKeys != sib2.numKeys {
		t.Fatalf("the two instances have different numbers of keys")
	}
	if sib1.size != size || sib2.size != size {
		t.Fatalf("the sizes of the indexes not set up correctly")
	}
	for i := 0; i < sib1.numKeys; i++ {
		if !bytes.Equal(sib1.keys[i], sib2.keys[i]) {
			t.Fatalf("the two instances have different keys")
		}
	}
	trapdoors1 := sib1.trapdoorFunc("test")
	trapdoors2 := sib2.trapdoorFunc("test")
	if sib1.numKeys != len(trapdoors1) || sib2.numKeys != len(trapdoors2) {
		t.Fatalf("incorrect number of trapdoor functions")
	}
	for i := 0; i < sib1.numKeys; i++ {
		if !bytes.Equal(trapdoors1[i], trapdoors2[i]) {
			t.Fatalf("the two instances have different trapdoor functions")
		}
	}
	trapdoors1dup := sib1.trapdoorFunc("test")
	for i := 0; i < sib1.numKeys; i++ {
		if !bytes.Equal(trapdoors1[i], trapdoors1dup[i]) {
			t.Fatalf("trapdoor functions not deterministic")
		}
	}
}

// Helper function that checks if a word is contained in the bloom filter.
func bfContainsWord(bf bitarray.BitArray, sib *SecureIndexBuilder, docID int, word string) bool {
	trapdoors := sib.trapdoorFunc(word)
	for _, trapdoor := range trapdoors {
		mac := hmac.New(sib.hash, trapdoor)
		mac.Write([]byte(string(docID)))
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
	salts, err := util.GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	doc, err := ioutil.TempFile("", "bfTest")
	docContent := "This is a test file. It has a pretty random content."
	docWords := strings.Split(docContent, " ")
	docID := 42
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
	bf1, count := sib.buildBloomFilter(docID, doc)
	// Rewinds the file again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf2, _ := sib.buildBloomFilter(docID, doc)
	// Rewinds the file yet again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildBloomFilter")
	}
	bf3, _ := sib.buildBloomFilter(docID+1, doc)
	if !bf1.Equals(bf2) {
		t.Fatalf("the two bloom filters are different.  `buildBloomFilter` is likely non-deterministic")
	}
	if bf1.Equals(bf3) {
		t.Fatalf("the same document with different ids produces the same bloom filter")
	}
	if count != len(docWords)-1 {
		t.Fatalf("the number of unique words is not correct")
	}
	for _, word := range docWords {
		if !bfContainsWord(bf1, sib, docID, word) {
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
	salts, err := util.GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	bf := bitarray.NewSparseBitArray()
	sib.blindBloomFilter(bf, 1000000)
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
	salts, err := util.GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error in generating the salts")
	}
	sib := CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	doc, err := ioutil.TempFile("", "indexTest")
	docContent := "This is a test file. It has a pretty random content."
	docWords := strings.Split(docContent, " ")
	docID := 42
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
	index1 := sib.BuildSecureIndex(docID, doc, len(docContent))
	// Rewinds the file again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildSecureIndex")
	}
	index2 := sib.BuildSecureIndex(docID, doc, len(docContent))
	// Rewinds the file yet again
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestBuildSecureIndex")
	}
	index3 := sib.BuildSecureIndex(docID+1, doc, len(docContent))
	if index1.BloomFilter.Equals(index2.BloomFilter) {
		t.Fatalf("the two indexes for the same document are the same.  They are not likely blinded")
	}
	if index1.BloomFilter.Equals(index3.BloomFilter) {
		t.Fatalf("the same document with different ids produces the same bloom filter")
	}
	if index1.DocID != docID || index3.DocID != docID+1 {
		t.Fatalf("the document ID in the index is not set up correctly")
	}
	if index1.Size != size {
		t.Fatalf("the size in the index is not set up correctly")
	}
	for _, word := range docWords {
		if !bfContainsWord(index1.BloomFilter, sib, docID, word) {
			t.Fatalf("one or more of the words is not present in the index")
		}
	}
}
