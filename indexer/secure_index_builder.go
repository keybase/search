package indexer

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"os"
	"search/index"
	"search/util"

	"github.com/jxguan/go-datastructures/bitarray"
)

// SecureIndexBuilder stores the essential information needed to build the
// indexes for the documents.
type SecureIndexBuilder struct {
	keys         [][]byte              // The keys for the PRFs. Derived from the masterSecret and the salts.
	hash         func() hash.Hash      // The hash function to be used for HMAC.
	trapdoorFunc func(string) [][]byte // The trapdoor function for the words
	size         uint64                // The size of each index, i.e. the number of buckets in the bloom filter.  Smaller size will lead to higher false positive rates.
}

// CreateSecureIndexBuilder instantiates a `SecureIndexBuilder`.  Sets up the
// hash function, and derives the keys from the master secret and salts by using
// PBKDF2.  Finally, sets up the trapdoor function for the words.
func CreateSecureIndexBuilder(h func() hash.Hash, masterSecret []byte, salts [][]byte, size uint64) *SecureIndexBuilder {
	sib := new(SecureIndexBuilder)
	sib.keys = make([][]byte, len(salts))
	for index, salt := range salts {
		sib.keys[index] = pbkdf2.Key(masterSecret, salt, 4096, 32, sha256.New)
	}
	sib.hash = h
	sib.size = size
	sib.trapdoorFunc = func(word string) [][]byte {
		trapdoors := make([][]byte, len(salts))
		for i := 0; i < len(salts); i++ {
			mac := hmac.New(sib.hash, sib.keys[i])
			mac.Write([]byte(word))
			trapdoors[i] = mac.Sum(nil)
		}
		return trapdoors
	}
	return sib
}

// Builds the bloom filter for the document and returns the result in a sparse
// bit array and the number of unique words in the document.  The result should
// not be directly used as the index, as obfuscation need to be added to the
// bloom filter.
func (sib *SecureIndexBuilder) buildBloomFilter(docID int, document *os.File) (bitarray.BitArray, int) {
	scanner := bufio.NewScanner(document)
	scanner.Split(bufio.ScanWords)
	bf := bitarray.NewSparseBitArray()
	words := make(map[string]bool)
	for scanner.Scan() {
		word := scanner.Text()
		if _, found := words[word]; found {
			continue
		}
		words[word] = true
		trapdoors := sib.trapdoorFunc(word)
		for _, trapdoor := range trapdoors {
			mac := hmac.New(sib.hash, trapdoor)
			mac.Write([]byte(string(docID)))
			codeword, _ := binary.Uvarint(mac.Sum(nil))
			bf.SetBit(codeword % sib.size)
		}
	}
	return bf, len(words)
}

// Blinds the bloom filter by setting random bits to be on for `numIterations`
// iterations.
func (sib *SecureIndexBuilder) blindBloomFilter(bf bitarray.BitArray, numIterations int) {
	for i := 0; i < numIterations; i++ {
		bf.SetBit(util.RandUint64n(sib.size))
	}
}

// BuildSecureIndex builds the index for `document` with `docID` and an
// *encrypted* length of `fileLen`.
func (sib *SecureIndexBuilder) BuildSecureIndex(docID int, document *os.File, fileLen int) index.SecureIndex {
	bf, numUniqWords := sib.buildBloomFilter(docID, document)
	sib.blindBloomFilter(bf, (fileLen-numUniqWords)*len(sib.keys))
	return index.SecureIndex{BloomFilter: bf, DocID: docID, Size: sib.size, Hash: sib.hash}
}

// ComputeTrapdoors computes the trapdoor values for `word`.  This acts as the
// public getter for the trapdoorFunc field of SecureIndexBUilder.
func (sib *SecureIndexBuilder) ComputeTrapdoors(word string) [][]byte {
	return sib.trapdoorFunc(word)
}
