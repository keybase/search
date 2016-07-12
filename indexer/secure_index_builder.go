package indexer

import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

// SecureIndexBuilder stores the essential information needed to build the
// indexes for the documents.
type SecureIndexBuilder struct {
	numKeys uint     // The number of keys.  This is also the number of PRFs.
	keys    [][]byte // The keys for the PRFs. Derived from the masterSecret
	// and the salts.
	hash hash.Hash // The hash function to be used for Hmac.
}

// CreateSecureIndexBuilder instantiates a `secureIndexBuilder`.  Sets up the
// hash function, and derives the keys from the master secret and salts by using
// PBKDF2.
func CreateSecureIndexBuilder(h func() hash.Hash, masterSecret []byte, salts [][]byte) *SecureIndexBuilder {
	sIB := new(SecureIndexBuilder)
	sIB.keys = make([][]byte, len(salts))
	for index, salt := range salts {
		sIB.keys[index] = pbkdf2.Key(masterSecret, salt, 4096, 32, sha256.New)
	}
	sIB.hash = h()
	sIB.numKeys = uint(len(salts))
	return sIB
}

/*
func BuildIndex(documentId, key [][]byte) {
	mac := hmac.New(sha256.New, key[0])
	mac.Write([]"test")
	fmt.Println(mac.Sum(nil))
}*/
