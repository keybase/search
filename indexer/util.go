package indexer

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateSalts generates `numKeys` salts with length `lenSalt` for the usage
// of `SecureIndexBuilder`.
func GenerateSalts(numKeys int, lenSalt uint) (salts [][]byte) {
	if lenSalt < 8 {
		fmt.Println("Error in generating the salts: lenSalt must be at leat 8")
	}
	salts = make([][]byte, numKeys)
	for i := 0; i < numKeys; i++ {
		salts[i] = make([]byte, lenSalt)
		_, err := rand.Read(salts[i])
		if err != nil {
			fmt.Println("Error in generating the salts: ", err)
			return
		}
	}
	return
}

// Returns a random 64-bit unsigned integer in the range of [0, n).  Panics if
// n <= 0.
func randUint64n(n uint64) uint64 {
	i := new(big.Int)
	i.SetUint64(n)
	num, _ := rand.Int(rand.Reader, i)
	return num.Uint64()
}
