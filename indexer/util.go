package indexer

import (
	"crypto/rand"
	"fmt"
)

// GenerateSalts generates `numKeys` salts with length `lenSalt` for the usage
// of `SecureIndexBuilder`.
func GenerateSalts(numKeys, lenSalt uint) (salts [][]byte) {
	if lenSalt < 8 {
		fmt.Println("Error in generating the salts: lenSalt must be at leat 8")
	}
	salts = make([][]byte, numKeys)
	for i := uint(0); i < numKeys; i++ {
		salts[i] = make([]byte, lenSalt)
		_, err := rand.Read(salts[i])
		if err != nil {
			fmt.Println("Error in generating the salts: ", err)
			return
		}
	}
	return
}
