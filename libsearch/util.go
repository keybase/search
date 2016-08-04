package libsearch

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
)

// GenerateSalts generates `numKeys` salts with length `lenSalt`.  Returns an
// error if the salts cannot be properly generated.
func GenerateSalts(numKeys, lenSalt int) (salts [][]byte, err error) {
	salts = make([][]byte, numKeys)
	for i := 0; i < numKeys; i++ {
		salts[i] = make([]byte, lenSalt)
		_, err = rand.Read(salts[i])
		if err != nil {
			return
		}
	}
	return
}

// RandUint64n returns a random 64-bit unsigned integer in the range of [0, n).
// Panics if n <= 0.
func RandUint64n(n uint64) (uint64, error) {
	i := new(big.Int)
	i.SetUint64(n)
	num, err := rand.Int(rand.Reader, i)
	return num.Uint64(), err
}

// XorBytes performs an xor operation on the first `len` bytes of the two input
// byte slices and returns the result as a byte slice.  Behavior is undefined if
// one or more of the input slices is shorter than `len`.
func XorBytes(one, two []byte, len int) []byte {
	result := make([]byte, len)
	for i := 0; i < len; i++ {
		result[i] = one[i] ^ two[i]
	}
	return result
}

// Reads an int from the input byte slice.
func readInt(input []byte) (int, error) {
	num, numBytes := binary.Varint(input)
	if numBytes <= 0 {
		return 0, errors.New("cannot read the int")
	}
	return int(num), nil
}
