package libsearch

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"strings"
	"unicode"
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

// RandUint64 returns a random 64-bit unsigned integer.
func RandUint64() (uint64, error) {
	i := new(big.Int)
	i.SetUint64(math.MaxUint64)
	i.Add(big.NewInt(1), i)
	num, err := rand.Int(rand.Reader, i)
	return num.Uint64(), err
}

// XorBytes performs an xor operation on the first `len` bytes of the two input
// byte slices and returns the result as a byte slice.  Behavior is undefined if
// one or more of the input slices is shorter than `len`.
// TODO: Probably not needed, delete.
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

// WriteFileAtomic writes `content` to a file with `pathname`.  First writes to
// a temporary file and then performs a rename so that the write is atomic.
func WriteFileAtomic(pathname string, content []byte) error {
	tmpFile, err := ioutil.TempFile("", "tmpFile")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	err = ioutil.WriteFile(tmpFile.Name(), content, 0666)
	if err != nil {
		return err
	}

	err = os.Rename(tmpFile.Name(), pathname)
	return err
}

// NormalizeKeyword normalizes a keyword for adding into the index by converting
// it to lower case and keeping only the alphanumeric characters.
func NormalizeKeyword(keyword string) string {
	lowerKeyword := strings.ToLower(keyword)
	normalizedKeyword := make([]rune, 0, len(lowerKeyword))

	for _, c := range lowerKeyword {
		if unicode.IsDigit(c) || unicode.IsLetter(c) {
			normalizedKeyword = append(normalizedKeyword, c)
		}
	}

	return string(normalizedKeyword)
}
