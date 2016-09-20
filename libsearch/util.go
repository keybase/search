package libsearch

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"unicode"

	"github.com/keybase/kbfs/libkbfs"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/crypto/nacl/secretbox"
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

// GetNumLeadingZeroes returns the number of leading zeroes in `num` as an
// uint64.  The algorithm is based upon the `__builtin_clz` function in C
// languages.
func GetNumLeadingZeroes(num uint64) uint {
	numZeroes := uint64(64)

	x := num
	var y uint64
	y = x >> 32
	if y != 0 {
		numZeroes -= 32
		x = y
	}
	y = x >> 16
	if y != 0 {
		numZeroes -= 16
		x = y
	}
	y = x >> 8
	if y != 0 {
		numZeroes -= 8
		x = y
	}
	y = x >> 4
	if y != 0 {
		numZeroes -= 4
		x = y
	}

	y = x >> 2
	if y != 0 {
		numZeroes -= 2
		x = y
	}

	y = x >> 1
	if y != 0 {
		numZeroes -= 2
	} else {
		numZeroes -= x
	}

	return uint(numZeroes)
}

// BuildMaskWithLeadingZeroes returns an uint64 with the first `numZeroes` bits
// being '0', and the rest being '1'.
func BuildMaskWithLeadingZeroes(numZeroes uint) uint64 {
	return (^uint64(0)) >> numZeroes
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
	normalizedKeyword := make([]rune, 0, len(keyword))

	for _, c := range keyword {
		if unicode.IsDigit(c) || unicode.IsLetter(c) {
			normalizedKeyword = append(normalizedKeyword, unicode.ToLower(c))
		}
	}

	return string(normalizedKeyword)
}

// The length of the overhead added to padding.
const padPrefixLength = 4
const docIDVersionLength = 8
const docIDNonceLength = 24
const docIDPrefixLength = docIDVersionLength + docIDNonceLength

// PathnameToDocID encrypts a `pathname` to a document ID using `key`.
// NOTE: Instead of using random nonce and padding, we need to use deterministic
// ones, because we want the encryptions of the same pathname to always yield the
// same result.
func PathnameToDocID(keyGen libkbfs.KeyGen, pathname string, key [32]byte) (sserver1.DocumentID, error) {
	var nonce [docIDNonceLength]byte
	cksum := sha256.Sum256([]byte(pathname))
	copy(nonce[:], cksum[0:docIDNonceLength])

	paddedPathname, err := padPathname(pathname)
	if err != nil {
		return sserver1.DocumentID(""), err
	}

	sealedBox := secretbox.Seal(nil, paddedPathname, &nonce, &key)

	versionBuf := new(bytes.Buffer)

	if err := binary.Write(versionBuf, binary.LittleEndian, int64(keyGen)); err != nil {
		return sserver1.DocumentID(""), err
	}

	docIDRaw := append(append(versionBuf.Bytes(), nonce[:]...), sealedBox...)

	return sserver1.DocumentID(base64.RawURLEncoding.EncodeToString(docIDRaw)), nil
}

// DocIDToPathname decrypts a `docID` to get the actual pathname by using the
// `keys`.
func DocIDToPathname(docID sserver1.DocumentID, keys [][32]byte) (string, error) {
	docIDRaw, err := base64.RawURLEncoding.DecodeString(docID.String())
	if err != nil {
		return "", err
	}

	var keyGen int64
	versionBuf := bytes.NewBuffer(docIDRaw[0:docIDVersionLength])
	if err := binary.Read(versionBuf, binary.LittleEndian, &keyGen); err != nil {
		return "", err
	}
	key := keys[keyGen-libkbfs.FirstValidKeyGen]

	var nonce [docIDNonceLength]byte
	copy(nonce[:], docIDRaw[docIDVersionLength:docIDPrefixLength])

	pathnameRaw, ok := secretbox.Open(nil, docIDRaw[docIDPrefixLength:], &nonce, &key)
	if !ok {
		return "", errors.New("invalid document ID")
	}

	return depadPathname(pathnameRaw)
}

// GetKeyGenFromDocID extracts the key generation from the document ID and
// returns it as an int.  Note that `docID` does not need to be a complete
// document ID.  A prefix of a document ID would also work, as the key
// generation is written in the very beginning.
func GetKeyGenFromDocID(docID sserver1.DocumentID) (int, error) {
	docIDRaw, err := base64.RawURLEncoding.DecodeString(docID.String())
	if err != nil {
		return 0, err
	}

	var keyGen int64
	versionBuf := bytes.NewBuffer(docIDRaw[0:docIDVersionLength])
	if err := binary.Read(versionBuf, binary.LittleEndian, &keyGen); err != nil {
		return 0, err
	}

	return int(keyGen), nil
}

// nextPowerOfTwo returns the next power of two that is strictly greater than n.
// Stolen from
// https://github.com/keybase/kbfs/tree/master/libkbfs/crypto_common.go#L357
func nextPowerOfTwo(n uint32) uint32 {
	if n&(n-1) == 0 {
		n++
	}

	n--
	n = n | (n >> 1)
	n = n | (n >> 2)
	n = n | (n >> 4)
	n = n | (n >> 8)
	n = n | (n >> 16)
	n++

	return n
}

// padPathname zero-pads the `pathname` and returns the padded pathname in a
// byte slice.
// NOTE: We use deterministic paddings instead of random ones, because we want
// the encryption to be deterministic.  See the note in the comment section for
// `pathnameToDocID`.
func padPathname(pathname string) ([]byte, error) {
	origLen := uint32(len(pathname))
	paddedLen := nextPowerOfTwo(origLen)

	buf := bytes.NewBuffer(make([]byte, 0, padPrefixLength+paddedLen))

	if err := binary.Write(buf, binary.LittleEndian, origLen); err != nil {
		return nil, err
	}

	buf.WriteString(pathname)

	return buf.Bytes(), nil
}

// depadPathname extracts the pathname from a padded byte slice of
// `paddedPathname` and returns it as a string.
// The string returned is empty iff error is not nil.
func depadPathname(paddedPathname []byte) (string, error) {
	buf := bytes.NewBuffer(paddedPathname)

	var origLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &origLen); err != nil {
		return "", err
	}

	contentEndPos := int(padPrefixLength + origLen)
	if contentEndPos > len(paddedPathname) {
		return "", errors.New("invalid padded padPathname")
	}

	return string(buf.Next(int(origLen))), nil
}
