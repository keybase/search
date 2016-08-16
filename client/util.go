package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"path/filepath"
	"strings"

	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/crypto/nacl/secretbox"
)

// The length of the overhead added to padding.
const padPrefixLength = 4
const docIDVersionLength = 2
const docIDNonceLength = 24
const docIDPrefixLength = docIDVersionLength + docIDNonceLength

// pathnameToDocID encrypts a `pathname` to a document ID using `key`.
func pathnameToDocID(pathname string, key [32]byte) (sserver1.DocumentID, error) {
	var nonce [docIDNonceLength]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return sserver1.DocumentID(""), err
	}

	paddedPathname, err := padPathname(pathname)
	if err != nil {
		return sserver1.DocumentID(""), err
	}

	sealedBox := secretbox.Seal(nil, paddedPathname, &nonce, &key)

	var version [docIDVersionLength]byte
	// TODO: initialize version number

	docIDRaw := append(append(version[:], nonce[:]...), sealedBox...)

	return sserver1.DocumentID(base64.RawURLEncoding.EncodeToString(docIDRaw)), nil
}

// docIDToPathname decrypts a `docID` to get the actual pathname by using `key`.
func docIDToPathname(docID sserver1.DocumentID, key [32]byte) (string, error) {
	docIDRaw, err := base64.RawURLEncoding.DecodeString(docID.String())
	if err != nil {
		return "", err
	}
	var nonce [docIDNonceLength]byte
	copy(nonce[:], docIDRaw[docIDVersionLength:docIDPrefixLength])
	pathnameRaw, ok := secretbox.Open(nil, docIDRaw[docIDPrefixLength:], &nonce, &key)
	if !ok {
		return "", errors.New("invalid document ID")
	}

	return depadPathname(pathnameRaw)
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

// padPathname pads the `pathname` and returns the padded pathname in a byte
// slice.
func padPathname(pathname string) ([]byte, error) {
	origLen := uint32(len(pathname))
	paddedLen := nextPowerOfTwo(origLen)
	padLen := int64(paddedLen - origLen)

	buf := bytes.NewBuffer(make([]byte, 0, padPrefixLength+paddedLen))

	if err := binary.Write(buf, binary.LittleEndian, origLen); err != nil {
		return nil, err
	}

	buf.WriteString(pathname)

	n, err := io.CopyN(buf, rand.Reader, padLen)
	if err != nil {
		return nil, err
	}
	if n != padLen {
		return nil, errors.New("short crypto rand read")
	}

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

// relPathStrict returns a relative path for `targpath` from `basepath`.  Unlike
// the `filepath.Rel` function, this function returns an error if `targpath` is
// not within `basepath`.
func relPathStrict(basepath, targpath string) (string, error) {
	absTargpath, err := filepath.Abs(targpath)
	if err != nil {
		return "", err
	}

	absBasepath, err := filepath.Abs(basepath)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(absTargpath, absBasepath) {
		return "", errors.New("target path not within base path")
	}

	relPath, err := filepath.Rel(absBasepath, absTargpath)
	if err != nil {
		return "", err
	}
	return relPath, nil
}
