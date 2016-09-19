package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/keybase/kbfs/libkbfs"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/crypto/nacl/secretbox"
)

// The length of the overhead added to padding.
const padPrefixLength = 4
const docIDVersionLength = 8
const docIDNonceLength = 24
const docIDPrefixLength = docIDVersionLength + docIDNonceLength

// pathnameToDocID encrypts a `pathname` to a document ID using `key`.
// NOTE: Instead of using random nonce and padding, we need to use deterministic
// ones, because we want the encryptions of the same pathname to always yield the
// same result.
func pathnameToDocID(keyGen libkbfs.KeyGen, pathname string, key [32]byte) (sserver1.DocumentID, error) {
	var nonce [docIDNonceLength]byte
	cksum := sha256.Sum256([]byte(pathname))
	copy(nonce[:], cksum[0:docIDNonceLength])

	paddedPathname, err := padPathname(pathname)
	if err != nil {
		return sserver1.DocumentID(""), err
	}

	sealedBox := secretbox.Seal(nil, paddedPathname, &nonce, &key)

	var version [docIDVersionLength]byte
	versionBuf := bytes.NewBuffer(version[:])

	if err := binary.Write(versionBuf, binary.LittleEndian, int64(keyGen)); err != nil {
		return sserver1.DocumentID(""), err
	}

	docIDRaw := append(append(version[:], nonce[:]...), sealedBox...)

	return sserver1.DocumentID(base64.RawURLEncoding.EncodeToString(docIDRaw)), nil
}

// docIDToPathname decrypts a `docID` to get the actual pathname by using the
// `keys`.
func docIDToPathname(docID sserver1.DocumentID, keys [][32]byte) (string, error) {
	docIDRaw, err := base64.RawURLEncoding.DecodeString(docID.String())
	if err != nil {
		return "", err
	}

	var keyGen int64
	versionBuf := bytes.NewBuffer(docIDRaw[0:docIDVersionLength])
	if err := binary.Read(versionBuf, binary.LittleEndian, &keyGen); err != nil {
		return "", err
	}
	key := keys[keyGen]

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

	if !strings.HasPrefix(absTargpath, absBasepath+string(filepath.Separator)) {
		return "", errors.New("target path not within base path")
	}

	relPath, err := filepath.Rel(absBasepath, absTargpath)
	if err != nil {
		return "", err
	}
	return relPath, nil
}

// getTlfIDAndKeyGen gets the TLF ID and the latest key generation of a
// directory.  Returns an error if TLF ID or the latest key generation cannot be
// acquired for that directory.
func getTlfIDAndKeyGen(directory string) (sserver1.FolderID, libkbfs.KeyGen, error) {
	statusJSON, err := ioutil.ReadFile(filepath.Join(directory, ".kbfs_status"))
	if err != nil {
		return sserver1.FolderID(""), 0, err
	}
	var folderStatus libkbfs.FolderBranchStatus
	err = json.Unmarshal(statusJSON, &folderStatus)
	if err != nil {
		return sserver1.FolderID(""), 0, err
	}
	return sserver1.FolderID(folderStatus.FolderID), folderStatus.LatestKeyGeneration, nil
}

// fetchMasterSecret returns the master secret of the specific `keyGen` under
// `directory`.
func fetchMasterSecret(directory string, keyGen libkbfs.KeyGen, lenMS int) ([]byte, error) {
	var masterSecret []byte
	f, err := os.OpenFile(filepath.Join(directory, ".search_kbfs_secret_"+strconv.Itoa(int(keyGen))), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)

	if err == nil {
		defer f.Close()
		// Generate a random master secret and write it to file
		masterSecret = make([]byte, lenMS)
		if _, err := rand.Read(masterSecret); err != nil {
			return nil, err
		}

		_, err = f.Write(masterSecret)
		if err != nil {
			return nil, err
		}
	} else if os.IsExist(err) {
		// Read the master secret from file
		masterSecret, err = ioutil.ReadFile(filepath.Join(directory, ".search_kbfs_secret_"+strconv.Itoa(int(keyGen))))
		if err != nil {
			return nil, err
		}
		if len(masterSecret) != lenMS {
			return nil, errors.New("Invalid master secret length")
		}
	} else {
		return nil, err
	}
	return masterSecret, nil
}
