package client

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/crypto/nacl/secretbox"
)

// pathnameToDocID encrypts a `pathname` to a document ID using `key`.
func pathnameToDocID(pathname string, key *[32]byte) (sserver1.DocumentID, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return sserver1.DocumentID(""), err
	}

	sealedBox := secretbox.Seal(nil, []byte(pathname), &nonce, key)

	docIDRaw := append(nonce[:], sealedBox...)

	return sserver1.DocumentID(base64.URLEncoding.EncodeToString(docIDRaw)), nil
}

// docIDToPathname decrypts a `docID` to get the actual pathname by using `key`.
func docIDToPathname(docID sserver1.DocumentID, key *[32]byte) (string, error) {
	docIDRaw, err := base64.URLEncoding.DecodeString(docID.String())
	if err != nil {
		return "", err
	}
	var nonce [24]byte
	copy(nonce[:], docIDRaw[0:24])
	pathnameRaw, ok := secretbox.Open(nil, docIDRaw[24:], &nonce, key)
	if !ok {
		return "", errors.New("invalid document ID")
	}

	return string(pathnameRaw), nil
}
