package server

import (
	"bytes"
	"crypto/sha256"
	"io/ioutil"
	"os"
	"search/util"
	"strconv"
	"testing"
)

// Calculates the master secret for client with `clientNum`, and the given
// `serverKeyHalf`.  This is the helper function to utilize the tests.
func calculateMasterSecret(clientNum int, serverKeyHalf []byte) []byte {
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(clientNum)))
	return util.XorBytes(h.Sum(nil), serverKeyHalf, len(serverKeyHalf))
}

// Tests the `CreateServer` function.  Checks that all the fields in the server
// struct are correctly set up.
func TestCreateServer(t *testing.T) {
	numClients := 5
	lenMS := 8
	lenSalt := 8
	fpRate := 0.000001
	expectedR := 20
	dir, err := ioutil.TempDir("", "serverTest")
	if err != nil {
		t.Errorf("cannot create the temporary test directory for `TestCreateServer`")
	}
	defer os.RemoveAll(dir)
	s := CreateServer(numClients, lenMS, lenSalt, dir, fpRate)
	if numClients != len(s.keyHalves) {
		t.Fatalf("incorrect number of server-side key halves")
	}
	if lenMS != len(s.keyHalves[0]) {
		t.Fatalf("incorrect length of the master secret being generated")
	}
	if lenMS != s.lenMS {
		t.Fatalf("incorrect length of the master secret")
	}
	if expectedR != len(s.salts) {
		t.Fatalf("incorrect number of salts generated")
	}
	if lenSalt != len(s.salts[0]) {
		t.Fatalf("incorrect length of the salts")
	}
	if s.numFiles != uint(0) {
		t.Fatalf("number of files not initialized to zero")
	}
	if dir != s.mountPoint {
		t.Fatalf("server mount point not set up correctly")
	}
	ms := calculateMasterSecret(0, s.keyHalves[0])
	for i := 1; i < numClients; i++ {
		msCpy := calculateMasterSecret(i, s.keyHalves[i])
		if !bytes.Equal(ms, msCpy) {
			t.Fatalf("different master secrets derived from different clients")
		}
	}
}
