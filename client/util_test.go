package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/keybase/kbfs/libkbfs"
)

// testRelPathStrictHelper checks that the call to `relPathStrict` with
// `basepath` and `targpath` yields the `expected` result and that the error
// status matches the `isError` boolean.
func testRelPathStrictHelper(t *testing.T, basepath, targpath, expected string, isError bool) {
	actual, err := relPathStrict(basepath, targpath)
	if isError {
		if err == nil {
			t.Fatalf("expecting error for basepath \"%s\" and targpath \"%s\", no error returned", basepath, targpath)
		}
	} else if err != nil {
		t.Fatalf("unexpected error for basepath \"%s\" and targpath \"%s\"", basepath, targpath)
	} else if actual != expected {
		t.Fatalf("incorrect relative path for basepath \"%s\" and targpath \"%s\", expected \"%s\", actual \"%s\"", basepath, targpath, expected, actual)
	}
}

// TestRelPathStrict tests multiple edge cases for the `relPathStrict` function.
func TestRelPathStrict(t *testing.T) {
	testRelPathStrictHelper(t, "test", "test/valid", "valid", false)
	testRelPathStrictHelper(t, "test", "test/multiple/folders/valid", "multiple/folders/valid", false)
	testRelPathStrictHelper(t, "test", "test/../dotdotinvalid", "", true)
	testRelPathStrictHelper(t, "test", "test/test/../../dotdotinvalid", "", true)
	testRelPathStrictHelper(t, "test", "test/../test/dotdotvalid", "dotdotvalid", false)
	testRelPathStrictHelper(t, "/abs", "/abs/valid", "valid", false)
	testRelPathStrictHelper(t, "test", "totallyinvalid", "", true)
	testRelPathStrictHelper(t, "reverse/invalid", "reverse", "", true)
	testRelPathStrictHelper(t, "prefix", "prefixinvalid/invalid", "", true)
	testRelPathStrictHelper(t, "same", "same", "", true)
}

// TestGetTlfIDAndKeyGen tests the `getTlfIDAndKeyGen` function.  Checks that
// the correct TLF ID and latest key generation are retrieved.
func TestGetTlfIDAndKeyGen(t *testing.T) {
	expectedTlfID := "randomrandomfolderID"
	expectedKeyGen := libkbfs.KeyGen(42)

	tempDir, err := ioutil.TempDir("", "TestTlfID")
	if err != nil {
		t.Fatalf("error when creating the test directory: %s", err)
	}
	defer os.RemoveAll(tempDir)

	var status libkbfs.FolderBranchStatus
	status.FolderID = expectedTlfID
	status.LatestKeyGeneration = expectedKeyGen
	bytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		t.Fatalf("error when writing the TLF status: %s", err)
	}
	err = ioutil.WriteFile(filepath.Join(tempDir, ".kbfs_status"), bytes, 0666)
	if err != nil {
		t.Fatalf("error when writing the TLF status: %s", err)
	}

	actualTlfID, actualKeyGen, err := getTlfIDAndKeyGen(tempDir)
	if err != nil {
		t.Fatalf("error when reading the TLF ID: %s", err)
	}
	if actualTlfID.String() != expectedTlfID {
		t.Fatalf("unmatching TLF IDs: expected \"%s\" actual \"%s\"", expectedTlfID, actualTlfID)
	}
	if actualKeyGen != expectedKeyGen {
		t.Fatalf("unmatching key generations: expected \"%d\" actual \"%d\"", expectedKeyGen, actualKeyGen)
	}
}

// TestFetchMasterSecret tests the `fetchMasterSecret` function.  Checks that
// the master secrets are correctly generated and fetched, and that errors are
// properly reported.
func TestFetchMasterSecret(t *testing.T) {
	dir, err := ioutil.TempDir("", "fetchMS")
	if err != nil {
		t.Fatalf("error when creating test directory: %s", err)
	}
	defer os.RemoveAll(dir)

	ms1, err := fetchMasterSecret(dir, 1, 256)
	if err != nil {
		t.Fatalf("error when generating master secret: %s", err)
	}
	ms2, err := fetchMasterSecret(dir, 2, 128)
	if err != nil {
		t.Fatalf("error when generating master secret: %s", err)
	}
	if bytes.Equal(ms1, ms2) {
		t.Fatalf("master secrets not randomly generated")
	}

	fetchedMs1, err := fetchMasterSecret(dir, 1, 256)
	if err != nil {
		t.Fatalf("error when fetching master secret: %s", err)
	}
	if !bytes.Equal(ms1, fetchedMs1) {
		t.Fatalf("master secret changed after fetching")
	}

	fetchedMs2, err := fetchMasterSecret(dir, 2, 128)
	if err != nil {
		t.Fatalf("error when fetching master secret: %s", err)
	}
	if !bytes.Equal(ms2, fetchedMs2) {
		t.Fatalf("master secret changed after fetching")
	}

	_, err = fetchMasterSecret(dir, 1, 128)
	if err == nil || err.Error() != "Invalid master secret length" {
		t.Fatalf("error not reported when master secret has unmatching length")
	}
}
