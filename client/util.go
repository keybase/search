package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/keybase/kbfs/libkbfs"
	sserver1 "github.com/keybase/search/protocol/sserver"
)

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
