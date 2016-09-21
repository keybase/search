package client

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keybase/client/go/libkb"
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	"github.com/keybase/kbfs/libkbfs"
	"github.com/keybase/search/libsearch"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/net/context"
)

// DirectoryInfo holds necessary information for a KBFS-mounted directory.
type DirectoryInfo struct {
	absDir       string                          // The absolute path of the directory.
	lenMS        int                             // The length of the master secret of the directory.
	tlfID        sserver1.FolderID               // The TLF ID of the directory.
	tlfInfo      sserver1.TlfInfo                // The TLF information of the directory.
	keyGenLock   sync.RWMutex                    // The RWMutex to protect the `keyGen`, `indexer` and `pathnameKeys` variables`.
	keyGen       libkbfs.KeyGen                  // The lastest key generation of this directory.
	indexers     []*libsearch.SecureIndexBuilder // The indexer for the directory.
	pathnameKeys []libsearch.PathnameKeyType     // The key to encrypt and decrypt the pathname to/from document IDs.
}

// Client contains all the necessary information for a KBFS Search Client.
// TODO: Add a lock to protect directoryInfos if adding directories during
// execution is allowed.
type Client struct {
	searchCli      sserver1.SearchServerInterface // The client that talks to the RPC Search Server.
	directoryInfos map[string]*DirectoryInfo      // The map from the directories to the DirectoryInfo's.
}

// HandlerName implements the ConnectionHandler interface.
func (Client) HandlerName() string {
	return "SearchClient"
}

// OnConnect implements the ConnectionHandler interface.
func (c *Client) OnConnect(ctx context.Context, conn *rpc.Connection, _ rpc.GenericClient, server *rpc.Server) error {
	return nil
}

// OnConnectError implements the ConnectionHandler interface.
func (c *Client) OnConnectError(err error, wait time.Duration) {
}

// OnDoCommandError implements the ConnectionHandler interface.
func (c *Client) OnDoCommandError(err error, wait time.Duration) {
}

// OnDisconnected implements the ConnectionHandler interface.
func (c *Client) OnDisconnected(_ context.Context, status rpc.DisconnectStatus) {
}

// ShouldRetry implements the ConnectionHandler interface.
func (c *Client) ShouldRetry(rpcName string, err error) bool {
	return false
}

// ShouldRetryOnConnect implements the ConnectionHandler interface.
func (c *Client) ShouldRetryOnConnect(err error) bool {
	return false
}

// logOutput is a simple log output that prints to the console.
type logOutput struct {
	verbose bool // Whether log outputs should be printed out
}

func (l logOutput) log(ch string, fmts string, args []interface{}) {
	if !l.verbose {
		return
	}
	fmts = fmt.Sprintf("[%s] %s", ch, fmts)
	fmt.Println(fmts, args)
}
func (l logOutput) Info(fmt string, args ...interface{})    { l.log("I", fmt, args) }
func (l logOutput) Error(fmt string, args ...interface{})   { l.log("E", fmt, args) }
func (l logOutput) Debug(fmt string, args ...interface{})   { l.log("D", fmt, args) }
func (l logOutput) Warning(fmt string, args ...interface{}) { l.log("W", fmt, args) }
func (l logOutput) Profile(fmt string, args ...interface{}) { l.log("P", fmt, args) }

func logTags(ctx context.Context) (map[interface{}]string, bool) {
	return nil, false
}

// getKeyIndex is the thread-safe helper function that calculates the index of
// the key to use for building the index or trapdoor word.
func (d *DirectoryInfo) getKeyIndex() int {
	d.keyGenLock.RLock()
	defer d.keyGenLock.RUnlock()
	keyGen := d.keyGen
	if keyGen == libkbfs.PublicKeyGen {
		keyGen = libkbfs.FirstValidKeyGen
	}
	return int(keyGen - libkbfs.FirstValidKeyGen)
}

// getIndexer is the thread-safe getter for a specific indexer with `index`.
func (d *DirectoryInfo) getIndexer(index int) *libsearch.SecureIndexBuilder {
	d.keyGenLock.RLock()
	defer d.keyGenLock.RUnlock()
	return d.indexers[index]
}

// getPathnameKey is the thread-safe getter for a specific pathname key with
// `index`.
func (d *DirectoryInfo) getPathnameKey(index int) libsearch.PathnameKeyType {
	d.keyGenLock.RLock()
	defer d.keyGenLock.RUnlock()
	return d.pathnameKeys[index]
}

// CreateClient creates a new `Client` instance with the parameters and returns
// a pointer the the instance.  Returns an error on any failure.
func CreateClient(ctx context.Context, ipAddr string, port int, directories []string, lenMS, lenSalt int, fpRate float64, numUniqWords uint64, verbose bool) (*Client, error) {
	serverAddr := fmt.Sprintf("%s:%d", ipAddr, port)
	conn := rpc.NewTLSConnection(serverAddr, libsearch.GetRootCerts(serverAddr), libkb.ErrorUnwrapper{}, &Client{}, true, rpc.NewSimpleLogFactory(logOutput{verbose: verbose}, nil), libkb.WrapError, logOutput{verbose: verbose}, logTags)

	searchCli := sserver1.SearchServerClient{Cli: conn.GetClient()}

	return createClientWithClient(ctx, searchCli, directories, lenMS, lenSalt, fpRate, numUniqWords)
}

// createClient creates a new `Client` with a given SearchServerInterface.
// Should only be used internally and for tests.
func createClientWithClient(ctx context.Context, searchCli sserver1.SearchServerInterface, directories []string, lenMS, lenSalt int, fpRate float64, numUniqWords uint64) (*Client, error) {
	directoryInfos := make(map[string]*DirectoryInfo)

	// Initializes the info for each directory.
	for _, directory := range directories {

		absDir, err := filepath.Abs(directory)
		if err != nil {
			return nil, err
		}

		tlfID, keyGen, err := getTlfIDAndKeyGen(absDir)
		if err != nil {
			return nil, err
		}

		tlfInfo, err := searchCli.RegisterTlfIfNotExists(ctx, sserver1.RegisterTlfIfNotExistsArg{TlfID: tlfID, LenSalt: lenSalt, FpRate: fpRate, NumUniqWords: int64(numUniqWords)})
		if err != nil {
			return nil, err
		}

		var indexers []*libsearch.SecureIndexBuilder
		var pathnameKeys []libsearch.PathnameKeyType

		// Sets up the indexers and pathname keys
		if keyGen == libkbfs.PublicKeyGen {
			masterSecret, err := fetchMasterSecret(directory, keyGen, lenMS)
			if err != nil {
				return nil, err
			}
			indexers = make([]*libsearch.SecureIndexBuilder, 1)
			pathnameKeys = make([]libsearch.PathnameKeyType, 1)
			indexers[0] = libsearch.CreateSecureIndexBuilder(sha256.New, masterSecret, tlfInfo.Salts, uint64(tlfInfo.Size))
			copy(pathnameKeys[0][:], masterSecret[0:32])
		} else if keyGen >= libkbfs.FirstValidKeyGen {
			indexers = make([]*libsearch.SecureIndexBuilder, keyGen)
			pathnameKeys = make([]libsearch.PathnameKeyType, keyGen)
			for i := libkbfs.KeyGen(libkbfs.FirstValidKeyGen); i <= keyGen; i++ {
				masterSecret, err := fetchMasterSecret(directory, i, lenMS)
				if err != nil {
					return nil, err
				}
				indexers[i-libkbfs.FirstValidKeyGen] = libsearch.CreateSecureIndexBuilder(sha256.New, masterSecret, tlfInfo.Salts, uint64(tlfInfo.Size))
				copy(pathnameKeys[i-libkbfs.FirstValidKeyGen][:], masterSecret[0:32])
			}
		} else {
			return nil, errors.New("invalid key generation")
		}

		directoryInfos[absDir] = &DirectoryInfo{
			absDir:       absDir,
			lenMS:        lenMS,
			tlfID:        tlfID,
			tlfInfo:      tlfInfo,
			keyGen:       keyGen,
			indexers:     indexers,
			pathnameKeys: pathnameKeys,
		}
	}

	cli := &Client{
		searchCli:      searchCli,
		directoryInfos: directoryInfos,
	}

	go cli.periodicKeyGenCheck()

	return cli, nil
}

// getDirectoryInfo is a helper function that gets the DirectoryInfo for
// `directory`.  Returns an error if the `directory` provided is invalid or
// not present in the current client.
func (c *Client) getDirectoryInfo(directory string) (*DirectoryInfo, error) {
	absDir, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}

	dirInfo, ok := c.directoryInfos[absDir]
	if !ok {
		return nil, errors.New("invalid directory name provided")
	}

	return dirInfo, nil
}

// AddFile indexes a file in `directory` with the given `pathname` and writes
// the index to the server.
func (c *Client) AddFile(directory, pathname string) error {
	dirInfo, err := c.getDirectoryInfo(directory)
	if err != nil {
		return err
	}

	relPath, err := relPathStrict(dirInfo.absDir, pathname)
	if err != nil {
		return err
	}

	keyIndex := dirInfo.getKeyIndex()

	docID, err := libsearch.PathnameToDocID(dirInfo.keyGen, relPath, dirInfo.getPathnameKey(keyIndex))
	if err != nil {
		return err
	}

	file, err := os.Open(pathname)
	if err != nil {
		return err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	secIndex, err := dirInfo.getIndexer(keyIndex).BuildSecureIndex(file, fileInfo.Size())
	if err != nil {
		return err
	}

	secIndexBytes, err := secIndex.MarshalBinary()
	if err != nil {
		return err
	}

	return c.searchCli.WriteIndex(context.TODO(), sserver1.WriteIndexArg{TlfID: dirInfo.tlfID, SecureIndex: secIndexBytes, DocID: docID})
}

// RenameFile is called when a file in `directory` has been renamed from `orig`
// to `curr`.  This will rename their corresponding indexes.  Returns an error
// if the filenames are invalid.
func (c *Client) RenameFile(directory string, orig, curr string) error {
	dirInfo, err := c.getDirectoryInfo(directory)
	if err != nil {
		return err
	}

	relOrig, err := relPathStrict(dirInfo.absDir, orig)
	if err != nil {
		return err
	}

	relCurr, err := relPathStrict(dirInfo.absDir, curr)
	if err != nil {
		return err
	}

	keyIndex := dirInfo.getKeyIndex()

	origDocID, err := libsearch.PathnameToDocID(dirInfo.keyGen, relOrig, dirInfo.getPathnameKey(keyIndex))
	if err != nil {
		return err
	}

	currDocID, err := libsearch.PathnameToDocID(dirInfo.keyGen, relCurr, dirInfo.getPathnameKey(keyIndex))
	if err != nil {
		return err
	}

	return c.searchCli.RenameIndex(context.TODO(), sserver1.RenameIndexArg{TlfID: dirInfo.tlfID, Orig: origDocID, Curr: currDocID})
}

// DeleteFile deletes the index on the server associated with `pathname` in
// `directory`.
func (c *Client) DeleteFile(directory string, pathname string) error {
	dirInfo, err := c.getDirectoryInfo(directory)
	if err != nil {
		return err
	}

	relPath, err := relPathStrict(dirInfo.absDir, pathname)
	if err != nil {
		return err
	}

	docID, err := libsearch.PathnameToDocID(dirInfo.keyGen, relPath, dirInfo.getPathnameKey(dirInfo.getKeyIndex()))
	if err != nil {
		return err
	}

	return c.searchCli.DeleteIndex(context.Background(), sserver1.DeleteIndexArg{TlfID: dirInfo.tlfID, DocID: docID})
}

// SearchWord performs a search request on the search server and returns the
// list of filenames in `directory` possibly containing the `word`.
// NOTE: False positives are possible.
func (c *Client) SearchWord(directory, word string) ([]string, error) {
	dirInfo, err := c.getDirectoryInfo(directory)
	if err != nil {
		return nil, err
	}

	keyGens, err := c.searchCli.GetKeyGens(context.TODO(), dirInfo.tlfID)
	if err != nil {
		return nil, err
	}

	trapdoorMap := make(map[string]sserver1.Trapdoor)
	for _, keyGen := range keyGens {
		origKeyGen := keyGen
		if keyGen == int(libkbfs.PublicKeyGen) {
			keyGen = libkbfs.FirstValidKeyGen
		}
		if keyGen < 0 || keyGen-libkbfs.FirstValidKeyGen > dirInfo.getKeyIndex() {
			continue
		}
		indexer := dirInfo.getIndexer(keyGen - libkbfs.FirstValidKeyGen)
		trapdoorMap[strconv.Itoa(origKeyGen)] = sserver1.Trapdoor{Codeword: indexer.ComputeTrapdoors(word), KeyGen: origKeyGen}
	}

	documents, err := c.searchCli.SearchWord(context.TODO(), sserver1.SearchWordArg{TlfID: dirInfo.tlfID, Trapdoors: trapdoorMap})
	if err != nil {
		return nil, err
	}

	filenames := make([]string, len(documents))
	for i, docID := range documents {
		dirInfo.keyGenLock.RLock()
		pathname, err := libsearch.DocIDToPathname(docID, dirInfo.pathnameKeys)
		dirInfo.keyGenLock.RUnlock()
		if err != nil {
			return nil, err
		}
		filenames[i] = filepath.Join(dirInfo.absDir, pathname)
	}

	sort.Strings(filenames)
	return filenames, nil
}

// SearchWordStrict is similar to `SearchWord`, but it uses a `grep` command to
// eliminate the possible false positives.  The `word` must have an exact match
// (cases ignored) in the file.
func (c *Client) SearchWordStrict(directory, word string) ([]string, error) {
	files, err := c.SearchWord(directory, word)
	if err != nil {
		return nil, err
	}
	args := make([]string, len(files)+2)
	args[0] = "-ilZw"
	args[1] = word
	copy(args[2:], files[:])
	output, _ := exec.Command("grep", args...).Output()
	filenames := strings.Split(string(output), "\x00")
	filenames = filenames[:len(filenames)-1]

	sort.Strings(filenames)

	return filenames, nil
}

// updateKeys fetches the new master secrets from `currKeyGen` to `newKeyGen`.
func (c *Client) updateKeys(dirInfo *DirectoryInfo, newKeyGen, currKeyGen libkbfs.KeyGen) {
	dirInfo.keyGenLock.Lock()
	defer dirInfo.keyGenLock.Unlock()
	for keyGen := currKeyGen + 1; keyGen <= newKeyGen; keyGen++ {
		masterSecret, err := fetchMasterSecret(dirInfo.absDir, keyGen, dirInfo.lenMS)
		if err != nil {
			return
		}
		dirInfo.indexers = append(dirInfo.indexers, libsearch.CreateSecureIndexBuilder(sha256.New, masterSecret, dirInfo.tlfInfo.Salts, uint64(dirInfo.tlfInfo.Size)))
		var pathnameKey [32]byte
		copy(pathnameKey[:], masterSecret[0:32])
		dirInfo.pathnameKeys = append(dirInfo.pathnameKeys, pathnameKey)
		dirInfo.keyGen = keyGen
	}
}

// periodicKeyGenCheck checks every hour and updates the master secrets if a
// rekey has occurred.
func (c *Client) periodicKeyGenCheck() {
	for {
		time.Sleep(time.Hour)
		for _, dirInfo := range c.directoryInfos {
			_, newKeyGen, err := getTlfIDAndKeyGen(dirInfo.absDir)
			if err != nil {
				continue
			}
			dirInfo.keyGenLock.RLock()
			currKeyGen := dirInfo.keyGen
			dirInfo.keyGenLock.RUnlock()
			if newKeyGen > currKeyGen {
				c.updateKeys(dirInfo, newKeyGen, currKeyGen)
			}
		}
	}
}
