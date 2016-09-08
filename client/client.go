package client

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keybase/client/go/libkb"
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	"github.com/keybase/search/libsearch"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/net/context"
)

// PathnameKeyType is the type of key used to encrypt the pathnames into
// document IDs, and vice versa.
type PathnameKeyType [32]byte

// DirectoryInfo holds necessary information for a KBFS-mounted directory.
type DirectoryInfo struct {
	tlfID       sserver1.FolderID             // The TLF ID of the directory.
	indexer     *libsearch.SecureIndexBuilder // The indexer for the directory.
	pathnameKey PathnameKeyType               // The key to encrypt and decrypt the pathname to/from document IDs.
}

// Client contains all the necessary information for a KBFS Search Client.
type Client struct {
	searchCli      sserver1.SearchServerInterface // The client that talks to the RPC Search Server.
	directoryInfos map[string]DirectoryInfo       // The map from the directories to the DirectoryInfo's.
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

// CreateClient creates a new `Client` instance with the parameters and returns
// a pointer the the instance.  Returns an error on any failure.
func CreateClient(ctx context.Context, ipAddr string, port int, masterSecrets [][]byte, directories []string, verbose bool) (*Client, error) {
	// TODO: Switch to TLS connection.
	uri, err := rpc.ParseFMPURI(fmt.Sprintf("fmprpc://%s:%d", ipAddr, port))
	if err != nil {
		return nil, err
	}

	conn := rpc.NewConnectionWithTransport(&Client{}, rpc.NewConnectionTransport(uri, rpc.NewSimpleLogFactory(logOutput{verbose: verbose}, nil), libkb.WrapError), libkb.ErrorUnwrapper{}, true, libkb.WrapError, logOutput{verbose: verbose}, logTags)

	searchCli := sserver1.SearchServerClient{Cli: conn.GetClient()}

	return createClientWithClient(ctx, searchCli, masterSecrets, directories)
}

// createClient creates a new `Client` with a given SearchServerInterface.
// Should only be used internally and for tests.
func createClientWithClient(ctx context.Context, searchCli sserver1.SearchServerInterface, masterSecrets [][]byte, directories []string) (*Client, error) {
	salts, err := searchCli.GetSalts(ctx)
	if err != nil {
		return nil, err
	}

	size, err := searchCli.GetSize(ctx)
	if err != nil {
		return nil, err
	}

	directoryInfos := make(map[string]DirectoryInfo)

	for i, directory := range directories {
		indexer := libsearch.CreateSecureIndexBuilder(sha256.New, masterSecrets[i], salts, uint64(size))

		var pathnameKey [32]byte
		copy(pathnameKey[:], masterSecrets[i][0:32])

		absDir, err := filepath.Abs(directory)
		if err != nil {
			return nil, err
		}

		tlfID, err := getTlfID(absDir)
		if err != nil {
			return nil, err
		}

		dirInfo := DirectoryInfo{
			tlfID:       tlfID,
			indexer:     indexer,
			pathnameKey: pathnameKey,
		}

		directoryInfos[absDir] = dirInfo
	}

	cli := &Client{
		searchCli:      searchCli,
		directoryInfos: directoryInfos,
	}

	return cli, nil
}

// AddFile indexes a file with the given `pathname` and writes the index to the
// server.
func (c *Client) AddFile(directory, pathname string) error {
	absDir, err := filepath.Abs(directory)
	if err != nil {
		return err
	}

	if _, ok := c.directoryInfos[absDir]; !ok {
		return errors.New("invalid directory name provided")
	}

	relPath, err := relPathStrict(absDir, pathname)
	if err != nil {
		return err
	}

	docID, err := pathnameToDocID(relPath, c.directoryInfos[absDir].pathnameKey)
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

	secIndex, err := c.directoryInfos[absDir].indexer.BuildSecureIndex(file, fileInfo.Size())
	if err != nil {
		return err
	}

	secIndexBytes, err := secIndex.MarshalBinary()
	if err != nil {
		return err
	}

	return c.searchCli.WriteIndex(context.TODO(), sserver1.WriteIndexArg{TlfID: c.directoryInfos[absDir].tlfID, SecureIndex: secIndexBytes, DocID: docID})
}

// RenameFile is called when a file has been renamed from `orig` to `curr`.
// This will rename their corresponding indexes.  Returns an error if the
// filenames are invalid.
func (c *Client) RenameFile(directory string, orig, curr string) error {
	absDir, err := filepath.Abs(directory)
	if err != nil {
		return err
	}

	if _, ok := c.directoryInfos[absDir]; !ok {
		return errors.New("invalid directory name provided")
	}

	relOrig, err := relPathStrict(absDir, orig)
	if err != nil {
		return err
	}

	relCurr, err := relPathStrict(absDir, curr)
	if err != nil {
		return err
	}

	origDocID, err := pathnameToDocID(relOrig, c.directoryInfos[absDir].pathnameKey)
	if err != nil {
		return err
	}

	currDocID, err := pathnameToDocID(relCurr, c.directoryInfos[absDir].pathnameKey)
	if err != nil {
		return err
	}

	return c.searchCli.RenameIndex(context.TODO(), sserver1.RenameIndexArg{TlfID: c.directoryInfos[absDir].tlfID, Orig: origDocID, Curr: currDocID})
}

// DeleteFile deletes the index on the server associated with `pathname`.
func (c *Client) DeleteFile(directory string, pathname string) error {
	absDir, err := filepath.Abs(directory)
	if err != nil {
		return err
	}

	if _, ok := c.directoryInfos[absDir]; !ok {
		return errors.New("invalid directory name provided")
	}

	relPath, err := relPathStrict(absDir, pathname)
	if err != nil {
		return err
	}

	docID, err := pathnameToDocID(relPath, c.directoryInfos[absDir].pathnameKey)
	if err != nil {
		return err
	}

	return c.searchCli.DeleteIndex(context.Background(), sserver1.DeleteIndexArg{TlfID: c.directoryInfos[absDir].tlfID, DocID: docID})
}

// SearchWord performs a search request on the search server and returns the
// list of filenames possibly containing the word.
// NOTE: False positives are possible.
func (c *Client) SearchWord(directory, word string) ([]string, error) {
	absDir, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}

	if _, ok := c.directoryInfos[absDir]; !ok {
		return nil, errors.New("invalid directory name provided")
	}

	trapdoors := c.directoryInfos[absDir].indexer.ComputeTrapdoors(word)
	documents, err := c.searchCli.SearchWord(context.TODO(), sserver1.SearchWordArg{TlfID: c.directoryInfos[absDir].tlfID, Trapdoors: trapdoors})
	if err != nil {
		return nil, err
	}

	filenames := make([]string, len(documents))
	for i, docID := range documents {
		pathname, err := docIDToPathname(docID, c.directoryInfos[absDir].pathnameKey)
		if err != nil {
			return nil, err
		}
		filenames[i] = filepath.Join(absDir, pathname)
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
