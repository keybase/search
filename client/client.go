package client

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	rpc "github.com/keybase/go-framed-msgpack-rpc"
	"github.com/keybase/search/libsearch"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/net/context"
)

// PathnameKeyType is the type of key used to encrypt the pathnames into
// document IDs, and vice versa.
type PathnameKeyType [32]byte

// Client contains all the necessary information for a KBFS Search Client.
type Client struct {
	searchCli   sserver1.SearchServerInterface // The client that talks to the RPC Search Server.
	directory   string                         // The directory where KBFS is mounted.
	indexer     *libsearch.SecureIndexBuilder  // The indexer for the client.
	pathnameKey PathnameKeyType                // The key to encrypt and decrypt the pathnames to/from document IDs.
}

type ClientRPC struct{}

// HandlerName implements the ConnectionHandler interface.
func (ClientRPC) HandlerName() string {
	return "CryptoClient"
}

// OnConnect implements the ConnectionHandler interface.
func (c *ClientRPC) OnConnect(ctx context.Context, conn *rpc.Connection, _ rpc.GenericClient, server *rpc.Server) error {
	return nil
}

// OnConnectError implements the ConnectionHandler interface.
func (c *ClientRPC) OnConnectError(err error, wait time.Duration) {
}

// OnDoCommandError implements the ConnectionHandler interface.
func (c *ClientRPC) OnDoCommandError(err error, wait time.Duration) {
}

// OnDisconnected implements the ConnectionHandler interface.
func (c *ClientRPC) OnDisconnected(_ context.Context, status rpc.DisconnectStatus) {
}

// ShouldRetry implements the ConnectionHandler interface.
func (c *ClientRPC) ShouldRetry(rpcName string, err error) bool {
	return false
}

// ShouldRetryOnConnect implements the ConnectionHandler interface.
func (c *ClientRPC) ShouldRetryOnConnect(err error) bool {
	return true
}

// CreateClient creates a new `Client` instance with the parameters and returns
// a pointer the the instance.  Returns an error on any failure.
func CreateClient(ctx context.Context, ipAddr string, port int, masterSecret []byte, directory string) (*Client, error) {
	uri, _ := rpc.ParseFMPURI(fmt.Sprintf("%s:%d", ipAddr, port))
	conn := rpc.NewConnectionWithTransport(&ClientRPC{}, rpc.NewConnectionTransport(uri, nil, nil), nil, true, nil, nil, nil)
	/*
		// TODO: Switch to TLS connection.
		c, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ipAddr, port))
		if err != nil {
			return nil, err
		}
		xp := rpc.NewTransport(c, nil, nil) */

	searchCli := sserver1.SearchServerClient{Cli: conn.GetClient()}

	salts, err := searchCli.GetSalts(ctx)
	if err != nil {
		return nil, err
	}

	size, err := searchCli.GetSize(ctx)
	if err != nil {
		return nil, err
	}

	indexer := libsearch.CreateSecureIndexBuilder(sha256.New, masterSecret, salts, uint64(size))

	var pathnameKey [32]byte
	copy(pathnameKey[:], masterSecret[0:32])

	absDir, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}

	cli := &Client{
		searchCli:   searchCli,
		directory:   absDir,
		indexer:     indexer,
		pathnameKey: pathnameKey,
	}

	return cli, nil
}

// AddFile indexes a file with the given `pathname` and writes the index to the
// server.
func (c *Client) AddFile(pathname string) error {
	relPath, err := relPathStrict(c.directory, pathname)
	if err != nil {
		return err
	}

	docID, err := pathnameToDocID(relPath, c.pathnameKey)
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

	secIndex, err := c.indexer.BuildSecureIndex(file, fileInfo.Size())
	if err != nil {
		return err
	}

	secIndexBytes, err := secIndex.MarshalBinary()
	if err != nil {
		return err
	}

	return c.searchCli.WriteIndex(context.TODO(), sserver1.WriteIndexArg{SecureIndex: secIndexBytes, DocID: docID})
}

// RenameFile is called when a file has been renamed from `orig` to `curr`.
// This will rename their corresponding indexes.  Returns an error if the
// filenames are invalid.
func (c *Client) RenameFile(orig, curr string) error {
	relOrig, err := relPathStrict(c.directory, orig)
	if err != nil {
		return err
	}

	relCurr, err := relPathStrict(c.directory, curr)
	if err != nil {
		return err
	}

	origDocID, err := pathnameToDocID(relOrig, c.pathnameKey)
	if err != nil {
		return err
	}

	currDocID, err := pathnameToDocID(relCurr, c.pathnameKey)
	if err != nil {
		return err
	}

	return c.searchCli.RenameIndex(context.TODO(), sserver1.RenameIndexArg{Orig: origDocID, Curr: currDocID})
}

// DeleteFile deletes the index on the server associated with `pathname`.
func (c *Client) DeleteFile(pathname string) error {
	relPath, err := relPathStrict(c.directory, pathname)
	if err != nil {
		return err
	}

	docID, err := pathnameToDocID(relPath, c.pathnameKey)
	if err != nil {
		return err
	}

	return c.searchCli.DeleteIndex(context.TODO(), docID)
}

// SearchWord performs a search request on the search server and returns the
// list of filenames possibly containing the word.
// NOTE: False positives are possible.
func (c *Client) SearchWord(word string) ([]string, error) {
	trapdoors := c.indexer.ComputeTrapdoors(word)
	documents, err := c.searchCli.SearchWord(context.TODO(), trapdoors)
	if err != nil {
		return nil, err
	}

	filenames := make([]string, len(documents))
	for i, docID := range documents {
		pathname, err := docIDToPathname(docID, c.pathnameKey)
		if err != nil {
			return nil, err
		}
		filenames[i] = filepath.Join(c.directory, pathname)
	}

	sort.Strings(filenames)
	return filenames, nil
}
