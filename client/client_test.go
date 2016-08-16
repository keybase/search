package client

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The IP adress of the test server
const TestServerIP = "127.0.0.1"

// The port that the server is listening on
const TestServerPort = 8022

// startTestServer starts a server listening at `TestServerIP` on
// `TestServerPort`.  Need to later manually tear down the server.
func startTestServer() (int, string, error) {
	dir, err := ioutil.TempDir("", "TestServer")
	if err != nil {
		return 0, "", err
	}

	cmd := exec.Command("go",
		"run",
		fmt.Sprintf("%s/src/github.com/keybase/search-server/sserver/sserver/main.go", os.Getenv("GOPATH")),
		fmt.Sprintf("--server_dir=%s", dir),
		fmt.Sprintf("--port=%d", TestServerPort),
		fmt.Sprintf("--ip_addr=%s", TestServerIP))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Start()
	if err != nil {
		os.RemoveAll(dir)
		return 0, "", err
	}

	// Need to wait for the server to properly start
	time.Sleep(time.Second * 10)

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		os.RemoveAll(dir)
		cmd.Process.Kill()
		return 0, "", err
	}

	return pgid, "", nil
}

// tearDownTestServer tears down the server process with `pgid`, and cleans up
// the temporary directort `dir` for the test server.
func tearDownTestServer(pgid int, dir string) error {
	err := syscall.Kill(-pgid, syscall.SIGKILL)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// startTestClient creates an instance of a test client and returns a pointer to
// the instance, as well as the name of the client's temporary directory.  Need
// to later manually clean up the directory.
func startTestClient(t *testing.T) (*Client, string) {
	cliDir, err := ioutil.TempDir("", "TestClient")
	if err != nil {
		t.Fatalf("error when creating the test client directory: %s", err)
	}

	cli, err := CreateClient(TestServerIP, TestServerPort, []byte("This is a random string"), cliDir)
	if err != nil {
		t.Fatalf("error when creating the client: %s", err)
	}

	return cli, cliDir
}

// TestCreateClient tests the `CreateClient` function.  Checks that a client can
// be successfully created and that two clients have the same `indexer` and
// `pathnameKey` if created with the same master secret.
func TestCreateClient(t *testing.T) {
	client1, dir1 := startTestClient(t)
	defer os.Remove(dir1)
	client2, dir2 := startTestClient(t)
	defer os.Remove(dir2)

	if !reflect.DeepEqual(client1.indexer.ComputeTrapdoors("test"), client2.indexer.ComputeTrapdoors("test")) {
		t.Fatalf("clients with different indexer created with the same master secret")
	}
	if client1.pathnameKey != client2.pathnameKey {
		t.Fatalf("clients with different pathnameKey created with the same master secret")
	}
}

// TestAddFile tests the `AddFile` function.  Checks that the index is properly
// written by the server, and that errors are properly returned when the file is
// not valid.
func TestAddFile(t *testing.T) {
	client, dir := startTestClient(t)
	defer os.RemoveAll(dir)

	content := "This is a random test string, it is quite long, or not really"
	if err := ioutil.WriteFile(filepath.Join(dir, "testFile"), []byte(content), 0666); err != nil {
		t.Fatalf("error when writing test file: %s", err)
	}

	if err := client.AddFile(filepath.Join(dir, "testFile")); err != nil {
		t.Fatalf("error when adding the file: %s", err)
	}

	if err := client.AddFile(filepath.Join(dir, "nonExisting")); err == nil {
		t.Fatalf("no error returned for non-existing file")
	}

	fileNotInDir, err := ioutil.TempFile("", "tmpFile")
	if err != nil {
		t.Fatalf("error when creating temporary test file: %s", err)
	}
	defer os.Remove(fileNotInDir.Name())

	if err := client.AddFile(fileNotInDir.Name()); err == nil {
		t.Fatalf("no error returned for file not in the client directory")
	}
}

// TestRenameFile tests the `renameFile` function.  Checks the indexes are
// properly renamed and errors returned when necessary.
func TestRenameFile(t *testing.T) {
	client, dir := startTestClient(t)
	defer os.RemoveAll(dir)

	content := "a random content"
	if err := ioutil.WriteFile(filepath.Join(dir, "testRenameFile"), []byte(content), 0666); err != nil {
		t.Fatalf("error when writing test file: %s", err)
	}

	if err := client.AddFile(filepath.Join(dir, "testRenameFile")); err != nil {
		t.Fatalf("error when adding the file: %s", err)
	}

	if err := client.RenameFile(filepath.Join(dir, "testRenameFile"), filepath.Join(dir, "testRename")); err != nil {
		t.Fatalf("error when renaming file: %s", err)
	}

	// Doing the renaming second time should fail, as the orignal file no longer
	// exists
	if err := client.RenameFile(filepath.Join(dir, "testRenameFile"), filepath.Join(dir, "testRename")); err == nil {
		t.Fatalf("no error returned when renaming non-existing file")
	}
}

// TestSearchWord tests the `SearchWord` function.  Checks that the correct set
// of filenames are returned.
func TestSearchWord(t *testing.T) {
	client, dir := startTestClient(t)
	defer os.RemoveAll(dir)

	contents := []string{
		"This is a simple test file",
		"This is another test file",
		"This is a different test file",
		"This is yet another test file",
		"This is the last test file",
	}
	filenames := make([]string, 5)

	for i := 0; i < len(contents); i++ {
		filenames[i] = filepath.Join(dir, "testSearchFile"+strconv.Itoa(i))
		if err := ioutil.WriteFile(filenames[i], []byte(contents[i]), 0666); err != nil {
			t.Fatalf("error when writing test file: %s", err)
		}
		if err := client.AddFile(filenames[i]); err != nil {
			t.Fatalf("error when adding the file: %s", err)
		}
	}

	expected := []string{filenames[1], filenames[3]}
	sort.Strings(expected)
	actual, err := client.SearchWord("another")
	if err != nil {
		t.Fatalf("error when searching word: %s", err)
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("incorrect search result: expected \"%s\" actual \"%s\"", expected, actual)
	}

	empty, err := client.SearchWord("non-existing")
	if err != nil {
		t.Fatalf("error when searching word: %s", err)
	}
	if len(empty) > 0 {
		t.Fatalf("filenames found for non-existing word")
	}

	expected = filenames
	sort.Strings(expected)
	actual, err = client.SearchWord("file")
	if err != nil {
		t.Fatalf("error when searching word: %s", err)
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("incorrect search result: expected \"%s\" actual \"%s\"", expected, actual)
	}
}

// TestMain sets up the test server and directory before the tests and tears
// them down after the tests are completed.
func TestMain(m *testing.M) {
	pgid, dir, err := startTestServer()
	if err != nil {
		panic("error when starting the test server")
	}

	// Redirect the logs from the client to nil
	os.Stderr = nil
	exitCode := m.Run()

	err = tearDownTestServer(pgid, dir)
	if err != nil {
		panic("error when tearing down the test server")
	}

	os.Exit(exitCode)
}
