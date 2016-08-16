package client

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// The IP adress of the test server
const TestServerIP = "127.0.0.1"

// The port that the server is listening on
const TestServerPort = 8022

var ServerDir string

// startTestServer starts a server listening at `TestServerIP` on
// `TestServerPort`.  Need to later manually tear down the server.
func startTestServer() (int, error) {
	ServerDir, err := ioutil.TempDir("", "TestServer")
	if err != nil {
		return 0, err
	}

	cmd := exec.Command("go",
		"run",
		fmt.Sprintf("%s/src/github.com/keybase/search-server/sserver/sserver/main.go", os.Getenv("GOPATH")),
		fmt.Sprintf("--server_dir=%s", ServerDir),
		fmt.Sprintf("--port=%d", TestServerPort),
		fmt.Sprintf("--ip_addr=%s", TestServerIP))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Start()
	if err != nil {
		os.RemoveAll(ServerDir)
		return 0, err
	}

	// Need to wait for the server to properly start
	time.Sleep(time.Second * 10)

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		os.RemoveAll(ServerDir)
		cmd.Process.Kill()
		return 0, err
	}

	return pgid, nil
}

// tearDownTestServer tears down the server process with `pgid`, and cleans up
// the temporary directort `ServerDir` for the test server.
func tearDownTestServer(pgid int) error {
	err := syscall.Kill(-pgid, syscall.SIGKILL)
	if err != nil {
		return err
	}
	return os.RemoveAll(ServerDir)
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

// TestMain sets up the test server and directory before the tests and tears
// them down after the tests are completed.
func TestMain(m *testing.M) {
	pgid, err := startTestServer()
	if err != nil {
		panic("error when starting the test server")
	}

	// Redirect the logs from the client to nil
	os.Stderr = nil
	exitCode := m.Run()

	err = tearDownTestServer(pgid)
	if err != nil {
		panic("error when tearing down the test server")
	}

	os.Exit(exitCode)
}
