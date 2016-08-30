package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/keybase/search/client"
	"golang.org/x/net/context"
)

var clientDirectory = flag.String("client_dir", "/keybase/private/jiaxin", "the keybase directory for the client where the files should be indexed")
var port = flag.Int("port", 8022, "the port that the search server is listening on")
var ipAddr = flag.String("ip_addr", "127.0.0.1", "the IP address that the search server is listening on")

// addAllFiles adds all the non-hidden files that have been modified after
// `lastIndexed`.
func addAllFiles(cli *client.Client, lastIndexed time.Time) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && (info.Name()[0] == '.' || info.ModTime().Before(lastIndexed)) {
			return filepath.SkipDir
		} else if !info.IsDir() && info.Name()[0] != '.' {
			if info.ModTime().After(lastIndexed) {
				cli.AddFile(path)
				fmt.Println("Added:", path)
			}
		}
		return nil
	}
}

// periodicAdd scans the files in the client directory every minute and adds
// the updated files to the search server.
func periodicAdd(cli *client.Client) {
	for {
		currTime := time.Now()

		var lastIndexed time.Time
		lastIndexedJSON, err := ioutil.ReadFile(filepath.Join(*clientDirectory, ".timestamp"))
		if err == nil {
			if parseErr := lastIndexed.UnmarshalJSON(lastIndexedJSON); parseErr != nil {
				panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
			}
		} else if !os.IsNotExist(err) {
			panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
		}

		if err := filepath.Walk(*clientDirectory, addAllFiles(cli, lastIndexed)); err != nil {
			panic(fmt.Sprintf("Error when indexing the files: %s", err))
		}

		currTimeJSON, err := currTime.MarshalJSON()
		if err != nil {
			panic(fmt.Sprintf("Error when writing the timestamp: %s", err))
		}

		ioutil.WriteFile(filepath.Join(*clientDirectory, ".timestamp"), currTimeJSON, 0666)

		fmt.Printf("\n[%s]: All files Indexed\n", currTime.Format("2006-01-02 15:04:05"))
		time.Sleep(time.Second * 60)
	}
}

func main() {
	flag.Parse()

	cli, err := client.CreateClient(context.TODO(), *ipAddr, *port, []byte("A really really really long Master Secret, oh god it's so long"), *clientDirectory)
	if err != nil {
		fmt.Printf("Cannot initiate the client: %s\n", err)
		os.Exit(1)
	}
	go periodicAdd(cli)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Please enter word to search for: ")
		keyword, _ := reader.ReadString('\n')
		keyword = keyword[:len(keyword)-1]
		files, err := cli.SearchWord(keyword)
		if err != nil {
			fmt.Printf("Error when searching word %s: %s", keyword, err)
			continue
		}
		args := make([]string, len(files)+2)
		args[0] = "-ilZw"
		args[1] = keyword
		copy(args[2:], files[:])
		output, _ := exec.Command("grep", args...).Output()
		filenames := strings.Split(string(output), "\x00")
		filenames = filenames[:len(filenames)-1]
		if len(filenames) == 0 {
			fmt.Printf("No file contains the word \"%s\".\n", keyword)
		} else {
			fmt.Printf("Files containing the word \"%s\":\n", keyword)
			for _, filename := range filenames {
				fmt.Printf("\t%s\n", filename)
			}
		}
	}
}
