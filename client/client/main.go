package main

import (
	"bufio"
	"crypto/rand"
	"errors"
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
var lenMS = flag.Int("len_ms", 64, "the length of the master secret")
var verbose = flag.Bool("v", false, "whether log outputs should be printed out")

// addAllFiles adds all the non-hidden files that have been modified after
// `lastIndexed`.
func addAllFiles(cli *client.Client, lastIndexed time.Time) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && (info.Name()[0] == '.' || info.ModTime().Before(lastIndexed)) {
			return filepath.SkipDir
		} else if !info.IsDir() && info.Name()[0] != '.' {
			if info.ModTime().After(lastIndexed) {
				cli.AddFile(path)
				if *verbose {
					fmt.Println("Added:", path)
				}
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
		f, err := os.OpenFile(filepath.Join(*clientDirectory, ".search_kbfs_timestamp"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)

		if err == nil {
			// Write the current time to the timestamp
			currTimeJSON, err := currTime.MarshalJSON()
			if err != nil {
				panic(fmt.Sprintf("Error when writing the timestamp: %s", err))
			}

			_, err = f.Write(currTimeJSON)
			if err != nil {
				panic(fmt.Sprintf("Error when writing the timestamp: %s", err))
			}
			f.Close()
		} else if os.IsExist(err) {
			// Read the last indexed time from the timestamp file
			lastIndexedJSON, err := ioutil.ReadFile(filepath.Join(*clientDirectory, ".search_kbfs_timestamp"))
			if err != nil {
				panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
			}
			if err := lastIndexed.UnmarshalJSON(lastIndexedJSON); err != nil {
				panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
			}
		} else {
			panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
		}

		if err := filepath.Walk(*clientDirectory, addAllFiles(cli, lastIndexed)); err != nil {
			panic(fmt.Sprintf("Error when indexing the files: %s", err))
		}

		if *verbose {
			fmt.Printf("\n[%s]: All files Indexed\n", currTime.Format("2006-01-02 15:04:05"))
		}
		time.Sleep(time.Second * 60)
	}
}

// fetchMasterSecret fetches the master secret from the client directory.  If
// the master secret is not present, a new one is generated and written to the
// directory.  An error is returned if the there is an issue accessing the
// master secret or the master secret is of the wrong length.
func fetchMasterSecret() ([]byte, error) {
	var masterSecret []byte

	f, err := os.OpenFile(filepath.Join(*clientDirectory, ".search_kbfs_secret"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)

	if err == nil {
		defer f.Close()
		// Generate a random master secret and write it to file
		masterSecret = make([]byte, *lenMS)
		if _, err := rand.Read(masterSecret); err != nil {
			return nil, err
		}

		_, err = f.Write(masterSecret)
		if err != nil {
			return nil, err
		}
	} else if os.IsExist(err) {
		// Read the master secret from file
		masterSecret, err = ioutil.ReadFile(filepath.Join(*clientDirectory, ".search_kbfs_secret"))
		if err != nil {
			return nil, err
		}
		if len(masterSecret) != *lenMS {
			return nil, errors.New("Invalid master secret length")
		}
	} else {
		return nil, err
	}
	return masterSecret, nil
}

// performSearchWord searched for the word `keyword` on `cli`, and print out the
// results.
func performSearchWord(cli *client.Client, keyword string) {
	if len(filenames) == 0 {
		fmt.Printf("No file contains the word \"%s\".\n", keyword)
	} else {
		fmt.Printf("Files containing the word \"%s\":\n", keyword)
		for _, filename := range filenames {
			fmt.Printf("\t%s\n", filename)
		}
	}
	fmt.Println()
}

func main() {
	flag.Parse()

	// Fetch the master secret from the client directory
	masterSecret, err := fetchMasterSecret()
	if err != nil {
		fmt.Printf("Cannot fetch the master secret: %s\n", err)
		os.Exit(1)
	}

	// Initiate the search client
	cli, err := client.CreateClient(context.TODO(), *ipAddr, *port, masterSecret, *clientDirectory, *verbose)
	if err != nil {
		fmt.Printf("Cannot initialize the client: %s\n", err)
		os.Exit(1)
	}

	go periodicAdd(cli)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Please enter words to search for separated by spaces (enter to exit): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimRight(input, "\n")
		if input == "" {
			break
		}
		keywords := strings.Split(input, " ")
		for _, keyword := range keywords {
			performSearchWord(cli, keyword)
		}
	}
}
