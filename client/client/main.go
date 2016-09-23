// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keybase/search/client"
	"golang.org/x/net/context"
)

var lenSalt = flag.Int("len_salt", 8, "the length of the salts used to generate the PRFs")
var fpRate = flag.Float64("fp_rate", 0.000001, "the desired false positive rate for searchable encryption")
var numUniqWords = flag.Uint64("num_words", uint64(100000), "the expected number of unique words in all the documents within one TLF")
var clientDirectories = flag.String("client_dirs", "", "the keybase directories for the client where the files should be indexed, separated by ';'")
var port = flag.Int("port", 8022, "the port that the search server is listening on")
var ipAddr = flag.String("ip_addr", "127.0.0.1", "the IP address that the search server is listening on")
var lenMS = flag.Int("len_ms", 64, "the length of the master secret")
var verbose = flag.Bool("v", false, "whether log outputs should be printed out")

// addAllFiles adds all the non-hidden files that have been modified after
// `lastIndexed`.
func addAllFiles(cli *client.Client, clientDir string, lastIndexed time.Time) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && (info.Name()[0] == '.' || info.ModTime().Before(lastIndexed)) {
			return filepath.SkipDir
		} else if !info.IsDir() && info.Name()[0] != '.' {
			if info.ModTime().After(lastIndexed) {
				cli.AddFile(clientDir, path)
				if *verbose {
					fmt.Println("Added:", path)
				}
			}
		}
		return nil
	}
}

// periodicAdd scans the files in the client directories every minute and adds
// the updated files to the search server.
func periodicAdd(cli *client.Client, clientDirs []string) {
	for {
		for _, clientDir := range clientDirs {
			currTime := time.Now()

			var lastIndexed time.Time

			lastIndexedJSON, err := ioutil.ReadFile(filepath.Join(clientDir, ".search_kbfs_timestamp"))
			if err == nil {
				if err := lastIndexed.UnmarshalJSON(lastIndexedJSON); err != nil {
					panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
				}
			} else if !os.IsNotExist(err) {
				panic(fmt.Sprintf("Error when accessing the last indexed timestamp: %s", err))
			}

			if err := filepath.Walk(clientDir, addAllFiles(cli, clientDir, lastIndexed)); err != nil {
				panic(fmt.Sprintf("Error when indexing the files: %s", err))
			}

			currTimeJSON, err := currTime.MarshalJSON()
			if err != nil {
				panic(fmt.Sprintf("Error when writing the timestamp: %s", err))
			}
			if err := ioutil.WriteFile(filepath.Join(clientDir, ".search_kbfs_timestamp"), currTimeJSON, 0666); err != nil {
				panic(fmt.Sprintf("Error when writing the timestamp: %s", err))
			}

			if *verbose {
				fmt.Printf("\n[%s]: All files under directory \"%s\" indexed in %s\n", currTime.Format("2006-01-02 15:04:05"), clientDir, time.Since(currTime))
			}
		}
		time.Sleep(time.Second * 60)
	}
}

// performSearchWord searches for the word `keyword` on `cli`, and prints out
// the results.
// TODO: Parallelize the search on different TLFs for performance optimization.
func performSearchWord(cli *client.Client, clientDirs []string, keyword string) {
	var allFiles []string
	for _, clientDir := range clientDirs {
		filenames, err := cli.SearchWordStrict(clientDir, keyword)
		if err != nil {
			fmt.Printf("Error when searching word %s: %s", keyword, err)
			return
		}
		allFiles = append(allFiles, filenames...)
	}
	if len(allFiles) == 0 {
		fmt.Printf("No file contains the word \"%s\".\n", keyword)
	} else {
		fmt.Printf("Files containing the word \"%s\":\n", keyword)
		for _, filename := range allFiles {
			fmt.Printf("\t%s\n", filename)
		}
	}
	fmt.Println()
}

func main() {
	flag.Parse()

	if *clientDirectories == "" {
		fmt.Printf("Please provide at least one client directory.\n")
		os.Exit(1)
	}

	clientDirs := strings.Split(*clientDirectories, ";")

	// Initiate the search client
	cli, err := client.CreateClient(context.TODO(), *ipAddr, *port, clientDirs, *lenMS, *lenSalt, *fpRate, *numUniqWords, *verbose)
	if err != nil {
		fmt.Printf("Cannot initialize the client: %s\n", err)
		os.Exit(1)
	}

	go periodicAdd(cli, clientDirs)

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
			performSearchWord(cli, clientDirs, keyword)
		}
	}
}
