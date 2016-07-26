package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strconv"
	"time"

	"gopkg.in/cheggaaa/pb.v1"
)

// Sets up the parameters
var numFiles = flag.Int("num_files", 10000, "The number of test files to be generated")
var numWordsPerFile = flag.Int("num_words", 200, "The number of words per test file")
var dictFile = flag.String("dict_file", "dictionary.txt", "The dictionary file used to generate the random words")
var outputPath = flag.String("output_path", "testFiles", "The directory where the test files should be stored")

// This is a little tool for creating test files with random English words.  Use
// `go run testFile.go --help` to check the configurable parameters.
func main() {
	if _, err := os.Stat(*outputPath); os.IsNotExist(err) {
		if os.Mkdir(*outputPath, 0777) != nil {
			fmt.Println("Failed to create the output directory", *outputPath)
			os.Exit(-1)
		}
	}

	// Creates the dictionary
	dict, err := os.Open(*dictFile)
	if err != nil {
		fmt.Println("Failed to open the dictionary file")
		os.Exit(-1)
	}
	scanner := bufio.NewScanner(dict)
	scanner.Split(bufio.ScanWords)
	words := make([]string, 10)
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}

	rand.Seed(time.Now().UnixNano())
	fmt.Println("Generating test files...")
	bar := pb.StartNew(*numFiles)
	for i := 0; i < *numFiles; i++ {
		outfile, err := os.Create(path.Join(*outputPath, "testFile"+strconv.Itoa(i)))
		if err != nil {
			fmt.Println("Cannot create one of the test files:", err)
		}
		for j := 0; j < *numWordsPerFile; j++ {
			fmt.Fprintln(outfile, words[rand.Intn(len(words))])
		}
		outfile.Close()
		bar.Increment()
	}
	bar.FinishPrint("All test files generated")
}
