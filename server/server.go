package server

import (
	"crypto/rand"
	"crypto/sha256"
	"math"
	"search/util"
	"strconv"
)

// Server contains all the necessary information for a running server.
type Server struct {
	mountPoint string   // Mount point of the server
	lenMS      int      // Length of the master secret in bytes
	keyHalves  [][]byte // The server-side keyhalves
	salts      [][]byte // The salts for deriving the keys for the PRFs
	numFiles   uint     // The number of files currently stored in the server.  This is used to determine the next docID.
}

// CreateServer initializes a server with `numClients` clients with a master
// secret of length `lenMS`, and generate salts with length `lenSalt`.  The
// number of salts is given by `r = -log2(fpRate)`, where `fpRate` is the
// desired false positive rate of the system.  `mountPoint` determines where the
// server files will be stored.
func CreateServer(numClients, lenMS, lenSalt int, mountPoint string, fpRate float64) *Server {
	s := new(Server)
	masterSecret := make([]byte, lenMS)
	rand.Read(masterSecret)
	s.keyHalves = make([][]byte, numClients)
	s.lenMS = lenMS
	for i := 0; i < numClients; i++ {
		h := sha256.New()
		h.Write([]byte(strconv.Itoa(i)))
		cksum := h.Sum(nil)
		s.keyHalves[i] = util.XorBytes(masterSecret, cksum, lenMS)
	}
	r := int(math.Ceil(-math.Log2(fpRate)))
	s.salts = util.GenerateSalts(r, lenSalt)
	s.numFiles = 0
	s.mountPoint = mountPoint
	return s
}
