package logger

import (
	"io/ioutil"
	"log"
	"testing"
	"time"
)

// TestLogger tests the logger interface and makes sure that the time are being
// correctly logged.
func TestLogger(t *testing.T) {
	Enable()
	log.SetOutput(ioutil.Discard)
	Start("test")
	AddTime(5 * time.Minute)
	Start("test2")
	AddTime(5 * time.Second)
	time.Sleep(3 * time.Second)
	result := Log("test")
	if result < time.Minute*5+time.Second*8 || result > time.Minute*5+time.Second*9 {
		t.Fatalf("timing not correct")
	}
	result2 := Log("test2")
	if result2 < time.Second*8 || result2 > time.Second*9 {
		t.Fatalf("timing not correct")
	}
	Start("test")
	AddTime(10 * time.Minute)
	resultDup := Log("test")
	if resultDup < time.Minute*10 || result2 > time.Minute*10+time.Second {
		t.Fatalf("same name cannot be reused")
	}

}
