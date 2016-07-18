package logger

import (
	"testing"
	"time"
)

// TestLogger tests the logger interface and makes sure that the time are being
// correctly logged.
func TestLogger(t *testing.T) {
	Enabled = false
	l := CreateLogger("test")
	l.AddTime(5 * time.Second)
	l.AddTime(5 * time.Minute)
	time.Sleep(3 * time.Second)
	result := l.LogTime()
	if result < time.Minute*5+time.Second*8 || result > time.Minute*5+time.Second*9 {
		t.Fatalf("timing not correct")
	}
}
