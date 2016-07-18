package logger

import (
	"log"
	"time"
)

// Logger allows simple logging for the time that a function takes to execute.
// In addition, this logger allows fake time to be added to simulate work
// supposed to be done.  Logging is enabled by default.  To turn them off, set
// `logger.enabled = false`.  A typical use case would be:
//
// func test() {
//	 logger.Enabled = true
//   l := CreateLogger("test")
//	 defer l.LogTime()
//
//   ... Some Work ...
//
//   l.AddTime(time.Minute * 2)  // Simultaes two minutes doing some work
//
//   ... Other Work ...
//
// }
type Logger struct {
	name    string
	start   time.Time
	elapsed time.Duration
}

// Enabled determines whether logging messages should be printed.  Defaulted to
// false.
var Enabled = false

// CreateLogger creates a logger for `name`.
func CreateLogger(name string) *Logger {
	l := new(Logger)
	l.start = time.Now()
	l.elapsed = 0
	l.name = name
	return l
}

// AddTime adds a time period of `t` as if that period of time had elapsed.
func (l *Logger) AddTime(t time.Duration) {
	l.elapsed += t
}

// LogTime logs how long it has been since the logger was created, together with
// all the time added to the logger.  This also returns the duration that is
// being printed.
func (l *Logger) LogTime() time.Duration {
	if Enabled {
		log.Printf("%s took %s", l.name, l.elapsed+time.Since(l.start))
	}
	return l.elapsed + time.Since(l.start)
}
