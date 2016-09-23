// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package logger

import (
	"log"
	"time"
)

// Logger allows simple logging for the time that a function, or a set of
// functions, takes to execute.
//
// In addition, this logger allows fake time to be added to simulate work
// supposed to be done.  Logging is disabled by default.  To turn them on, call
// `logger.Enable()`.  A typical use case would be:
//
// func test() {
//   logger.Enable()
//   logger.Start("test")
//
//   ... Some Work ...
//
//   logger.AddTime(time.Minute * 2)  // Simulates two minutes doing some work
//
//   ... Other Work ...
//
//   logger.Log("test")
// }

// timeLogs stores the correspondance between entry names and the start time of
// each entry.  The start time would be adjusted accordingly to account for the
// `AddTime` function.
var timeLogs = make(map[string]time.Time)

// enabled determines whether the logger is enabled.  Defaulted to false.
var enabled = false

// Start starts the timer for `name`.
func Start(name string) {
	if !enabled {
		return
	}
	timeLogs[name] = time.Now()
}

// Enable enables the logger functionality.
func Enable() {
	enabled = true
}

// Disable disables the entire logger and clears the current log entries.
func Disable() {
	enabled = false
	timeLogs = make(map[string]time.Time)
}

// AddTime adds a time period to the logger as if that amount of time has
// passed.
func AddTime(duration time.Duration) {
	if !enabled {
		return
	}
	for name := range timeLogs {
		timeLogs[name] = timeLogs[name].Add(-duration)
	}
}

// Log logs the time for `name` and remove it from the log entries.
func Log(name string) time.Duration {
	if !enabled {
		return 0
	}
	if startTime, found := timeLogs[name]; found {
		log.Printf("%s took %s", name, time.Since(startTime))
		delete(timeLogs, name)
		return time.Since(startTime)
	}
	return 0
}
