// +build ignore

// This program performs a sequence of Roughtime queries and creates an alert
// via `notify-send` if the system's clock is skewed beyond an acceptable
// threshold.
//
// This has been tested with go>=1.10 on Ubuntu 18.04.
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"time"

	"github.com/cloudflare/roughtime"
)

var (
	caFile         = flag.String("ca", "data/ca.pem", "File with the server's CA certificate")
	rtConfig       = flag.String("rt", "data/roughtime.config", "File with the Roughtime configuration")
	dialAttempts   = flag.Int("a", roughtime.DefaultQueryAttempts, "Number of times to try dialing each Roughtime server")
	dialTimeout    = flag.Duration("d", roughtime.DefaultQueryTimeout, "Time to wait for each dial attempt")
	rtMaxRadius    = flag.Duration("r", time.Second*10, "Maximum uncertainty radius permitted from Roughtime server")
	alertThreshold = flag.Duration("thresh", time.Second*10, "Minimum clock skew for triggering an alert")
	logFile        = flag.String("log", "/var/log/roughtime", "File to which to write the log")
)

var summary = `Check your clock!`
var template = `Your clock is off Roughtime by %v. See %s for details.`

func main() {
	flag.Parse()

	// Logging
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	logger := log.New(f, "", log.Ldate|log.Lshortfile)
	roughtime.SetLogger(logger)

	// Query the Roughtime servers.
	t0 := time.Now()
	res, err := roughtime.DoFromFile(*rtConfig, *dialAttempts, *dialTimeout, nil)
	if err != nil {
		logger.Fatal(err)
	}

	// Compute the average difference between t0 and the time reported by the
	// each server.
	delta, err := roughtime.AvgDeltaWithRadiusThresh(res, t0, *rtMaxRadius)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("delta: %v", delta.Truncate(time.Millisecond))

	// Check if the skew exceeds the alert threshold. If so, then use
	// `notify-send` to emit an alert.
	skew := time.Duration(math.Abs(float64(delta)))
	if skew > *alertThreshold {
		body := fmt.Sprintf(template, skew.Truncate(time.Millisecond), *logFile)
		cmd := exec.Command("notify-send", "-u", "critical", "-i", "clock", summary, body)
		if err := cmd.Run(); err != nil {
			logger.Fatal(err)
		}
	}
}
