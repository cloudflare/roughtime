//go:build ignore
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

	"github.com/cloudflare/roughtime/client"
)

const (
	summary  = `Check your clock!`
	template = `Your clock is off Roughtime by %v. See %s for details.`
)

func main() {
	//caFile := flag.String("ca", "recipes/testdata/ca.pem", "File with the server's CA certificate")
	rtConfig := flag.String("rt", "ecosystem.json", "File with the Roughtime configuration")
	dialAttempts := flag.Int("a", client.DefaultQueryAttempts, "Number of times to try dialing each Roughtime server")
	dialTimeout := flag.Duration("d", client.DefaultQueryTimeout, "Time to wait for each dial attempt")
	rtMaxRadius := flag.Duration("r", time.Second*10, "Maximum uncertainty radius permitted from Roughtime server")
	alertThreshold := flag.Duration("thresh", time.Second*10, "Minimum clock skew for triggering an alert")
	logFile := flag.String("log", "/dev/stdout", "File to which to write the log")

	flag.Parse()

	// Logging
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	logger := log.New(f, "", log.Ldate|log.Lshortfile)
	client.SetLogger(logger)

	// Query the Roughtime servers.
	t0 := time.Now()
	res, err := client.DoFromFile(*rtConfig, *dialAttempts, *dialTimeout, nil)
	if err != nil {
		logger.Fatal(err)
	}

	// Compute the median difference between t0 and the time reported by the
	// each server, excluding those servers whose radii are too large.
	delta, err := client.MedianDeltaWithRadiusThresh(res, t0, *rtMaxRadius)
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
