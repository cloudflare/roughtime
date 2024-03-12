//go:build ignore
// +build ignore

// This example configures a TLS client to use Roughtime to synchronize its
// clock and sends a GET request to https://example.com.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/roughtime/client"
)

func main() {
	caFile := flag.String("ca", "recipes/testdata/ca.pem", "File with the server's CA certificate")
	rtConfig := flag.String("rt", "ecosystem.json", "File with the Roughtime configuration")
	dialAttempts := flag.Int("a", client.DefaultQueryAttempts, "Number of times to try dialing each Roughtime server")
	dialTimeout := flag.Duration("d", client.DefaultQueryTimeout, "Time to wait for each dial attempt")
	rtMaxRadius := flag.Duration("r", time.Second*10, "Maximum uncertainty radius permitted from Roughtime server")

	flag.Parse()
	logger := log.New(os.Stdout, "", 0)
	client.SetLogger(logger)

	// Load the list of Roughtime-server configurations.
	rtServers, skipped, err := client.LoadConfig(*rtConfig)
	if err != nil {
		logger.Fatal(err)
	}
	if len(rtServers) == 0 {
		logger.Fatalf("No valid servers (skipped %d)", skipped)
	}

	// Get the system clock's current time, then immediately query the Roughtime
	// servers.
	t0 := time.Now()
	res := client.Do(rtServers, *dialAttempts, *dialTimeout, nil)

	// Compute the median difference between t0 and the time reported by each
	// server, rejecting those responses whose radii are too large. (Note that
	// this accounts for network delay.)
	delta, err := client.MedianDeltaWithRadiusThresh(res, t0, *rtMaxRadius)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("delta: %v\n", delta.Truncate(time.Millisecond))

	ca, err := os.ReadFile(*caFile)
	if err != nil {
		logger.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
				Time: func() time.Time {
					return time.Now().Add(delta)
				},
			},
		},
	}

	resp, err := httpClient.Get("https://example.com")
	if err != nil {
		logger.Fatal(err)
	}
	logger.Print(resp.Status)
	resp.Body.Close()
}
