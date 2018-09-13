// +build ignore

// This example configures a TLS client to use Roughtime to synchronize its
// clock and sends a GET request to https://example.com.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/roughtime"
)

var (
	caFile       = flag.String("ca", "data/ca.pem", "File with the server's CA certificate")
	rtConfig     = flag.String("rt", "data/ecosystem.config", "File with the Roughtime configuration")
	dialAttempts = flag.Int("a", roughtime.DefaultQueryAttempts, "Number of times to try dialing each Roughtime server")
	dialTimeout  = flag.Duration("d", roughtime.DefaultQueryTimeout, "Time to wait for each dial attempt")
	rtMaxRadius  = flag.Duration("r", time.Second*10, "Maximum uncertainty radius permitted from Roughtime server")
)

func main() {
	flag.Parse()
	logger := log.New(os.Stdout, "", 0)
	roughtime.SetLogger(logger)

	// Load the list of Roughtime-server configurations.
	rtServers, skipped, err := roughtime.LoadConfig(*rtConfig)
	if err != nil {
		logger.Fatal(err)
	}
	if len(rtServers) == 0 {
		logger.Fatalf("no valid servers (skipped %s)", skipped)
	}

	// Get the system clock's current time, then immediately query the Roughtime
	// servers.
	t0 := time.Now()
	res := roughtime.Do(rtServers, *dialAttempts, *dialTimeout, nil)

	// Compute the average difference between t0 and the time reported by each
	// server, rejecting those responses whose radii are too large. (Note that
	// this accounts for network delay.)
	delta, err := roughtime.AvgDeltaWithRadiusThresh(res, t0, *rtMaxRadius)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("delta: %v\n", delta.Truncate(time.Millisecond))

	ca, err := ioutil.ReadFile(*caFile)
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
