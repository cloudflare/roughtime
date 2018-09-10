// Copyright 2018 Cloudflare, Inc.

// A simple Roughtime roughtime.
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/cloudflare/roughtime"

	"roughtime.googlesource.com/go/config"
)

var (
	// Build info.
	Version   = "dev"
	GoVersion = runtime.Version()
	BuildTime = ""

	// Command-line arguments.
	getVersion = flag.Bool("version", false, "Print the version and exit.")
	configFile = flag.String("config", "", "A list of Roughtime servers.")
	pingAddr   = flag.String("ping", "", "Send a UDP request, e.g., localhost:2002.")
	pingPubKey = flag.String("pubkey", "", "The Ed25519 public key of the address to ping.")
	attempts   = flag.Int("attempts", roughtime.DefaultQueryAttempts, "Number of times to try each server.")
	timeout    = flag.Duration("timeout", roughtime.DefaultQueryTimeout, "Amount of time to wait for each request.")
)

func main() {
	flag.Parse()
	logger := log.New(os.Stdout, "", 0)
	roughtime.SetLogger(logger)

	if *getVersion {
		logger.Printf("getroughtime %s (%s) built %s\n", Version, GoVersion, BuildTime)
		os.Exit(0)
	}

	if *configFile != "" {
		t0 := time.Now()
		res, err := roughtime.DoFromFile(*configFile, *attempts, *timeout, nil)
		if err != nil {
			logger.Fatal(err)
		}
		delta, err := roughtime.AvgDeltaWithRadiusThresh(res, t0, 10*time.Second)
		if err != nil {
			logger.Fatal(err)
		}
		logger.Printf("delta: %v", delta.Truncate(time.Millisecond))
		os.Exit(0)
	}

	if *pingAddr != "" {
		if *pingPubKey == "" {
			logger.Fatal("ping: missing -pubkey")
		}
		pk, err := base64.StdEncoding.DecodeString(*pingPubKey)
		if err != nil {
			logger.Fatalf("pubkey decode error: %s\n", err)
		} else if len(pk) != 32 {
			logger.Fatalf("pubkey decode error: incorrect length")
		}

		server := &config.Server{
			Name:          "",
			PublicKeyType: "ed25519",
			PublicKey:     pk,
			Addresses: []config.ServerAddress{
				config.ServerAddress{
					Protocol: "udp",
					Address:  *pingAddr,
				},
			},
		}

		start := time.Now()
		rt, err := roughtime.Get(server, *attempts, *timeout, nil)
		delay := time.Since(start).Truncate(time.Millisecond)
		if err != nil {
			logger.Fatalf("ping error: %s\n", err)
		}
		logger.Printf("ping response: %s (in %s)\n", rt, delay)
		os.Exit(0)
	}

	logger.Fatal("either provide a configuration via -config or an address via -ping")
}
