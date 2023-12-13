// Copyright 2023 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A simple Roughtime server, intended for testing.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net"
	"time"

	"github.com/cloudflare/roughtime/protocol"

	"crypto/ed25519"
)

var (
	// Command line parameters
	addr           = flag.String("addr", "127.0.0.1:2002", "address to listen on")
	rootKeySeedHex = flag.String("root-key", "", "hex-encoded root key seed (random 32 bytes)")

	// Roughtime radius to use for responses
	radius = time.Duration(1) * time.Second
)

func main() {
	var (
		err         error
		rootKeySeed []byte
	)

	log.SetFlags(log.Lshortfile &^ (log.Ldate | log.Ltime))
	flag.Parse()

	// Set up root key
	if *rootKeySeedHex != "" {
		rootKeySeed, err = hex.DecodeString(*rootKeySeedHex)
		if err != nil {
			log.Fatalf("failed to parse root key seed: %v", err)
		}
		if len(rootKeySeed) != 32 {
			log.Fatalf("unexpected root key seed length: got %d; want 32", len(rootKeySeed))
		}
	} else {
		rootKeySeed = make([]byte, 32)
		if _, err = rand.Read(rootKeySeed); err != nil {
			log.Fatalf("rand.Read() failed: %v", err)
		}
	}
	rootSK := ed25519.NewKeyFromSeed(rootKeySeed)
	log.Printf("root public key: %s", base64.StdEncoding.EncodeToString(rootSK.Public().(ed25519.PublicKey)))

	netAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("could not resolve %s: %v", netAddr, err)
	}
	conn, err := net.ListenUDP("udp", netAddr)
	if err != nil {
		log.Fatalf("could not listen on %s: %v", *addr, err)
	}

	onlinePK, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("could not generate key: %v", err)
	}

	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	tomorrow := now.Add(24 * time.Hour)
	onlineCert, err := protocol.NewCertificate(yesterday, tomorrow, onlinePK, rootSK)
	if err != nil {
		log.Fatalf("could not generate certificate: %v", err)
	}

	buf := make([]byte, 1280)
	for {
		reqLen, peer, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("failed to read request: %v", err)
		}

		resp, err := handleRequest(buf[:reqLen], onlineCert, onlineSK)
		if err != nil {
			log.Fatalf("error while handling request: %v", err)
		}

		if _, err = conn.WriteTo(resp, peer); err != nil {
			log.Fatalf("failed to write response: %v", err)
		}
	}
}

func handleRequest(req []byte, cert *protocol.Certificate, onlineSK ed25519.PrivateKey) (resp []byte, err error) {
	nonce, supportedVerions, err := protocol.HandleRequest(req)
	if err != nil {
		return nil, err
	}

	responseVer, err := protocol.ResponseVersionFromSupported(supportedVerions)
	if err != nil {
		return nil, err
	}

	// Parse the request and create the response.
	replies, err := protocol.CreateReplies(responseVer, [][]byte{nonce}, time.Now(), radius, cert, onlineSK)
	if err != nil {
		return nil, err
	}

	if len(replies) != 1 {
		return nil, errors.New("internal error: unexpected number of replies were computed")
	}

	return replies[0], nil
}
