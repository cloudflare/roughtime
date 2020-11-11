package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"net"

	"github.com/cloudflare/roughtime/mjd"
	"github.com/cloudflare/roughtime/protocol"

	"golang.org/x/crypto/ed25519"
)

var addr string
var privKeyFile string

func main() {
	flag.StringVar(&addr, "a", "", "address to listen on")
	flag.StringVar(&privKeyFile, "k", "", "file with private key")
	flag.Parse()

	keyStr, err := ioutil.ReadFile(privKeyFile)
	if err != nil {
		log.Fatalf("could not read %s: %v", privKeyFile, err)
	}
	rootKey, err := base64.StdEncoding.DecodeString(string(keyStr))
	if err != nil {
		log.Fatalf("could not decode private key: %v", err)
	}

	netAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("could not resolve %s: %v", netAddr, err)
	}
	conn, err := net.ListenUDP("udp", netAddr)
	if err != nil {
		log.Fatalf("could not listen on %s: %v", addr, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("could not generate key: %v", err)
	}

	now := mjd.Now()
	yesterday := mjd.New(now.Day()-1, now.Microseconds())
	tomorrow := mjd.New(now.Day()+1, now.Microseconds())
	cert, err := protocol.CreateCertificate(yesterday, tomorrow, pub, rootKey)
	if err != nil {
		log.Fatalf("could not generate certificate: %v", err)
	}

	query := make([]byte, 1280)
	for {
		queryLen, peer, err := conn.ReadFrom(query)
		if err != nil {
			log.Fatal("read failed")
		}
		resp, err := protocol.CreateReply(query[:queryLen], mjd.Now(), 1000000, cert, priv)
		if err != nil {
			log.Printf("error in response: %v", err)
		}

		conn.WriteTo(resp, peer)
	}

}
