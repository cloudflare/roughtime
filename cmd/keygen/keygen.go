package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"log"
	"os"
)

func main() {
	pubFile := flag.String("pub", "", "File to put the public key in")
	privFile := flag.String("priv", "", "File to put the private key in")

	flag.Parse()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	pubEnc := base64.StdEncoding.EncodeToString(pub)

	privEnc := base64.StdEncoding.EncodeToString(priv)

	if err := os.WriteFile(*pubFile, []byte(pubEnc), 0o644); err != nil {
		log.Fatal("Can't write public key")
	}

	if err := os.WriteFile(*privFile, []byte(privEnc), 0o600); err != nil {
		log.Fatal("Can't write private key")
	}

}
