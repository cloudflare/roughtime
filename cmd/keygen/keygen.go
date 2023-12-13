package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"

	"crypto/ed25519"
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

	err = ioutil.WriteFile(*pubFile, []byte(pubEnc), 0644)
	if err != nil {
		log.Fatal("can't write public key")
	}

	err = ioutil.WriteFile(*privFile, []byte(privEnc), 0600)
	if err != nil {
		log.Fatal("can't write private key")
	}

}
