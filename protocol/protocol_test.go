// Copyright 2016 The Roughtime Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License. */

package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"testing/quick"

	"github.com/cloudflare/roughtime/mjd"
	"golang.org/x/crypto/ed25519"
)

func testEncodeDecodeRoundtrip(msg map[uint32][]byte) bool {
	encoded, err := Encode(msg)
	if err != nil {
		return true
	}

	decoded, err := Decode(encoded)
	if err != nil {
		return false
	}

	if len(msg) != len(decoded) {
		return false
	}

	for tag, payload := range msg {
		otherPayload, ok := decoded[tag]
		if !ok {
			return false
		}
		if !bytes.Equal(payload, otherPayload) {
			return false
		}
	}

	return true
}

func TestEncodeDecode(t *testing.T) {
	quick.Check(testEncodeDecodeRoundtrip, &quick.Config{
		MaxCountScale: 10,
	})
}

func TestRequestSize(t *testing.T) {
	_, _, request, err := CreateRequest(rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != MinRequestSize {
		t.Errorf("got %d byte request, want %d bytes", len(request), MinRequestSize)
	}
}

func createServerIdentity(t *testing.T) (cert, rootPublicKey, onlinePrivateKey []byte) {
	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	onlinePublicKey, onlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if cert, err = CreateCertificate(mjd.New(0, 0), mjd.New(100, 0), onlinePublicKey, rootPrivateKey); err != nil {
		t.Fatal(err)
	}

	return cert, rootPublicKey, onlinePrivateKey
}

func TestRoundtrip(t *testing.T) {
	cert, rootPublicKey, onlinePrivateKey := createServerIdentity(t)

	for _, numRequests := range []int{1, 2, 3, 4, 5, 15, 16, 17} {
		nonces := make([][NonceSize]byte, numRequests)
		for i := range nonces {
			binary.LittleEndian.PutUint32(nonces[i][:], uint32(i))
		}

		noncesSlice := make([][]byte, 0, numRequests)
		for i := range nonces {
			noncesSlice = append(noncesSlice, nonces[i][:])
		}

		expectedMidpoint := mjd.New(50, 0)
		expectedRadius := uint32(5)

		replies, err := CreateReplies(noncesSlice, expectedMidpoint, expectedRadius, cert, onlinePrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		if len(replies) != len(nonces) {
			t.Fatalf("received %d replies for %d nonces", len(replies), len(nonces))
		}

		for i, reply := range replies {
			midpoint, radius, err := VerifyReply(reply, rootPublicKey, nonces[i])
			if err != nil {
				t.Errorf("error parsing reply #%d: %s", i, err)
				continue
			}

			if midpoint != expectedMidpoint {
				t.Errorf("reply #%d gave a midpoint of %v, want %v", i, midpoint, expectedMidpoint)
			}
			if radius != expectedRadius {
				t.Errorf("reply #%d gave a radius of %d, want %d", i, radius, expectedRadius)
			}
		}
	}
}
