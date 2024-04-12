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

// Modifications copyright 2023 Cloudflare, Inc.
//
// The code has been extended to support IETF-Roughtime.

//go:generate go run ./internal/cmd/gen_test_vectors.go

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
	"testing/quick"
	"time"

	protocolTesting "github.com/cloudflare/roughtime/protocol/internal/testing"
)

var (
	testMinTime  = time.Unix(0, 0)
	testMaxTime  = time.Unix(100, 0)
	testMidpoint = time.Unix(50, 0)
	testRadius   = time.Duration(5) * time.Second
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
	if err := quick.Check(testEncodeDecodeRoundtrip, &quick.Config{
		MaxCountScale: 10,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRequestSize(t *testing.T) {
	for _, ver := range allVersions {
		t.Run(ver.String(), func(t *testing.T) {
			_, _, request, err := CreateRequest([]Version{ver}, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(request) != MinRequestSize {
				t.Errorf("got %d byte request, want %d bytes", len(request), MinRequestSize)
			}
		})
	}
}

func createServerIdentity(t *testing.T) (cert *Certificate, rootPublicKey, onlinePrivateKey []byte) {
	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	onlinePublicKey, onlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if cert, err = NewCertificate(testMinTime, testMaxTime, onlinePublicKey, rootPrivateKey); err != nil {
		t.Fatal(err)
	}

	return cert, rootPublicKey, onlinePrivateKey
}

func TestRunTestVectors(t *testing.T) {
	for _, fileName := range []string{
		"testdata/roughtime_ietf_draft08_001.json",
		"testdata/roughtime_ietf_draft08_010.json",
		"testdata/roughtime_ietf_draft08_100.json",
		"testdata/roughtime_google_001.json",
		"testdata/roughtime_google_010.json",
		"testdata/roughtime_google_100.json",
	} {
		f, err := os.Open(fileName)
		if err != nil {
			t.Fatal(err)
		}

		testVecBytes, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}

		var testVec protocolTesting.TestVector
		if err = json.Unmarshal(testVecBytes, &testVec); err != nil {
			t.Fatal(err)
		}

		t.Run(testVec.Info, func(t *testing.T) {
			rootKeySeed, err := hex.DecodeString(testVec.RootKey)
			if err != nil {
				t.Fatal(err)
			}
			rootPrivateKey := ed25519.NewKeyFromSeed(rootKeySeed)
			rootPublicKey := rootPrivateKey.Public().(ed25519.PublicKey)

			onlineKeySeed, err := hex.DecodeString(testVec.OnlineKey)
			if err != nil {
				t.Fatal(err)
			}
			onlinePrivateKey := ed25519.NewKeyFromSeed(onlineKeySeed)
			onlinePublicKey := onlinePrivateKey.Public().(ed25519.PublicKey)
			onlineCert, err := NewCertificate(testMinTime, testMaxTime, onlinePublicKey, rootPrivateKey)
			if err != nil {
				panic(err)
			}

			nonces := make([][]byte, 0)
			advertisedVersions := make(map[Version]uint)
			for _, ver := range allVersions {
				advertisedVersions[ver] = 0
			}
			for _, request := range testVec.Requests {
				requestBytes, err := hex.DecodeString(request)
				if err != nil {
					t.Fatal(err)
				}

				nonce, vers, err := HandleRequest(requestBytes)
				if err != nil {
					t.Fatal(err)
				}

				for _, ver := range vers {
					advertisedVersions[ver] += 1
				}

				nonces = append(nonces, nonce)
			}

			supportedVersions := make([]Version, 0, len(allVersions))
			for ver, advertisementCount := range advertisedVersions {
				if advertisementCount > 0 {
					supportedVersions = append(supportedVersions, ver)
				}
			}
			responseVer, err := ResponseVersionFromSupported(supportedVersions)
			if err != nil {
				t.Fatal(err)
			}

			replies, err := CreateReplies(responseVer, nonces, testMidpoint, testRadius, onlineCert, onlinePrivateKey)
			if err != nil {
				t.Fatal(err)
			}

			// Infer the client's configuration. (The client must have supported the response version.)
			for i := range replies {
				expectedReply, err := hex.DecodeString(testVec.Replies[i])
				if err != nil {
					t.Fatal(err)
				}

				// Check that the replies match the test vector.
				if !bytes.Equal(replies[i], expectedReply) {
					t.Error("unexpected reply")
				}

				// Make sure the responses verify properly.
				_, _, err = VerifyReply([]Version{responseVer}, replies[i], rootPublicKey, nonces[i])
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestRoundtrip(t *testing.T) {
	cert, rootPublicKey, onlinePrivateKey := createServerIdentity(t)

	for _, ver := range allVersions {
		t.Run(ver.String(), func(t *testing.T) {
			for _, numRequests := range []int{1, 2, 3, 4, 5, 15, 16, 17} {
				advertisedVersions := make(map[Version]uint)
				for _, ver := range allVersions {
					advertisedVersions[ver] = 0
				}

				nonces := make([][]byte, 0, numRequests)
				for i := 0; i < numRequests; i++ {
					nonceSent, _, request, err := CreateRequest([]Version{ver}, rand.Reader, nil)
					if err != nil {
						panic(err)
					}

					nonceReceived, vers, err := HandleRequest(request)
					if err != nil {
						t.Fatal(err)
					}

					if !bytes.Equal(nonceSent, nonceReceived) {
						t.Fatal("received nonce does not match sent")
					}

					for _, ver := range vers {
						advertisedVersions[ver] += 1
					}

					nonces = append(nonces, nonceReceived)
				}

				supportedVersions := make([]Version, 0, len(allVersions))
				for ver, advertisementCount := range advertisedVersions {
					if advertisementCount > 0 {
						supportedVersions = append(supportedVersions, ver)
					}
				}
				responseVer, err := ResponseVersionFromSupported(supportedVersions)
				if err != nil {
					t.Fatal(err)
				}

				replies, err := CreateReplies(responseVer, nonces, testMidpoint, testRadius, cert, onlinePrivateKey)
				if err != nil {
					t.Fatal(err)
				}

				if len(replies) != len(nonces) {
					t.Fatalf("received %d replies for %d nonces", len(replies), len(nonces))
				}

				for i, reply := range replies {
					midpoint, radius, err := VerifyReply([]Version{responseVer}, reply, rootPublicKey, nonces[i])
					if err != nil {
						t.Errorf("error parsing reply #%d: %s", i, err)
						continue
					}

					if midpoint != testMidpoint {
						t.Errorf("reply #%d gave a midpoint of %v, want %v", i, midpoint, testMidpoint)
					}
					if radius != testRadius {
						t.Errorf("reply #%d gave a radius of %d, want %d", i, radius, testRadius)
					}
				}
			}
		})
	}
}

func TestChaining(t *testing.T) {
	// This test demonstrates how a claim of misbehaviour from a client
	// would be checked. The client creates a two element chain in this
	// example where the first server says that the time is 10 and the
	// second says that it's 5.
	certA, rootPublicKeyA, onlinePrivateKeyA := createServerIdentity(t)
	certB, rootPublicKeyB, onlinePrivateKeyB := createServerIdentity(t)

	for _, ver := range allVersions {
		t.Run(ver.String(), func(t *testing.T) {
			nonce1, _, _, err := CreateRequest([]Version{ver}, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}

			replies1, err := CreateReplies(ver, [][]byte{nonce1[:]}, testMidpoint, testRadius, certA, onlinePrivateKeyA)
			if err != nil {
				t.Fatal(err)
			}

			nonce2, blind2, _, err := CreateRequest([]Version{ver}, rand.Reader, replies1[0])
			if err != nil {
				t.Fatal(err)
			}

			replies2, err := CreateReplies(ver, [][]byte{nonce2[:]}, testMidpoint.Add(time.Duration(-10)*time.Second), testRadius, certB, onlinePrivateKeyB)
			if err != nil {
				t.Fatal(err)
			}

			// The client would present a series of tuples of (server identity,
			// nonce/blind, reply) as its claim of misbehaviour. The first element
			// contains a nonce where as all other elements contain just the
			// blinding value, as the nonce used for that request is calculated
			// from that and the previous reply.
			type claimStep struct {
				serverPublicKey []byte
				nonceOrBlind    []byte
				reply           []byte
			}

			claim := []claimStep{
				{rootPublicKeyA, nonce1, replies1[0]},
				{rootPublicKeyB, blind2, replies2[0]},
			}

			// In order to verify a claim, one would check each of the replies
			// based on the calculated nonce.
			var lastMidpoint time.Time
			var misbehaviourFound bool
			for i, step := range claim {
				nonce := make([]byte, len(step.nonceOrBlind))
				if i == 0 {
					copy(nonce[:], step.nonceOrBlind[:])
				} else {
					CalculateChainNonce(nonce, claim[i-1].reply, step.nonceOrBlind)
				}
				midpoint, _, err := VerifyReply([]Version{ver}, step.reply, step.serverPublicKey, nonce)
				if err != nil {
					t.Fatal(err)
				}

				// This example doesn't take the radius into account.
				if i > 0 && midpoint.Before(lastMidpoint) {
					misbehaviourFound = true
				}
				lastMidpoint = midpoint
			}

			if !misbehaviourFound {
				t.Error("did not find expected misbehaviour")
			}
		})
	}
}

// Test that tag constants match values in the tag registry (draft-ietf-ntp-roughtime-08, Section 12.3)
func TestIETFTags(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{
			name: "VER",
			got:  tagVER,
			want: 0x00524556,
		},
		{
			name: "ZZZZ",
			got:  tagZZZZ,
			want: 0x5a5a5a5a,
		},
	} {
		if tc.got != tc.want {
			t.Errorf("%s mismatch: got %04x; want %04x", tc.name, tc.got, tc.want)
		}
	}
}

func TestServerIgnoresUnrecognizedVersions(t *testing.T) {
	for _, ver := range ietfVersions {
		t.Run(ver.String(), func(t *testing.T) {
			_, _, request, err := CreateRequest([]Version{0x1234578, ver, 0xffffffff, ver}, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}

			_, vers, err := HandleRequest(request)
			if err != nil {
				t.Fatal(err)
			}

			if len(vers) != 1 || vers[0] != ver {
				t.Fatal("unexpected version")
			}
		})
	}
}

// Test that if no version preference is specified, then the client defaults to
// IETF-Roughtime.
func TestEmptyVersionPreference(t *testing.T) {
	advertisedVersions, versionIETF, err := advertisedVersionsFromPreference(nil)
	if err != nil {
		t.Fatal(err)
	}

	if versionIETF != true {
		t.Fatal("versionIETF: got false; want true")
	}

	if len(advertisedVersions) != len(ietfVersions) {
		t.Fatalf("len(advertisedVersions): got %d; want %d", len(advertisedVersions), len(ietfVersions))
	}

	for i := range advertisedVersions {
		if advertisedVersions[i] != ietfVersions[i] {
			t.Fatalf("advertisedVersions: got %q; want %q", advertisedVersions, ietfVersions)
		}
	}
}
