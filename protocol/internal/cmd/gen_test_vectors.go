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

// Generate test vectors consumed by the unit tests for the protocol package.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/roughtime/protocol"
	"github.com/cloudflare/roughtime/protocol/internal/testing"
)

const (
	ROOT_KEY_HEX   = "d102b712f341204711daaf20e0d13557a37073e9c25325c1c6bda876eb2d6a2d"
	ONLINE_KEY_HEX = "613bbf61d362d6474041486a9440feeb7cc71b48951a30e7b0190be42bc7a5ab"
)

var (
	rootPrivateKey   ed25519.PrivateKey
	rootPublicKey    ed25519.PublicKey
	onlinePrivateKey ed25519.PrivateKey
	onlineCert       *protocol.Certificate

	testMinTime  = time.Unix(0, 0)
	testMaxTime  = time.Unix(100, 0)
	testMidpoint = time.Unix(50, 0)
	testRadius   = time.Duration(5) * time.Second
)

func init() {
	rootKeySeed, err := hex.DecodeString(ROOT_KEY_HEX)
	if err != nil {
		panic(err)
	}
	rootPrivateKey = ed25519.NewKeyFromSeed(rootKeySeed)
	rootPublicKey = rootPrivateKey.Public().(ed25519.PublicKey)

	onlineKeySeed, err := hex.DecodeString(ONLINE_KEY_HEX)
	if err != nil {
		panic(err)
	}
	onlinePrivateKey = ed25519.NewKeyFromSeed(onlineKeySeed)
	onlineCert, err = protocol.NewCertificate(testMinTime, testMaxTime, onlinePrivateKey, rootPrivateKey)
	if err != nil {
		panic(err)
	}
}

func ensureDir(dirName string) error {
	err := os.Mkdir(dirName, 0777)
	if err == nil {
		return nil
	}
	if os.IsExist(err) {
		// Check that the existing path is a directory.
		info, err := os.Stat(dirName)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("path exists but is not a directory")
		}
		return nil
	}
	return err
}

func fileNmameFor(ver protocol.Version) string {
	switch ver {
	case protocol.VersionGoogle:
		return "roughtime_google"
	case protocol.VersionDraft08:
		return "roughtime_ietf_draft08"
	case protocol.VersionDraft11:
		return "roughtime_ietf_draft11"
	default:
		panic("unhandled version")
	}
}

func main() {
	if err := ensureDir("testdata"); err != nil {
		panic(err)
	}

	for _, ver := range []protocol.Version{protocol.VersionDraft11, protocol.VersionDraft08, protocol.VersionGoogle} {
		r := testing.NewTestRand()
		clientVersionPref := []protocol.Version{ver}

		for _, numRequestsPerBatch := range []int{1, 10, 100} {
			var testVec testing.TestVector
			testVec.Info = fmt.Sprintf("%s %d", ver, numRequestsPerBatch)
			testVec.RootKey = ROOT_KEY_HEX
			testVec.OnlineKey = ONLINE_KEY_HEX

			// Set the requests and replies.
			nonces := make([][]byte, 0, numRequestsPerBatch)
			for i := 0; i < numRequestsPerBatch; i++ {
				nonce, _, request, err := protocol.CreateRequest(clientVersionPref, r, nil, rootPublicKey)
				if err != nil {
					panic(err)
				}
				testVec.Requests = append(testVec.Requests, hex.EncodeToString(request))
				nonces = append(nonces, nonce[:])
			}

			replies, err := protocol.CreateReplies(ver, nonces, testMidpoint, testRadius, onlineCert)
			if err != nil {
				panic(err)
			}

			for i := 0; i < numRequestsPerBatch; i++ {
				_, _, err = protocol.VerifyReply(clientVersionPref, replies[i], rootPublicKey, nonces[i])
				if err != nil {
					panic(err)
				}

				testVec.Replies = append(testVec.Replies, hex.EncodeToString(replies[i]))
			}

			testVecBytes, err := json.Marshal(&testVec)
			if err != nil {
				panic(err)
			}

			f, err := os.Create(fmt.Sprintf("testdata/%s_%03d.json", fileNmameFor(ver), numRequestsPerBatch))
			if err != nil {
				panic(err)
			}
			if _, err = f.Write(testVecBytes); err != nil {
				panic(err)
			}
			f.Close()
		}
	}
}
