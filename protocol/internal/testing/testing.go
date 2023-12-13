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

package testing

// TestVector encodes test vectors.
type TestVector struct {
	// Info encodes some high level information about the test vector.
	Info string `json:"info"`

	// RootKey is the hex-encoded ed25519 key seed used to generate the root
	// key pair.
	RootKey string `json:"root_key"`

	// OnlineKey is the hex-encoded ed25519 key seed used to generate the
	// online key pair.
	OnlineKey string `json:"online_key"`

	// Requests is a sequence of hex-encoded requests.
	Requests []string `json:"request"`

	// Replies is a sequence of hex-encoded replies corresponding to
	// `Requests`. The requests are handled as a batch.
	Replies []string `json:"replies"`
}

// TestRand implements io/Reader using a fixed sequence of bytes. It is
// intended to be used in place of crypto/Rand for tests that we want to be
// deterministic.
type TestRand struct {
	nextByte uint
	byteWrap uint
}

func (r *TestRand) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = byte(r.nextByte)
		r.nextByte = (r.nextByte + 1) % r.byteWrap
	}
	return len(b), nil
}

// NewTestRand returns an instance of TestRand.
func NewTestRand() *TestRand {
	return &TestRand{
		nextByte: 0,
		// Pick a modulus that is not a multiple of the Roughtime nonce size so
		// that when generating many nonces at once we're likley to not have a
		// repeat.
		byteWrap: 253,
	}
}
