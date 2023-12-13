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

package protocol

import "fmt"

// ErrorType is an error type.
type ErrorType uint16

const (
	ErrorDecode ErrorType = iota
	ErrorNonceLen
	ErrorRequestLen
	ErrorUnsupportedVersion
	ErrorMissingVersion
)

// Error represents a protocol error.
type Error struct {
	// Type is the error type.
	Type ErrorType

	// Info includes optional info.
	Info string
}

func (e Error) Error() string {
	s := ""
	switch e.Type {
	case ErrorDecode:
		s += "decode"
	case ErrorNonceLen:
		s += "nonce length"
	case ErrorRequestLen:
		s += "request length"
	case ErrorUnsupportedVersion:
		s += "no version in common"
	case ErrorMissingVersion:
		s += "missing VER tag"
	default:
		s += "unknown"
	}
	if len(e.Info) > 0 {
		s += ": " + e.Info
	}
	return s
}

func errDecode(info string) Error {
	return Error{
		Type: ErrorDecode,
		Info: info,
	}
}

func errUnsupportedVersion(vers []Version) Error {
	return Error{
		Type: ErrorUnsupportedVersion,
		Info: fmt.Sprintf("%q", vers),
	}
}

var (
	errNonceLen = Error{
		Type: ErrorNonceLen,
		Info: "",
	}
	errRequestLen = Error{
		Type: ErrorRequestLen,
		Info: "",
	}
	errMissingVersion = Error{
		Type: ErrorMissingVersion,
		Info: "",
	}
)
