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

// Package protocol implements the core of the Roughtime protocol.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sort"
	"time"
)

const (
	ietfRoughtimeFrame = "ROUGHTIM"
	maxNonceSize       = sha512.Size

	// MinRequestSize is the minimum number of bytes in a request.
	MinRequestSize = 1024

	certificateContext    = "RoughTime v1 delegation signature--\x00"
	signedResponseContext = "RoughTime v1 response signature\x00"
)

// makeTag converts a four character string into a Roughtime tag value.
func makeTag(tag string) uint32 {
	if len(tag) != 4 {
		panic("makeTag: len(tag) != 4: " + tag)
	}

	return uint32(tag[0]) | uint32(tag[1])<<8 | uint32(tag[2])<<16 | uint32(tag[3])<<24
}

var (
	// Various tags used in the Roughtime protocol.
	tagCERT = makeTag("CERT")
	tagDELE = makeTag("DELE")
	tagINDX = makeTag("INDX")
	tagMAXT = makeTag("MAXT")
	tagMIDP = makeTag("MIDP")
	tagMINT = makeTag("MINT")
	tagNONC = makeTag("NONC")
	tagPAD  = makeTag("PAD\xff")
	tagPATH = makeTag("PATH")
	tagPUBK = makeTag("PUBK")
	tagRADI = makeTag("RADI")
	tagROOT = makeTag("ROOT")
	tagSIG  = makeTag("SIG\x00")
	tagSREP = makeTag("SREP")
	tagSRV  = makeTag("SRV\x00")
	tagVER  = makeTag("VER\x00")
	tagZZZZ = makeTag("ZZZZ")
)

// tagsSlice is the type of an array of tags. It provides utility functions so
// that they can be sorted.
type tagsSlice []uint32

func (t tagsSlice) Len() int           { return len(t) }
func (t tagsSlice) Less(i, j int) bool { return t[i] < t[j] }
func (t tagsSlice) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

// Encode converts a map of tags to bytestrings into an encoded message. The
// number of elements in msg and the sum of the lengths of all the bytestrings
// must be ≤ 2**32.
func Encode(msg map[uint32][]byte) ([]byte, error) {
	if len(msg) == 0 {
		return make([]byte, 4), nil
	}

	if len(msg) >= math.MaxInt32 {
		return nil, errors.New("encode: too many tags")
	}

	var payloadSum uint64
	for _, payload := range msg {
		if len(payload)%4 != 0 {
			return nil, errors.New("encode: length of value is not a multiple of four")
		}
		payloadSum += uint64(len(payload))
	}
	if payloadSum >= 1<<32 {
		return nil, errors.New("encode: payloads too large")
	}

	tags := tagsSlice(make([]uint32, 0, len(msg)))
	for tag := range msg {
		tags = append(tags, tag)
	}
	sort.Sort(tags)

	numTags := uint64(len(tags))

	encoded := make([]byte, 4*(1+numTags-1+numTags)+payloadSum)
	binary.LittleEndian.PutUint32(encoded, uint32(len(tags)))
	offsets := encoded[4:]
	tagBytes := encoded[4*(1+(numTags-1)):]
	payloads := encoded[4*(1+(numTags-1)+numTags):]

	currentOffset := uint32(0)

	for i, tag := range tags {
		payload := msg[tag]
		if i > 0 {
			binary.LittleEndian.PutUint32(offsets, currentOffset)
			offsets = offsets[4:]
		}

		binary.LittleEndian.PutUint32(tagBytes, tag)
		tagBytes = tagBytes[4:]

		if len(payload) > 0 {
			copy(payloads, payload)
			payloads = payloads[len(payload):]
			currentOffset += uint32(len(payload))
		}
	}

	return encoded, nil
}

// Decode parses the output of encode back into a map of tags to bytestrings.
func Decode(bytes []byte) (map[uint32][]byte, error) {
	if len(bytes) < 4 {
		return nil, errDecode("message too short to be valid")
	}
	if len(bytes)%4 != 0 {
		return nil, errDecode("message is not a multiple of four bytes")
	}

	numTags := uint64(binary.LittleEndian.Uint32(bytes))

	if numTags == 0 {
		return make(map[uint32][]byte), nil
	}

	minLen := 4 * (1 + (numTags - 1) + numTags)

	if uint64(len(bytes)) < minLen {
		return nil, errDecode("message too short to be valid")
	}

	offsets := bytes[4:]
	tags := bytes[4*(1+numTags-1):]
	payloads := bytes[minLen:]

	if len(payloads) > math.MaxInt32 {
		return nil, errDecode("message too large")
	}
	payloadLength := uint32(len(payloads))

	currentOffset := uint32(0)
	var lastTag uint32
	ret := make(map[uint32][]byte)

	for i := uint64(0); i < numTags; i++ {
		tag := binary.LittleEndian.Uint32(tags)
		tags = tags[4:]

		if i > 0 && lastTag >= tag {
			return nil, errDecode("tags out of order")
		}

		var nextOffset uint32
		if i < numTags-1 {
			nextOffset = binary.LittleEndian.Uint32(offsets)
			offsets = offsets[4:]
		} else {
			nextOffset = payloadLength
		}

		if nextOffset%4 != 0 {
			return nil, errDecode("payload length is not a multiple of four bytes")
		}

		if nextOffset < currentOffset {
			return nil, errDecode("offsets out of order")
		}

		length := nextOffset - currentOffset
		if uint32(len(payloads)) < length {
			return nil, errDecode("message truncated")
		}

		payload := payloads[:length]
		payloads = payloads[length:]
		ret[tag] = payload
		currentOffset = nextOffset
		lastTag = tag
	}

	return ret, nil
}

// messageOverhead returns the number of bytes needed for Encode to encode the
// given number of tags.
func messageOverhead(versionIETF bool, numTags int) int {
	framing := 0
	if versionIETF {
		framing = 12 // "ROUGHTIM" + message length (4 bytes)
	}
	return framing + 4*2*numTags
}

// nonceSize returns the nonce length.
func nonceSize(versionIETF bool) int {
	if !versionIETF {
		return 64
	}
	return 32
}

// CalculateChainNonce fills the `nonce` buffer with the nonce used in the next
// request in a chain given a reply and a blinding factor. The length of the
// buffer is expected to match the nonce length for the protocol version.
func CalculateChainNonce(nonce, prevReply, blind []byte) {
	var out [maxNonceSize]byte
	h := sha512.New()
	h.Write(prevReply)
	h.Sum(out[:0])

	h.Reset()
	h.Write(out[:])
	h.Write(blind)
	h.Sum(out[:0])
	copy(nonce, out[:])
}

// encodeFramed adds IETF message framing to a message.
func encodeFramed(versionIETF bool, msg []byte) []byte {
	if versionIETF {
		framedMsg := make([]byte, 0, 12+len(msg))
		framedMsg = append(framedMsg, ietfRoughtimeFrame...)
		framedMsg = binary.LittleEndian.AppendUint32(framedMsg, uint32(len(msg)))
		framedMsg = append(framedMsg, msg...)
		msg = framedMsg
	}

	return msg
}

// decodeFramed determines if the requester is a legacy client
// (Google-Roughtime) or supports the IETF version. In the later case, it
// removes the IETF message framing.
func decodeFramed(req []byte) ([]byte, bool, error) {
	// In the IETF version of Roughtime, the first eight bytes of the datagram are
	// equal to "ROUGHTIM". In Google-Roughtime, the first four bytes encode the
	// number of tags. This is therefore a good distinguisher as long as "ROUG",
	// interpreted as a little-endian uint32, is not a valid number of tags.
	versionIETF := len(req) >= 8 && bytes.Equal(req[:8], []byte(ietfRoughtimeFrame))

	if versionIETF {
		if len(req) < 8 {
			return nil, false, errDecode("request is too short to encode message frame")
		}
		req = req[8:]

		if len(req) < 4 {
			return nil, false, errDecode("request is too short to encode the message length")
		}
		roughtimeMessageLen := binary.LittleEndian.Uint32(req[:4])
		req = req[4:]

		if len(req) != int(roughtimeMessageLen) {
			return nil, false, errDecode("message has unexpected length")
		}
	}

	return req, versionIETF, nil
}

func handleSRVTag(advertisedPreference []Version) bool {
	for _, version := range advertisedPreference {
		// The SRV tag is first defined in draft-ietf-ntp-roughtime-11
		if version == VersionDraft11 {
			return true
		}
	}
	return false
}

// CreateRequest creates a Roughtime request given an entropy source and the
// contents of a previous reply for chaining. If this request is the first of a
// chain, prevReply can be empty. It returns the nonce (needed to verify the
// reply), the blind (needed to prove correct chaining to an external party)
// and the request itself.
func CreateRequest(versionPreference []Version, rand io.Reader, prevReply []byte, rootPublicKey ed25519.PublicKey) (nonce, blind []byte, request []byte, err error) {
	advertisedVersions, versionIETF, err := advertisedVersionsFromPreference(versionPreference)
	if err != nil {
		return nil, nil, nil, err
	}
	nonceSize := nonceSize(versionIETF)
	nonce = make([]byte, nonceSize)
	blind = make([]byte, nonceSize)
	if _, err := io.ReadFull(rand, blind); err != nil {
		return nil, nil, nil, err
	}

	CalculateChainNonce(nonce, prevReply, blind)

	// Construct the packet.
	packet := make(map[uint32][]byte)
	valuesLen := 0
	numTags := 0

	// NONC
	packet[tagNONC] = nonce
	valuesLen += len(nonce)
	numTags += 1

	// VER
	if versionIETF {
		encoded := make([]byte, 0, len(advertisedVersions)*4)
		for _, ver := range advertisedVersions {
			encoded = binary.LittleEndian.AppendUint32(encoded, uint32(ver))
		}
		packet[tagVER] = encoded
		valuesLen += len(encoded)
		numTags += 1
	}

	// SRV
	if handleSRVTag(advertisedVersions) {
		srv := make([]byte, 0, 64)
		h := sha512.New()
		h.Write([]byte{0xff})
		h.Write(rootPublicKey)
		h.Sum(srv)
		srv = srv[:32]
		packet[tagSRV] = srv
		valuesLen += len(nonce)
		numTags += 1
	}

	// Padding (PAD in Google-Roughtime or ZZZZ in the IETF version)
	var paddingTag uint32
	if versionIETF {
		paddingTag = tagZZZZ
	} else {
		paddingTag = tagPAD
	}
	padding := make([]byte, MinRequestSize-messageOverhead(versionIETF, numTags+1)-valuesLen)
	packet[paddingTag] = padding

	msg, err := Encode(packet)
	if err != nil {
		return nil, nil, nil, err
	}

	return nonce, blind, encodeFramed(versionIETF, msg), nil
}

// tree represents a Merkle tree of nonces. Each element of values is a layer
// in the tree, with the widest layer first.
type tree struct {
	values [][][maxNonceSize]byte
}

var (
	hashLeafTweak = []byte{0}
	hashNodeTweak = []byte{1}
)

// hashLeaf hashes an nonce to form the leaf of the Merkle tree.
func hashLeaf(out *[maxNonceSize]byte, in []byte) {
	h := sha512.New()
	h.Write(hashLeafTweak)
	h.Write(in)
	h.Sum(out[:0])
}

// hashNode hashes two child elements of the Merkle tree to produce an interior
// node.
func hashNode(out *[maxNonceSize]byte, left, right []byte) {
	h := sha512.New()
	h.Write(hashNodeTweak)
	h.Write(left)
	h.Write(right)
	h.Sum(out[:0])
}

// newTree creates a Merkle tree given one or more nonces.
func newTree(nonceSize int, requests []Request) *tree {
	if len(requests) == 0 {
		panic("newTree: passed empty slice")
	}

	levels := 1
	width := len(requests)
	for width > 1 {
		width = (width + 1) / 2
		levels++
	}

	ret := &tree{
		values: make([][][maxNonceSize]byte, 0, levels),
	}

	leaves := make([][maxNonceSize]byte, ((len(requests)+1)/2)*2)
	for i, req := range requests {
		var leaf [maxNonceSize]byte
		hashLeaf(&leaf, req.Nonce)
		leaves[i] = leaf
	}
	// Fill any extra leaves with an existing leaf, to simplify analysis
	// that we are not inadvertently signing other messages.
	for i := len(requests); i < len(leaves); i++ {
		leaves[i] = leaves[0]
	}
	ret.values = append(ret.values, leaves)

	for i := 1; i < levels; i++ {
		lastLevel := ret.values[i-1]
		width := len(lastLevel) / 2
		if width%2 == 1 {
			width++
		}
		level := make([][maxNonceSize]byte, width)
		for j := 0; j < len(lastLevel)/2; j++ {
			hashNode(&level[j], lastLevel[j*2][:nonceSize], lastLevel[j*2+1][:nonceSize])
		}
		// Fill the extra node with an existing node, to simplify
		// analysis that we are not inadvertently signing other
		// messages.
		if len(lastLevel)/2 < len(level) {
			level[len(lastLevel)/2] = level[0]
		}
		ret.values = append(ret.values, level)
	}

	return ret
}

// Root returns the root value of t.
func (t *tree) Root() *[maxNonceSize]byte {
	return &t.values[len(t.values)-1][0]
}

// Levels returns the number of levels in t.
func (t *tree) Levels() int {
	return len(t.values)
}

// Path returns elements from t needed to prove, given the root, that the leaf
// at the given index is in the tree.
func (t *tree) Path(index int) (path [][]byte) {
	path = make([][]byte, 0, len(t.values))

	for level := 0; level < len(t.values)-1; level++ {
		if index%2 == 1 {
			path = append(path, t.values[level][index-1][:])
		} else {
			path = append(path, t.values[level][index+1][:])
		}

		index /= 2
	}

	return path
}

// Request is a request sent by a client.
type Request struct {
	// Nonce is the request nonce.
	Nonce []byte
	// Nonce is the sequence of versions advertised by the client, ordered from
	// most to least preferred.
	Versions []Version
	// srv is the SRV tag indicating which root public key the client is
	// expecting to verify the response with.
	srv []byte
}

// ParseRequest resolves the supported versions indicated by the client and
// parses the values required to produce a response.
func ParseRequest(bytes []byte) (req *Request, err error) {
	if len(bytes) < MinRequestSize {
		return nil, errRequestLen
	}

	msg, versionIETF, err := decodeFramed(bytes)
	if err != nil {
		return nil, err
	}

	packet, err := Decode(msg)
	if err != nil {
		return nil, err
	}

	nonce, ok := packet[tagNONC]
	if !ok || len(nonce) != nonceSize(versionIETF) {
		return nil, errNonceLen
	}

	var versions []Version
	if versionIETF {
		encoded, ok := packet[tagVER]
		if !ok {
			return nil, errMissingVersion
		}
		for len(encoded) > 0 {
			if len(encoded) < 4 {
				return nil, errDecode("malformed version list")
			}

			ver := Version(binary.LittleEndian.Uint32(encoded[:4]))
			if ver.isSupported() {
				// De-duplicate any repeated version.
				ok := true
				for i := range versions {
					if versions[i] == ver {
						ok = false
						break
					}
				}
				if ok {
					versions = append(versions, ver)
				}
			}
			encoded = encoded[4:]
		}
	} else {
		versions = []Version{VersionGoogle}
	}

	var srv []byte
	if handleSRVTag(versions) {
		srv = packet[tagSRV]
	}

	return &Request{nonce, versions, srv}, nil
}

// CreateReplies signs, using privateKey, a batch of nonces along with the
// given time and radius. It returns one reply for each nonce using that
// signature and includes cert in each.
//
// The same version is indicated in each reply. It's the callers responsibility
// to ensure that each client supports this version.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	versionIETF := ver != VersionGoogle
	nonceSize := nonceSize(versionIETF)

	if len(requests) == 0 {
		return nil, nil
	}

	tree := newTree(nonceSize, requests)

	// Convert the midpoint and radius to their Roughtime representation.
	var midPointUint64 uint64
	var radiusUint32 uint32
	if versionIETF {
		midPointUint64 = uint64(midpoint.Unix())
		radiusUint32 = uint32(radius.Seconds())
	} else {
		midPointUint64 = uint64(midpoint.UnixMicro())
		radiusUint32 = uint32(radius.Microseconds())
	}

	var midpointBytes [8]byte
	binary.LittleEndian.PutUint64(midpointBytes[:], midPointUint64)
	var radiusBytes [4]byte
	binary.LittleEndian.PutUint32(radiusBytes[:], radiusUint32)

	signedReply := map[uint32][]byte{
		tagMIDP: midpointBytes[:],
		tagRADI: radiusBytes[:],
		tagROOT: tree.Root()[:nonceSize],
	}

	signedReplyBytes, err := Encode(signedReply)
	if err != nil {
		return nil, err
	}

	toBeSigned := signedResponseContext + string(signedReplyBytes)
	sig := ed25519.Sign(cert.onlinePrivateKey, []byte(toBeSigned))

	reply := map[uint32][]byte{
		tagSREP: signedReplyBytes,
		tagSIG:  sig,
		tagCERT: cert.BytesForVersion(ver),
	}

	if versionIETF {
		encoded := make([]byte, 0, 4)
		encoded = binary.LittleEndian.AppendUint32(encoded, uint32(ver))
		reply[tagVER] = encoded
	}

	replies := make([][]byte, 0, len(requests))

	for i := range requests {
		var indexBytes [4]byte
		binary.LittleEndian.PutUint32(indexBytes[:], uint32(i))
		reply[tagINDX] = indexBytes[:]

		path := tree.Path(i)
		pathBytes := make([]byte, 0, nonceSize*len(path))
		for _, pathStep := range path {
			pathBytes = append(pathBytes, pathStep[:nonceSize]...)
		}
		reply[tagPATH] = pathBytes

		replyBytes, err := Encode(reply)
		if err != nil {
			return nil, err
		}

		replies = append(replies, encodeFramed(versionIETF, replyBytes))
	}

	return replies, nil
}

type Certificate struct {
	// googleBytes is the certificate we send to legacy clients
	// (Google-Roughtime). The MINT and MAXT fields encode timestamps in
	// microseconds.
	googleBytes []byte
	bytes       []byte

	// onlinePrivateKey is the online private key.
	onlinePrivateKey ed25519.PrivateKey

	// srv is the payload of the SRV tag that the client would send to indicate
	// the root public key delegated by this certificate.
	srv ed25519.PublicKey
}

// BytesForVersion returns a serialized certificate compatible with the given
// version. Legacy clients (Google-Roughtime) expect a non-standard encoding of
// the MINT and MAXT fields.
func (cert *Certificate) BytesForVersion(ver Version) []byte {
	switch ver {
	case VersionGoogle:
		return cert.googleBytes
	default:
		return cert.bytes
	}
}

// Select a certificate suitable for responding to the request.
func SelectCertificateForRequest(req *Request, certs []Certificate) *Certificate {
	// Return the first certificate for which the root public key was indicated
	// by the client.
	for _, cert := range certs {
		if bytes.Equal(req.srv, cert.srv) {
			return &cert
		}
	}

	// If no SRV tag was sent, then guess the first certificate.
	if len(req.srv) == 0 && len(certs) > 0 {
		return &certs[0]
	}

	// The SRV tag indicates an unknown root public key, or the certificate
	// list is empty.
	return nil
}

// NewCertificate returns a signed certificate, using rootPrivateKey,
// delegating authority for the given timestamp to onlinePrivateKey.
func NewCertificate(minTime, maxTime time.Time, onlinePrivateKey, rootPrivateKey ed25519.PrivateKey) (cert *Certificate, err error) {
	if maxTime.Before(minTime) {
		return nil, errors.New("protocol: maxTime < minTime")
	}

	certs := make([][]byte, 2)
	for i, t := range []struct {
		minTime uint64
		maxTime uint64
	}{
		// Legacy (Google-Roughtime)
		{
			minTime: uint64(minTime.UnixMicro()),
			maxTime: uint64(maxTime.UnixMicro()),
		},
		// IETF
		{
			minTime: uint64(minTime.Unix()),
			maxTime: uint64(maxTime.Unix()),
		},
	} {
		var minTimeBytes, maxTimeBytes [8]byte
		binary.LittleEndian.PutUint64(minTimeBytes[:], t.minTime)
		binary.LittleEndian.PutUint64(maxTimeBytes[:], t.maxTime)

		signed := map[uint32][]byte{
			tagPUBK: ed25519.PrivateKey(onlinePrivateKey).Public().(ed25519.PublicKey),
			tagMINT: minTimeBytes[:],
			tagMAXT: maxTimeBytes[:],
		}

		signedBytes, err := Encode(signed)
		if err != nil {
			return nil, err
		}

		toBeSigned := certificateContext + string(signedBytes)
		sig := ed25519.Sign(rootPrivateKey, []byte(toBeSigned))

		cert := map[uint32][]byte{
			tagSIG:  sig,
			tagDELE: signedBytes,
		}

		certs[i], err = Encode(cert)
		if err != nil {
			return nil, err
		}
	}

	// SRV
	srv := make([]byte, 0, 64)
	h := sha512.New()
	h.Write([]byte{0xff})
	h.Write(ed25519.PrivateKey(rootPrivateKey).Public().(ed25519.PublicKey))
	h.Sum(srv)
	srv = srv[:32]

	return &Certificate{
		googleBytes:      certs[0],
		bytes:            certs[1],
		onlinePrivateKey: onlinePrivateKey,
		srv:              srv,
	}, nil
}

func getValue(msg map[uint32][]byte, tag uint32, name string) (value []byte, err error) {
	value, ok := msg[tag]
	if !ok {
		return nil, errors.New("protocol: missing " + name)
	}
	return value, nil
}

func getFixedLength(msg map[uint32][]byte, tag uint32, name string, length int) (value []byte, err error) {
	value, err = getValue(msg, tag, name)
	if err != nil {
		return nil, err
	}
	if len(value) != length {
		return nil, errors.New("protocol: incorrect length for " + name)
	}
	return value, nil
}

func getUint32(msg map[uint32][]byte, tag uint32, name string) (result uint32, err error) {
	valueBytes, err := getFixedLength(msg, tag, name, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(valueBytes), nil
}

func getUint64(msg map[uint32][]byte, tag uint32, name string) (result uint64, err error) {
	valueBytes, err := getFixedLength(msg, tag, name, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(valueBytes), nil
}

func getSubmessage(msg map[uint32][]byte, tag uint32, name string) (result map[uint32][]byte, err error) {
	valueBytes, err := getValue(msg, tag, name)
	if err != nil {
		return nil, err
	}

	result, err = Decode(valueBytes)
	if err != nil {
		return nil, errors.New("protocol: failed to parse " + name + ": " + err.Error())
	}

	return result, nil
}

// VerifyReply parses the Roughtime reply in replyBytes, authenticates it using
// publicKey and verifies that nonce is included in it. It returns the included
// timestamp and radius.
func VerifyReply(versionPreference []Version, replyBytes, publicKey []byte, nonce []byte) (midp time.Time, radi time.Duration, err error) {
	advertisedVersions, versionIETF, err := advertisedVersionsFromPreference(versionPreference)
	if err != nil {
		return midp, radi, err
	}
	nonceSize := nonceSize(versionIETF)

	unframedReply, _, err := decodeFramed(replyBytes)
	if err != nil {
		return midp, radi, err
	}

	reply, err := Decode(unframedReply)
	if err != nil {
		return midp, radi, errors.New("protocol: failed to parse top-level reply: " + err.Error())
	}

	// Make sure the version selected by the server matches one that we advertised.
	var responseVer Version
	if versionIETF {
		encoded, ok := reply[tagVER]
		if !ok {
			return midp, radi, errMissingVersion
		}
		if len(encoded) != 4 {
			return midp, radi, errDecode("malformed version")
		}

		responseVer = Version(binary.LittleEndian.Uint32(encoded[:]))
	} else {
		responseVer = VersionGoogle
	}
	versionOK := false
	for _, ver := range advertisedVersions {
		if responseVer == ver {
			versionOK = true
			break
		}
	}
	if !versionOK {
		return midp, radi, errUnsupportedVersion([]Version{responseVer})
	}

	cert, err := getSubmessage(reply, tagCERT, "certificate")
	if err != nil {
		return midp, radi, err
	}

	signatureBytes, err := getFixedLength(cert, tagSIG, "signature", ed25519.SignatureSize)
	if err != nil {
		return midp, radi, err
	}

	delegationBytes, err := getValue(cert, tagDELE, "delegation")
	if err != nil {
		return midp, radi, err
	}

	if !ed25519.Verify(publicKey, []byte(certificateContext+string(delegationBytes)), signatureBytes) {
		return midp, radi, errors.New("protocol: invalid delegation signature")
	}

	delegation, err := Decode(delegationBytes)
	if err != nil {
		return midp, radi, errors.New("protocol: failed to parse delegation: " + err.Error())
	}

	minTime, err := getUint64(delegation, tagMINT, "minimum time")
	if err != nil {
		return midp, radi, err
	}

	maxTime, err := getUint64(delegation, tagMAXT, "maximum time")
	if err != nil {
		return midp, radi, err
	}

	delegatedPublicKey, err := getFixedLength(delegation, tagPUBK, "public key", ed25519.PublicKeySize)
	if err != nil {
		return midp, radi, err
	}

	responseSigBytes, err := getFixedLength(reply, tagSIG, "signature", ed25519.SignatureSize)
	if err != nil {
		return midp, radi, err
	}

	signedResponseBytes, ok := reply[tagSREP]
	if !ok {
		return midp, radi, errors.New("protocol: response is missing signed portion")
	}

	if !ed25519.Verify(delegatedPublicKey, []byte(signedResponseContext+string(signedResponseBytes)), responseSigBytes) {
		return midp, radi, errors.New("protocol: invalid response signature")
	}

	signedResponse, err := Decode(signedResponseBytes)
	if err != nil {
		return midp, radi, errors.New("protocol: failed to parse signed response: " + err.Error())
	}

	root, err := getFixedLength(signedResponse, tagROOT, "root", nonceSize)
	if err != nil {
		return midp, radi, err
	}

	midpoint, err := getUint64(signedResponse, tagMIDP, "midpoint")
	if err != nil {
		return midp, radi, err
	}

	radius, err := getUint32(signedResponse, tagRADI, "radius")
	if err != nil {
		return midp, radi, err
	}

	if maxTime < minTime {
		return midp, radi, errors.New("protocol: invalid delegation range")
	}

	if midpoint < minTime || maxTime < midpoint {
		return midp, radi, errors.New("protocol: timestamp out of range for delegation")
	}

	index, err := getUint32(reply, tagINDX, "index")
	if err != nil {
		return midp, radi, err
	}

	path, err := getValue(reply, tagPATH, "path")
	if err != nil {
		return midp, radi, err
	}
	if len(path)%nonceSize != 0 {
		return midp, radi, errors.New("protocol: path is not a multiple of the hash size")
	}

	var hash [maxNonceSize]byte
	hashLeaf(&hash, nonce)

	for len(path) > 0 {
		pathElementIsRight := index&1 == 0
		if pathElementIsRight {
			hashNode(&hash, hash[:nonceSize], path[:nonceSize])
		} else {
			hashNode(&hash, path[:nonceSize], hash[:nonceSize])
		}

		index >>= 1
		path = path[nonceSize:]
	}

	if !bytes.Equal(hash[:nonceSize], root) {
		return midp, radi, errors.New("protocol: calculated tree root doesn't match signed root")
	}

	if versionIETF {
		midp = time.Unix(int64(midpoint), 0)
		radi = time.Duration(radius) * time.Second
	} else {
		midp = time.UnixMicro(int64(midpoint))
		radi = time.Duration(radius) * time.Microsecond
	}
	return
}
