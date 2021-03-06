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

// Package protocol implements the core of the Roughtime protocol.

// Modified by Cloudflare 2020 to implement draft version 03 and succeeding.
package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/cloudflare/roughtime/mjd"
	"github.com/cloudflare/roughtime/sha512trunc"
	"golang.org/x/crypto/ed25519"
)

const (
	Version = 0x80000003
	// NonceSize is the number of bytes in a nonce.
	NonceSize = 32
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
	tagDUT1 = makeTag("DUT1")
	tagDTAI = makeTag("DTAI")
	tagINDX = makeTag("INDX")
	tagLEAP = makeTag("LEAP")
	tagMAXT = makeTag("MAXT")
	tagMIDP = makeTag("MIDP")
	tagMINT = makeTag("MINT")
	tagNONC = makeTag("NONC")
	tagPAD  = makeTag("PAD\x00")
	tagPATH = makeTag("PATH")
	tagPUBK = makeTag("PUBK")
	tagRADI = makeTag("RADI")
	tagROOT = makeTag("ROOT")
	tagSIG  = makeTag("SIG\x00")
	tagSREP = makeTag("SREP")
	tagVER  = makeTag("VER\x00")

	// TagNonce names the bytestring containing the client's nonce.
	TagNonce = tagNONC
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
		return nil, errors.New("decode: message too short to be valid")
	}
	if len(bytes)%4 != 0 {
		return nil, errors.New("decode: message is not a multiple of four bytes")
	}

	numTags := uint64(binary.LittleEndian.Uint32(bytes))

	if numTags == 0 {
		return make(map[uint32][]byte), nil
	}

	minLen := 4 * (1 + (numTags - 1) + numTags)

	if uint64(len(bytes)) < minLen {
		return nil, errors.New("decode: message too short to be valid")
	}

	offsets := bytes[4:]
	tags := bytes[4*(1+numTags-1):]
	payloads := bytes[minLen:]

	if len(payloads) > math.MaxInt32 {
		return nil, errors.New("decode: message too large")
	}
	payloadLength := uint32(len(payloads))

	currentOffset := uint32(0)
	ret := make(map[uint32][]byte)

	for i := uint64(0); i < numTags; i++ {
		tag := binary.LittleEndian.Uint32(tags)
		tags = tags[4:]

		var nextOffset uint32
		if i < numTags-1 {
			nextOffset = binary.LittleEndian.Uint32(offsets)
			offsets = offsets[4:]
		} else {
			nextOffset = payloadLength
		}

		if nextOffset%4 != 0 {
			return nil, errors.New("decode: payload length is not a multiple of four bytes")
		}

		if nextOffset < currentOffset {
			return nil, errors.New("decode: offsets out of order")
		}

		length := nextOffset - currentOffset
		if uint32(len(payloads)) < length {
			return nil, errors.New("decode: message truncated")
		}

		payload := payloads[:length]
		payloads = payloads[length:]
		ret[tag] = payload
		currentOffset = nextOffset
	}

	return ret, nil
}

// messageOverhead returns the number of bytes needed for Encode to encode the
// given number of tags.
func messageOverhead(numTags int) int {
	return 4 * 2 * numTags
}

// CalculateChainNonce calculates the nonce to be used in the next request in a
// chain given a reply and a blinding factor.
func CalculateChainNonce(prevReply, blind []byte) (nonce [NonceSize]byte) {
	h := sha512trunc.New()
	h.Write(prevReply)
	prevReplyHash := h.Sum(nil)

	h.Reset()
	h.Write(prevReplyHash)
	h.Write(blind)
	h.Sum(nonce[:0])

	return nonce
}

// CreateRequest creates a Roughtime request given an entropy source and the
// contents of a previous reply for chaining. If this request is the first of a
// chain, prevReply can be empty. It returns the nonce (needed to verify the
// reply), the blind (needed to prove correct chaining to an external party)
// and the request itself.
func CreateRequest(rand io.Reader, prevReply []byte) (nonce, blind [NonceSize]byte, request []byte, err error) {
	versionBytes := []byte{0x03, 0x00, 0x00, 0x80}
	if _, err := io.ReadFull(rand, blind[:]); err != nil {
		return nonce, blind, nil, err
	}

	nonce = CalculateChainNonce(prevReply, blind[:])

	padding := make([]byte, MinRequestSize-messageOverhead(3)-len(nonce)-len(versionBytes))
	msg, err := Encode(map[uint32][]byte{
		tagNONC: nonce[:],
		tagPAD:  padding,
		tagVER:  versionBytes,
	})
	if err != nil {
		return nonce, blind, nil, err
	}

	return nonce, blind, msg, nil
}

// tree represents a Merkle tree of nonces. Each element of values is a layer
// in the tree, with the widest layer first.
type tree struct {
	values [][][NonceSize]byte
}

var (
	hashLeafTweak = []byte{0}
	hashNodeTweak = []byte{1}
)

// hashLeaf hashes an nonce to form the leaf of the Merkle tree.
func hashLeaf(out *[sha512.Size256]byte, in []byte) {
	h := sha512trunc.New()
	h.Write(hashLeafTweak)
	h.Write(in)
	h.Sum(out[:0])
}

// hashNode hashes two child elements of the Merkle tree to produce an interior
// node.
func hashNode(out *[sha512.Size256]byte, left, right []byte) {
	h := sha512trunc.New()
	h.Write(hashNodeTweak)
	h.Write(left)
	h.Write(right)
	h.Sum(out[:0])
}

// newTree creates a Merkle tree given one or more nonces.
func newTree(nonces [][]byte) *tree {
	if len(nonces) == 0 {
		panic("newTree: passed empty slice")
	}

	levels := 1
	width := len(nonces)
	for width > 1 {
		width = (width + 1) / 2
		levels++
	}

	ret := &tree{
		values: make([][][NonceSize]byte, 0, levels),
	}

	leaves := make([][NonceSize]byte, ((len(nonces)+1)/2)*2)
	for i, nonce := range nonces {
		var leaf [NonceSize]byte
		hashLeaf(&leaf, nonce)
		leaves[i] = leaf
	}
	// Fill any extra leaves with an existing leaf, to simplify analysis
	// that we are not inadvertently signing other messages.
	for i := len(nonces); i < len(leaves); i++ {
		leaves[i] = leaves[0]
	}
	ret.values = append(ret.values, leaves)

	for i := 1; i < levels; i++ {
		lastLevel := ret.values[i-1]
		width := len(lastLevel) / 2
		if width%2 == 1 {
			width++
		}
		level := make([][NonceSize]byte, width)
		for j := 0; j < len(lastLevel)/2; j++ {
			hashNode(&level[j], lastLevel[j*2][:], lastLevel[j*2+1][:])
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
func (t *tree) Root() *[NonceSize]byte {
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

// CreateReplies signs, using privateKey, a batch of nonces along with the
// given time and radius in microseconds. It returns one reply for each nonce
// using that signature and includes cert in each.
func CreateReplies(nonces [][]byte, midpoint mjd.Mjd, radius uint32, cert []byte, privateKey []byte) ([][]byte, error) {
	if len(nonces) == 0 {
		return nil, nil
	}

	tree := newTree(nonces)

	var midpointBytes [8]byte
	binary.LittleEndian.PutUint64(midpointBytes[:], midpoint.RoughtimeEncoding())
	var radiusBytes [4]byte
	binary.LittleEndian.PutUint32(radiusBytes[:], radius)

	signedReply := map[uint32][]byte{
		tagMIDP: midpointBytes[:],
		tagRADI: radiusBytes[:],
		tagROOT: tree.Root()[:],
	}
	signedReplyBytes, err := Encode(signedReply)
	if err != nil {
		return nil, err
	}

	toBeSigned := signedResponseContext + string(signedReplyBytes)
	sig := ed25519.Sign(privateKey, []byte(toBeSigned))
	versionBytes := []byte{0x03, 0x00, 0x00, 0x80}

	reply := map[uint32][]byte{
		tagSREP: signedReplyBytes,
		tagSIG:  sig,
		tagCERT: cert,
		tagVER:  versionBytes,
	}

	replies := make([][]byte, 0, len(nonces))

	for i := range nonces {
		var indexBytes [4]byte
		binary.LittleEndian.PutUint32(indexBytes[:], uint32(i))
		reply[tagINDX] = indexBytes[:]

		path := tree.Path(i)
		pathBytes := make([]byte, 0, NonceSize*len(path))
		for _, pathStep := range path {
			pathBytes = append(pathBytes, pathStep...)
		}
		reply[tagPATH] = pathBytes

		replyBytes, err := Encode(reply)
		if err != nil {
			return nil, err
		}

		replies = append(replies, replyBytes)
	}

	return replies, nil
}

// CreateCertificate returns a signed certificate, using rootPrivateKey,
// delegating authority for the given timestamp to publicKey.
func CreateCertificate(minTime, maxTime mjd.Mjd, publicKey, rootPrivateKey []byte) (certBytes []byte, err error) {
	if maxTime.Cmp(minTime) < 0 {
		return nil, errors.New("protocol: maxTime < minTime")
	}

	var minTimeBytes, maxTimeBytes [8]byte
	binary.LittleEndian.PutUint64(minTimeBytes[:], minTime.RoughtimeEncoding())
	binary.LittleEndian.PutUint64(maxTimeBytes[:], maxTime.RoughtimeEncoding())

	signed := map[uint32][]byte{
		tagPUBK: publicKey,
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

	return Encode(cert)
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

func getTimestamp(msg map[uint32][]byte, tag uint32, name string) (result mjd.Mjd, err error) {
	timestamp, err := getUint64(msg, tag, name)
	if err != nil {
		return mjd.Mjd{}, err
	}
	return mjd.RoughtimeVal(timestamp), nil
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
func VerifyReply(replyBytes, publicKey []byte, nonce [NonceSize]byte) (time mjd.Mjd, radius uint32, err error) {
	reply, err := Decode(replyBytes)
	if err != nil {
		return mjd.Mjd{}, 0, errors.New("protocol: failed to parse top-level reply: " + err.Error())
	}
	versionBytes, err := getValue(reply, tagVER, "version")
	if err != nil {
		return mjd.Mjd{}, 0, errors.New("protocol: failure to get version: " + err.Error())
	}

	if !isCompatibleVersion(versionBytes, Version) {
		return mjd.Mjd{}, 0, errors.New("protocol: incompatible versions")
	}
	cert, err := getSubmessage(reply, tagCERT, "certificate")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	signatureBytes, err := getFixedLength(cert, tagSIG, "signature", ed25519.SignatureSize)
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	delegationBytes, err := getValue(cert, tagDELE, "delegation")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	if !ed25519.Verify(publicKey, []byte(certificateContext+string(delegationBytes)), signatureBytes) {
		return mjd.Mjd{}, 0, errors.New("protocol: invalid delegation signature")
	}

	delegation, err := Decode(delegationBytes)
	if err != nil {
		return mjd.Mjd{}, 0, errors.New("protocol: failed to parse delegation: " + err.Error())
	}

	minTime, err := getTimestamp(delegation, tagMINT, "minimum time")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	maxTime, err := getTimestamp(delegation, tagMAXT, "maximum time")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	delegatedPublicKey, err := getFixedLength(delegation, tagPUBK, "public key", ed25519.PublicKeySize)
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	responseSigBytes, err := getFixedLength(reply, tagSIG, "signature", ed25519.SignatureSize)
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	signedResponseBytes, ok := reply[tagSREP]
	if !ok {
		return mjd.Mjd{}, 0, errors.New("protocol: response is missing signed portion")
	}

	if !ed25519.Verify(delegatedPublicKey, []byte(signedResponseContext+string(signedResponseBytes)), responseSigBytes) {
		return mjd.Mjd{}, 0, errors.New("protocol: invalid response signature")
	}

	signedResponse, err := Decode(signedResponseBytes)
	if err != nil {
		return mjd.Mjd{}, 0, errors.New("protocol: failed to parse signed response: " + err.Error())
	}

	root, err := getFixedLength(signedResponse, tagROOT, "root", 32)
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	midpoint, err := getTimestamp(signedResponse, tagMIDP, "midpoint")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	radius, err = getUint32(signedResponse, tagRADI, "radius")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	// We now need to do some arithmetic.

	if maxTime.Cmp(minTime) < 0 {
		return mjd.Mjd{}, 0, errors.New("protocol: invalid delegation range")
	}

	if midpoint.Cmp(minTime) < 0 || maxTime.Cmp(midpoint) < 0 {
		fmt.Printf("midpoint: %v\n minTime: %v\n maxTime: %v\n", midpoint, minTime, maxTime)
		return mjd.Mjd{}, 0, errors.New("protocol: timestamp out of range for delegation")
	}

	index, err := getUint32(reply, tagINDX, "index")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}

	path, err := getValue(reply, tagPATH, "path")
	if err != nil {
		return mjd.Mjd{}, 0, err
	}
	if len(path)%32 != 0 {
		return mjd.Mjd{}, 0, errors.New("protocol: path is not a multiple of 32")
	}

	var hash [sha512.Size256]byte
	hashLeaf(&hash, nonce[:])

	for len(path) > 0 {
		pathElementIsRight := index&1 == 0
		if pathElementIsRight {
			hashNode(&hash, hash[:32], path[:32])
		} else {
			hashNode(&hash, path[:32], hash[:32])
		}

		index >>= 1
		path = path[32:]
	}

	if !bytes.Equal(hash[:32], root) {
		return mjd.Mjd{}, 0, errors.New("protocol: calculated tree root doesn't match signed root")
	}

	return midpoint, radius, nil
}

// EncapsulatePacket creates a UDP/TCP payload containing a roughtime message.
func EncapsulatePacket(version uint32, message []byte) []byte {
	length := len(message)
	ret := make([]byte, length+12)
	copy(ret, "ROUGHTIM")
	binary.LittleEndian.PutUint32(ret[8:], uint32(length))
	copy(ret[12:], message)
	return ret
}

// DencapsulatePacket removes the encapsulation layer.
func DencapsulatePacket(packet []byte) ([]byte, error) {
	if bytes.Compare(packet[0:8], []byte("ROUGHTIM")) != 0 {
		return nil, errors.New("Header invalid")
	}
	length := int(binary.LittleEndian.Uint32(packet[8:12]))
	if length != len(packet)-12 {
		return nil, errors.New("Mangled length!")
	}
	return packet[12:], nil

}

// CreateReply crafts a reply for a single packet from the wire form
func CreateReply(packet []byte, midpoint mjd.Mjd, radius uint32, cert []byte, privateKey []byte) ([]byte, error) {
	innards, err := DencapsulatePacket(packet)
	if err != nil {
		return nil, err
	}
	parsed, err := Decode(innards)
	if err != nil {
		return nil, err
	}
	nonce, err := getValue(parsed, tagNONC, "nonce")
	if err != nil {
		return nil, err
	}
	resps, err := CreateReplies([][]byte{nonce}, midpoint, radius, cert, privateKey)
	if err != nil {
		return nil, err
	}
	return EncapsulatePacket(Version, resps[0]), nil
}

func isCompatibleVersion(list []byte, version uint32) bool {
	if len(list)%4 != 0 {
		return false
	}

	for ptr := 0; ptr < len(list); ptr += 4 {
		if binary.LittleEndian.Uint32(list[ptr:ptr+4]) == version {
			return true
		}
	}
	return false
}
