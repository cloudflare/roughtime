package sha512trunc

import (
	"crypto/sha512"
	"hash"
)

type shatrunc struct {
	inner hash.Hash
}

func (h *shatrunc) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *shatrunc) Reset() {
	h.inner.Reset()
}

func (h *shatrunc) Size() int {
	return 32
}

func (h *shatrunc) BlockSize() int {
	return h.inner.BlockSize()
}
func (h *shatrunc) Sum(b []byte) []byte {
	tmp := h.inner.Sum(nil)
	return append(b, tmp[:32]...)

}
func New() hash.Hash {
	ret := new(shatrunc)
	ret.inner = sha512.New()
	return ret
}
