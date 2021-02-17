package sha512trunc

import (
	"crypto/sha512"
	"testing"
)

func TestSha512Trunc(t *testing.T) {
	hash := New()
	hash.Write([]byte("Hello"))
	res := hash.Sum(nil)
	sha := sha512.New()
	sha.Write([]byte("Hello"))
	shahash := sha.Sum(nil)
	if len(res) != 32 {
		t.Errorf("output too long")
	}
	for i := 0; i < 32; i++ {
		if shahash[i] != res[i] {
			t.Errorf("output mismatch")
		}
	}
}
