package mjd

import (
	"testing"
)

func TestMJD(t *testing.T) {
	result := Now()
	if result.Day() < unix_epoch+365*(2020-1970) {
		t.Fatal("Day seems wrong")
	}

	example := Mjd{day: 0xadbeef, µs: 1337.00}
	res := RoughtimeVal(example.RoughtimeEncoding())
	if res.day != example.day {
		t.Fatal("day mismatch")
	}
	if res.µs-example.µs != 0 {
		t.Fatal("micros mismatch")
	}

}
