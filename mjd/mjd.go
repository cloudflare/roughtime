package mjd

import (
	"math"
	"time"
)

const secs_per_day = 24 * 60 * 60
const unix_epoch = 40587 // Days between 1858-11-17 and 1970-01-01 Gregorian

type Mjd struct {
	day uint64
	µs  float64
}

func (t Mjd) Unix() time.Time {
	days := t.day - unix_epoch
	secs := t.µs / 1e6
	if secs > secs_per_day {
		secs -= secs_per_day
	}
	additional_secs := (int64)(math.Floor(secs))
	residue := secs - math.Floor(secs)
	nanos := (int64)(math.Floor(residue * 1e9))
	return time.Unix((int64)(days*secs_per_day)+additional_secs, nanos)
}

func New(day uint64, micros float64) Mjd {
	return Mjd{
		day,
		micros,
	}
}

func (t Mjd) Day() uint64 {
	return t.day
}

func (t Mjd) Microseconds() float64 {
	return t.µs
}

func (a Mjd) Cmp(b Mjd) int {
	if a.day < b.day {
		return -1
	}
	if a.day > b.day {
		return 1
	}
	if a.µs < b.µs {
		return -1
	}
	if a.µs > b.µs {
		return 1
	}
	return 0
}

func (t Mjd) RoughtimeEncoding() uint64 {
	return t.day<<40 + uint64(math.Floor(t.µs))
}

func RoughtimeVal(in uint64) Mjd {
	ret := Mjd{}
	ret.day = in >> 40
	ret.µs = float64(in & 0xffffffffff)
	return ret
}
