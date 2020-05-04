package mjd

import (
	"golang.org/x/sys/unix"
)

func Now() Mjd {
	instant := unix.Timex{}
	timestatus, err := unix.Adjtimex(&instant) // result has microseconds
	if err != nil {
		panic("adjtimex failed")
	}
	retval := Mjd{}
	daysPostEpoch := instant.Time.Sec / secs_per_day
	retval.day = uint64(unix_epoch + daysPostEpoch)
	retval.µs = float64(instant.Time.Sec-daysPostEpoch*secs_per_day*1e6) + float64(instant.Time.Usec)
	if unix.TIME_OOP == timestatus { // we are inserting a leap second, hence are 1 second behind
		retval.µs += 1_000_000

	}
	return retval
}
