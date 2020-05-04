package mjd

import (
	"golang.org/x/sys/unix"
)

func Now() Mjd {
	time := unix.Timeval{}
	err := unix.Gettimeofday(&time) // result has microseconds
	if err != nil {
		panic("adjtimex failed")
	}
	retval := Mjd{}
	daysPostEpoch := time.Sec / secs_per_day
	retval.day = uint64(unix_epoch + daysPostEpoch)
	retval.µs = float64(time.Sec-daysPostEpoch*secs_per_day*1e6) + float64(time.Usec)
	return retval
}
