//go:build windows
// +build windows

package mjd

import (
	"golang.org/x/sys/windows"
)

func Now() Mjd {
	fileTime := windows.Filetime{}
	windows.GetSystemTimeAsFileTime(&fileTime)
	ns := fileTime.Nanoseconds()
	daysPostEpoch := ns / 1e9 / secs_per_day
	retval := Mjd{
		day: unix_epoch + uint64(daysPostEpoch),
		µs:  float64(ns/1e3 - daysPostEpoch*secs_per_day*1e6),
	}
	return retval
}
