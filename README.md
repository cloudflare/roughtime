# Roughtime

This package implements a simple Roughtime client based on [Google's
implementation](https://roughtime.googlesource.com/roughtime). To run it, do:
```
$ go get -u github.com/cloudflare/roughtime
$ go install github.com/cloudflare/roughtime...
$ getroughtime -ping roughtime.cloudflare.com:2002 \
    -pubkey gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=
ping response: 2018-09-20 10:26:56.327 -0400 EDT ±1s (in 16ms)
```
Or, better yet, use multiple servers!
```
$ getroughtime -config ~/go/src/github.com/cloudflare/roughtime/ecosystem.config
Cloudflare-Roughtime: 2018-09-20 10:25:10.568 -0400 EDT ±1s (in 14ms)
Google-Sandbox-Roughtime: 2018-09-20 10:25:10.587429 -0400 EDT ±1s (in 20ms)
int08h-Roughtime: 2018-09-20 10:25:10.618522 -0400 EDT ±1s (in 40ms)
delta: -12ms
```
For more information about Roughtime and tips for writing your own client, visit
the [developer documentation](https://developers.cloudflare.com/roughtime/).
