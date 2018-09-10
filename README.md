# Cloudflare-Roughtime

This package implements a simple Roughtime client that is based on [Google's
implementation](https://roughtime.googlesource.com/roughtime). To run it, do:
```
$ go get -u github.com/cloudflare/roughtime
$ go install github.com/cloudflare/roughtime...
$ getroughtime -ping roughtime.cloudflare.com:2002 \
    -pubkey "gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo="
ping response: 2018-09-06 19:05:33.054 -0700 PDT ±1s (in 5ms)
```

For more information about Roughtime and tips for writing your own client, visit
the [developer documentation](https://developers.cloudflare.com/roughtime/).
