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
$ getroughtime -config ~/go/src/github.com/cloudflare/roughtime/ecosystem.json
Cloudflare-Roughtime: 2018-09-20 10:25:10.568 -0400 EDT ±1s (in 14ms)
Google-Sandbox-Roughtime: 2018-09-20 10:25:10.587429 -0400 EDT ±1s (in 20ms)
int08h-Roughtime: 2018-09-20 10:25:10.618522 -0400 EDT ±1s (in 40ms)
delta: -12ms
```
For more information about Roughtime and tips for writing your own client, visit
the [developer documentation](https://developers.cloudflare.com/roughtime/).

## Ecosystem guidelines

We welcome pull requests for adding your Roughtime service to our list. Your PR
should do the following:

  * Add your server's configuration to `ecosystem.json`. The list of servers
    will be alphabetized by the `"name"` field.

  * Add some information about your service to `ecosystem.md`. (This is also
    kept in alphabetical order.) This should include details about how your
    service is provisioned:

     1. how you synchronize your server's clock;
     2. if your code is open source, a link to the code;
     3. where in the world your server is located; and
     4. whether you will guarantee up time, and if so, how you will do so.

A couple things to keep in mind:

  * To be healthy, the Roughtime ecosystem **needs a diverse set of time
    sources.** The list already contains servers that are synced with Google's
    NTP servers; as such, servers that expose new sources will be preferred. (An
    atomic clock would be cool!)

  * We reserve the right to prune this list at any time. (For example, if a
    server is unreliable, or its root secret key has been compromised.)

Finally, a disclaimer: the ecosystem is growing, and ours might not be the
definitive list of who is serving Roughtime at any given time. For details about
the current state and the future of the protocol, see Adam Langley's [write
up](https://roughtime.googlesource.com/roughtime/+/HEAD/ECOSYSTEM.md) about the
Roughtime ecosystem. There's also a [Google
group](https://groups.google.com/a/chromium.org/forum/#!forum/proto-roughtime)
with ongoing discussion.
