# The Roughtime ecosystem

File `ecosystem.json` contains the configurations of a growing list of Roughtime
servers. This file contains a brief description of how each server is
provisioned. Refer to `README.md` for information about adding your server to
the list.


## Chainpoint-Roughtime

The [Chainpoint](https://chainpoint.org) Roughtime service is hosted
at `roughtime.chainpoint.org:2002`. The public key, and information about
running the Docker container we've created for [roughenough](https://github.com/int08h/roughenough),
is provided at [https://github.com/chainpoint/chainpoint-roughtime](https://github.com/chainpoint/chainpoint-roughtime).

In addition to the Github repository `README.md`, the long-term public key in
Hexadecimal form is also provided as a DNS `TXT` record accessible with:

```
$ dig -t txt roughtime.chainpoint.org
```

The Chainpoint Roughtime service is in open beta, but aims to operate with
high-availability. The [roughenough](https://github.com/int08h/roughenough)
Rust implementation of Roughtime is currently running on two servers in the
Google Compute Engine cloud (US-EAST4), both synced to Google's internal
high accuracy NTP service. These servers exist behind a public UDP
load-balancer and a Cloudflare DNS `A` record.


## Cloudflare-Roughtime

Cloudflare's Roughtime service aims for high availability and low latency. The
[announcement](https://blog.cloudflare.com/roughtime/) provides details about
how we set up the service. Briefly, the domain for Roughtime resolves to an
address in Cloudflare's anycast IP range (both IPv4 and IPv6 are supported), so
the response may come from any one of their points of presence. The
implementation is based on Google's [Go
code](https://roughtime.googlesource.com/roughtime). This service is currently in beta. As
such the root key is subject to change. It will be updated here and in the
[developer docs](https://developers.cloudflare.com/roughtime/docs/usage/). You
can also obtain it over DNS; see the docs for details.


## Google-Sandbox-Roughtime

This is Google's [proof-of-concept
server](https://roughtime.googlesource.com/roughtime/#current-state-of-the-project).
It is experimental and does not, as of yet, provide uptime guarantees. The root
public key is published
[here](https://roughtime.googlesource.com/roughtime/+/master/roughtime-servers.json).


## Mixmin Roughtime

Mixmin's Roughtime service resides on a dedicated Raspberry Pi running Arch
Linux.  The Pi has an Adafruit GPS module fitted and uses it to sync the system
clock via NTP.  It uses Adam Langley's reference implementation of Roughtime,
written in Go and is compiled locally on the Raspberry Pi.  The Roughtime
server was announced on the mailing list, archived
[here](https://groups.google.com/a/chromium.org/forum/#!topic/proto-roughtime/7PApRXJ-x0Y).
The announcement includes the server details.
