# The Roughtime ecosystem

File `ecosystem.json` contains the configurations of a growing list of Roughtime
servers. This file contains a brief description of how each server is
provisioned. Refer to `README.md` for information about adding your server to
the list.


## Cloudflare-Roughtime-2

Cloudflare's Roughtime service aims for high availability and low latency. The
[announcement](https://blog.cloudflare.com/roughtime/) provides details about
how we set up the service. Briefly, the domain for Roughtime resolves to an
address in Cloudflare's anycast IP range (both IPv4 and IPv6 are supported), so
the response may come from any one of their points of presence. The
implementation is based on Google's [Go
code](https://roughtime.googlesource.com/roughtime), but has been updated to
support both Google-Roughtime and IETF Roughtime (draft08). This service is
currently in beta. As such the root key is subject to change. It will be
updated here and in the [developer
docs](https://developers.cloudflare.com/time-services/roughtime/recipes/). You
can also obtain it over DNS; see the docs for details.


## int08h-Roughtime

A public Roughtime server operated by the author of the [Rust](https://github.com/int08h/roughenough) 
and [Java](https://github.com/int08h/nearenough) implementations of Roughtime.

The server runs the latest release of [roughenough](https://github.com/int08h/roughenough) 
on Digital Ocean droplets in their US NYC datacenter. The server supports both the 
Google-Roughtime and IETF-Roughtime protocols. Time is sourced from Google's 
[public NTP servers](https://developers.google.com/time/smear), 
Amazon's [public NTP servers](https://aws.amazon.com/about-aws/whats-new/2022/11/amazon-time-sync-internet-public-ntp-service/),
and NIST's [public NTP servers](https://www.nist.gov/pml/time-and-frequency-division/time-distribution/internet-time-service-its).

Available at `roughtime.int08h.com:2002` its public key is stable and the service 
is available 24/7, modulo a few seconds downtime for maintenance. 

The int08h instance keeps the "rough" in Roughtime: it smears leapseconds
and always reports a 'radius' (RADI tag) of 2 seconds to account for the resulting 
uncertainty. The int08h Roughtime instance will **never** set the DUT1, 
DTAI, or LEAP tags as this level of precision is unnecessary.

The public key is available in a [blog post at int08h](https://int08h.com/post/public-roughtime-server/), 
and the DNS `TXT` record of `roughtime.int08h.com`:

```
$ dig -t txt roughtime.int08h.com
```

## roughtime.se

[roughtime.se](https://roughtime.se) provides a stratum 1 Roughtime service. It
runs the [roughtimed](https://github.com/dansarie/roughtimed) implementation.
Hosting is provided by STUPI AB. The server is located in Stockholm, Sweden and
is directly connected to atomic clocks that track the UTC timescale. The aim is
for the server to be compatible with the
[latest published IETF Roughtime draft](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/).
The server is connected to high-availability power and network infrastructure in
a datacenter, however no availability is guaranteed. The public key is available
on the server's web site, and as a DNS TXT record:

```
dig TXT roughtime.se
```

## time.txryan.com

[time.txryan.com](https://time.txryan.com) operates on a stratum 2 NTP server. Roughtime service is operating on `time.txryan.com:2002`. The public key is available on time.txryan.com and through DNS:

```
$ dig TXT time.txryan.com +short
```

The clock is synchronized with authenticated and non-authenticated NTP connections to multiple stratum 1 sources. Accuracy is typically within ±50 microseconds. The service is built on Cloudflare’s [implementation](https://github.com/cloudflare/roughtime) of Roughtime protocol.

At the time of writing, this instance supports draft-ietf-ntp-roughtime-11, draft-ietf-ntp-roughtime-08, and Google-Roughtime. While the service is monitored for accuracy and availability, it's provided without guarantees.


## Inactive servers


## Chainpoint-Roughtime

**This service is unreachable as of 2024-07-01.**

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



### Cloudflare-Roughtime

**Deprecation notice**: The Cloudflare-Roughtime server will be shut down on
2024-07-01. Please update your client to use Cloudflare-Roughtime-2 instead.


## Google-Sandbox-Roughtime

**This service is unreachable as of 2024-07-01.**

This is Google's [proof-of-concept
server](https://roughtime.googlesource.com/roughtime/#current-state-of-the-project).
It is experimental and does not, as of yet, provide uptime guarantees. The root
public key is published
[here](https://roughtime.googlesource.com/roughtime/+/master/roughtime-servers.json).


## Mixmin Roughtime

**This service is unreachable as of 2024-07-01.**

Mixmin's Roughtime service resides on a dedicated Raspberry Pi running Arch
Linux.  The Pi has an Adafruit GPS module fitted and uses it to sync the system
clock via NTP.  It uses Adam Langley's reference implementation of Roughtime,
written in Go and is compiled locally on the Raspberry Pi.  The Roughtime
server was announced on the mailing list, archived
[here](https://groups.google.com/a/chromium.org/forum/#!topic/proto-roughtime/7PApRXJ-x0Y).
The announcement includes the server details.

