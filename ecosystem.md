# The Roughtime ecosystem

File `ecosystem.json` contains the configurations of a growing list of Roughtime
servers. This file contains a brief description of how each server is
provisioned. Refer to `README.md` for information about adding your server to
the list.


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
