# Roughtime

This package implements a simple Roughtime client based on the
[IETF draft](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)

For more information about Roughtime and tips for writing your own
client or server, visit the [developer
documentation](https://developers.cloudflare.com/time-services/roughtime/).

## Note on status

Roughtime is now experimental and will undergo backwards incompatible
changes as it goes through the IETF process. This library will
likewise undergo backwards incompatible changes. There are already
substantial changes from Google Roughtime that have forced interface changes.

If you want to use this code and the protocol please join the NTP WG
[mailing list](https://www.ietf.org/mailman/listinfo/ntp) so that you are
aware of the evolution of the protocol and issues that others discover.

** DO NOT USE IN PRODUCTION SOFTWARE **

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
     5. what version you run

  * Generate the `ecosystem.json.go` from the `ecosystem.json`. Use the
    `go generate` command for this.

A couple things to keep in mind:

  * To be healthy, the Roughtime ecosystem **needs a diverse set of time
    sources.** The list already contains servers that are synced with Google's
    NTP servers; as such, servers that expose new sources will be preferred. (An
    atomic clock would be cool!)

  * We reserve the right to prune this list at any time. (For example, if a
    server is unreliable, or its root secret key has been compromised.)
    
  * As new versions come out we may prune servers that do not update.

Finally, a disclaimer: the ecosystem is growing, and ours might not be the
definitive list of who is serving Roughtime at any given time.

## Contributing

We welcome your bug fixes, issues, and improvements to either the
protocol or this code. Note that substantive changes to the protocol
need to be discussed on the NTP WG mailing list.
