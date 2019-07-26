[![PyPI version](https://badge.fury.io/py/TrustTrees.svg)](https://badge.fury.io/py/TrustTrees)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](https://github.com/mandatoryprogrammer/TrustTrees/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22+)
[![Tor](https://img.shields.io/badge/Donate-Tor-orange)](https://donate.torproject.org/)


# TrustTrees
## *A Tool for DNS Delegation Trust Graphing*

## Summary
TrustTrees is a script to recursively follow all the possible delegation paths for a target domain and graph the relationships between various nameservers along the way. TrustTrees also allows you to view where errors occured in this chain such as DNS `REFUSED`, `NXDOMAIN`, and other errors. Finally, the tool also comes with the ability to scan enumerated nameservers for expired base-domains which may allow for domain takeovers and hijacking of the target domain.

The purpose of this tool is to allow domain owners to verify that their domain's DNS is set up properly and is not vulnerable.

Installation
------------
``` {.sourceCode .bash}
$ pip install TrustTrees
✨🍰✨
```

## Example Usage:
```
(env)bash-3.2$ trusttrees.py --target example.com --open

  ______                __ ______
 /_  __/______  _______/ //_  __/_______  ___  _____
  / / / ___/ / / / ___/ __// / / ___/ _ \/ _ \/ ___/
 / / / /  / /_/ (__  ) /_ / / / /  /  __/  __(__  )
/_/ /_/   \__,_/____/\__//_/ /_/   \___/\___/____/
          Graphing & Scanning DNS Delegation Trees

[ STATUS ] Querying nameserver '192.203.230.10/e.root-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.5.6.30/a.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '199.43.135.53/a.iana-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '199.43.133.53/b.iana-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.33.14.30/b.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.26.92.30/c.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.31.80.30/d.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.12.94.30/e.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.35.51.30/f.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.42.93.30/g.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.54.112.30/h.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.43.172.30/i.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.48.79.30/j.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.52.178.30/k.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.41.162.30/l.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Querying nameserver '192.55.83.30/m.gtld-servers.net.' for NS of 'example.com.'
[ STATUS ] Building 'example.com.|ns|192.42.93.30|g.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.55.83.30|m.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|199.43.135.53|a.iana-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.26.92.30|c.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.52.178.30|k.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.35.51.30|f.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.31.80.30|d.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.43.172.30|i.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|199.43.133.53|b.iana-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.12.94.30|e.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.203.230.10|e.root-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.48.79.30|j.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.54.112.30|h.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.41.162.30|l.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.5.6.30|a.gtld-servers.net.'...
[ STATUS ] Building 'example.com.|ns|192.33.14.30|b.gtld-servers.net.'...
[ STATUS ] Opening final graph...
[ SUCCESS ] Finished generating graph!
```

## Example Generated Graph:
[![example.com](https://i.imgur.com/K6FBvQv.png)](https://i.imgur.com/K6FBvQv.png)

## Example Generated Graph With Errors in DNS Chain
[![ticonsultores.biz.ni](https://i.imgur.com/MRcSaie.png)](https://i.imgur.com/MRcSaie.png)

The above graph is a good example of a domain with many DNS errors in its delegation chain. Some of these issues are not even the fault of the domain owner but rather are issues with the upstream TLD. Depending on the configuration of the DNS resolver, the round robin order, and the error tolerance of the DNS resolver, resolution of this domain may or may not succeed.

## Command-Line Options
```sh
(env)bash-3.2$ trusttrees.py --help
usage: trusttrees.py [-h] (-t TARGET_HOSTNAME | -l TARGET_HOSTNAMES_LIST) [-o]
                     [--gandi-api-v4-key GANDI_API_V4_KEY]
                     [--gandi-api-v5-key GANDI_API_V5_KEY] [-x EXPORT_FORMATS]

Graph out a domain's DNS delegation chain and trust trees!

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET_HOSTNAME, --target TARGET_HOSTNAME
                        Target hostname to generate delegation graph from.
  -l TARGET_HOSTNAMES_LIST, --target-list TARGET_HOSTNAMES_LIST
                        Input file with a list of target hostnames.
  -o, --open            Open the generated graph once run.
  --gandi-api-v4-key GANDI_API_V4_KEY
                        Gandi API V4 key for checking if nameserver base
                        domains are registerable.
  --gandi-api-v5-key GANDI_API_V5_KEY
                        Gandi API V5 key for checking if nameserver base
                        domains are registerable.
  -x EXPORT_FORMATS, --export-formats EXPORT_FORMATS
                        Comma-seperated export formats, e.g: -x png,pdf
```

In order to use the domain-check functionality to look for domain takeovers via expired-domain registration you must have a Gandi production API key. Only Gandi is supported because they are the only registrar I'm aware of with a wide range of supported TLDs, a solid API, and good support. [Click here to sign up for a Gandi account.](https://www.gandi.net/)

## Graph Nodes/Edges Documentation
### Nodes
* *White Nameserver Nodes*: These are nameservers which have delegated the query to another nameserver and have not responded authoritatively to the query.
* *Blue Nameserver Nodes*: These are nameservers which have answered authoritatively to the query.
* *Red Nameserver Nodes*: These are nameserves which were found to have no IP address associated with them. They are essentially dead-ends because the resolver has no way to send queries to them.
* *Yellow DNS Error Nodes*: These are DNS errors which occured while recursing the DNS chain.
* *Orange Domain Unregistered Nodes*: These nodes indicate that the base domain for the nameserver is reported by Gandi to be unregistered. This can mean the domain can be registered and the DNS hijacked!

### Edges
* *Dashed gray lines*: This means that the query response was not authoritative.
* *Solid blue lines*: This means the query response was authoritative.
* *Solid black lines*: (or it links to an error/domain registered node).
