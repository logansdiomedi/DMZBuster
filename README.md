# DMZBuster
A handy tool to help you find your way out of jail.

## Overview
DMZBuster is a standalone tool written in both Python and Bash for the purposes of discovering hidden proxy servers. DMZ networks are, by their very design, supposed to be entirely isolated from internal, corporate networks. However, instances in the wild have demonstrated that proxy servers are used within DMZs to enable certain functionality sometimes, creating an opportunity for you, the hacker, to obtain internal access. 

Edits and PRs are welcome. There's certainly improvements to be made. 

Example attack scenario: Shell on DMZ webserver, discover hidden HTTP proxy, scan for web-based exploit on internal network through proxy -> collect win.

The Bash version will come at a later date for usage in highly restricted environments where Python may not be installed, or desired for various reasons. 

## Usage
### Help
```
python3 dmzbuster.py -h
usage: dmzbuster.py [-h] --range RANGE [--output OUTPUT] [--threads THREADS] [--resolve] [--dns DNS] [--socks_proxy SOCKS_PROXY] [--http_proxy HTTP_PROXY]

Scan a CIDR range or single IP for (HTTP, SOCKS4, SOCKS5) proxies on ~50 common proxy ports.

optional arguments:
  -h, --help            show this help message and exit
  --range RANGE         CIDR range or single IP to scan (e.g. 192.168.0.0/24 or 192.168.0.50)
  --output OUTPUT       Output filename (plain text) to store found proxy results.
  --threads THREADS     Number of worker threads to use (default=50).
  --resolve             Attempt reverse DNS and use hostname in the CONNECT request for HTTP proxy detection.
  --dns DNS             Use the specified DNS server for reverse lookups (requires dnspython). Example: --dns 8.8.8.8
  --socks_proxy SOCKS_PROXY
                        Supply a SOCKS5 proxy in IP:Port format for scanning (e.g. 127.0.0.1:1080).
  --http_proxy HTTP_PROXY
                        Supply an HTTP proxy in IP:Port format for scanning (e.g. 127.0.0.1:8080).
```
