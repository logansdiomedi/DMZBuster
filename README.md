# DMZBuster
A handy tool to help you find your way out of jail.

## Overview
DMZBuster is a standalone tool written in both Python and Bash for the purposes of discovering hidden proxy servers and devices that have IP forwarding enabled. DMZ networks are, by their very design, supposed to be entirely isolated from internal, corporate networks. However, I've seen instances in the wild where proxy servers are used within DMZs to enable certain functionality, creating an opportunity for you, the hacker, to obtain internal access. 

Example attack scenario: Shell on DMZ webserver, discover hidden HTTP proxy, scan for web-based exploit on internal network through proxy -> collect win.

The Bash version will come at a later date for usage in highly restricted environments where Python may not be installed, or desired for various reasons. 

## Usage
### Help
```
python3 dmzbuster.py -h
usage: dmzbuster.py [-h] --range RANGE [--output OUTPUT] [--threads THREADS]

Scan a CIDR range or single IP for (HTTP, SOCKS4, SOCKS5) proxies on ~50 common proxy ports.

optional arguments:
  -h, --help         show this help message and exit
  --range RANGE      CIDR range or single IP to scan (e.g. 192.168.0.0/24 or 192.168.0.50)
  --output OUTPUT    Output filename (plain text) to store found proxy results.
  --threads THREADS  Number of worker threads to use (default=50).
```

### Python
python3 dmzbuster.py --range <cidr_range> --find

### Bash
Coming soon. 
