# DMZBuster
A handy tool to help you find your way out of jail.

## Overview
DMZBuster is a standalone tool written in both Python and Bash for the purposes of discovering hidden proxy servers. DMZ networks are, by their very design, supposed to be entirely isolated from internal, corporate networks. However, instances in the wild have demonstrated that proxy servers are used within DMZs to enable certain functionality sometimes, creating an opportunity for you, the hacker, to obtain internal access. Better yet, DMZBuster can use discovered HTTP proxies to help you find and fingerprint web-based HTTP services with known RCE bugs such as PaperCut, iLO devices, ColdFusion servers, Tomcat/JMXInvokerServlet stuff, and more.

Edits and PRs are welcome. There's certainly improvements to be made. 

Example attack scenario: Shell on DMZ webserver, discover hidden HTTP proxy, scan for web-based exploit on internal network through proxy -> collect win.

The Bash version will come at a later date for usage in highly restricted environments where Python may not be installed, or desired for various reasons. 

## Usage
### Help
```
root# python3 dmzbuster.py -h
usage: dmzbuster.py [-h] [--range RANGE] [--output OUTPUT] [--threads THREADS] [--resolve] [--dns DNS] [--socks_proxy SOCKS_PROXY] [--http_proxy HTTP_PROXY] [--find-foothold] [--foothold_range FOOTHOLD_RANGE]

Scan a CIDR range or single IP for (HTTP, SOCKS4, SOCKS5) proxies on ~50 common proxy ports, and optionally do foothold scans for specific devices.

optional arguments:
  -h, --help            show this help message and exit
  --range RANGE         CIDR range or single IP to scan (e.g. 192.168.0.0/24 or 192.168.0.50). Not required if using --find-foothold alone.
  --output OUTPUT       Output filename (plain text) to store found proxy results.
  --threads THREADS     Number of worker threads to use (default=50).
  --resolve             Attempt reverse DNS and use hostname in the CONNECT request for HTTP proxy detection.
  --dns DNS             Use the specified DNS server for reverse lookups (requires dnspython). Example: --dns 8.8.8.8
  --socks_proxy SOCKS_PROXY
                        Supply a SOCKS5 proxy in IP:Port format for scanning (e.g. 127.0.0.1:9050).
  --http_proxy HTTP_PROXY
                        Supply an HTTP proxy in IP:Port format for scanning (e.g. 127.0.0.1:8080).
  --find-foothold       Enable special HTTP-based scans to identify potentially exploitable devices/products via HTTP (HP iLO, PaperCut, etc.).
  --foothold_range FOOTHOLD_RANGE
                        CIDR range used for foothold scanning (e.g. 192.168.0.0/16). Only ports 80,443,8080,8443,8844,9191 are tested.
```
## FAQ
### Can't nmap just do this already?
Sure. It can. 

### The detection I got using the proxy + HTTP foothold feature was a false positive. What gives?
The detection right now is absolutely not perfect and needs a lot of work. Just in my brief testing, I've seen numerous dumb things that can cause the detection to fail or improperly identify certain vendor products. For example, if you run across crappy web servers or applications that return a 200 for 404s - you'll get FPs. If you want me to fix it, I need a few things:
1. The raw HTTP traffic you receive from the affected host when issuing a cURL command
2. The actual product it ended up being
3. Anything else that might be pertinent.

### XYZ thing could be done better or DMZBuster needs XYZ feature!
PRs are always welcome. :) Otherwise, open a feature request.

### Can I specifiy additional ports?
Sure, you can by simply editing the array of ports the script uses to check. In the future, I'll add a feature to allow specifying a range of ports or comma-separated ports, nmap-style.
