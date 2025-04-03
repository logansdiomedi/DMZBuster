# DMZBuster
A handy tool to help you find your way out of jail.

## Overview
DMZBuster is a standalone tool written in both Bash and Python for the purposes of discovering hidden proxy servers and devices that have IP forwarding enabled. DMZ networks are, by their very design, supposed to be entirely isolated from internal, corporate networks. However, I've seen instances in the wild where proxy servers are used within DMZs to enable certain functionality, creating an opportunity for you, the hacker, to obtain internal access. 

Example attack scenario: Shell on DMZ webserver, discover hidden HTTP proxy, scan for web-based exploit on internal network through proxy -> collect win.

## Usage
### Python
python3 dmzbuster.py --range <cidr_range> --find

### Bash
./dmzbuster.sh --range <cidr_range> --find
