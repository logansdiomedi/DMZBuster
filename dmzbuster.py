#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import sys
import concurrent.futures
import ssl  # Needed for ignoring invalid certs in foothold scanning

# Optional: For custom DNS in the original scanning logic
try:
    import dns.resolver
    import dns.reversename
    DNSPY_AVAILABLE = True
except ImportError:
    DNSPY_AVAILABLE = False

# =========================
# SCAN FOR PROXIES
# =========================

COMMON_PROXY_PORTS = [
    80,    81,    88,    443,   808,   888,   999,   1080,  1081,  1111,
    2020,  3128,  3129,  3130,  5000,  5566,  6588,  6666,  6667,  6668,
    6669,  8000,  8001,  8008,  8010,  8080,  8081,  8082,  8088,  8090,
    8111,  8118,  8123,  8181,  8443,  8888,  9000,  9050,  9051,  9060,
    9080,  9090,  9150,  9999,  10000, 10080, 18080, 62078, 3838
]

def reverse_dns_lookup(ip, dns_server=None):
    """
    Attempt to do a reverse DNS lookup on the given IP.
    """
    ip_str = str(ip)
    if dns_server and not DNSPY_AVAILABLE:
        print(f"[!] --dns {dns_server} specified but dnspython is not installed. Skipping custom resolution.")
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            return hostname
        except:
            return None

    if dns_server and DNSPY_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            rev_name = dns.reversename.from_address(ip_str)
            answer = resolver.resolve(rev_name, "PTR")
            if answer:
                return str(answer[0]).rstrip(".")
        except:
            return None

    if DNSPY_AVAILABLE:
        try:
            rev_name = dns.reversename.from_address(ip_str)
            answer = dns.resolver.resolve(rev_name, "PTR")
            if answer:
                return str(answer[0]).rstrip(".")
        except:
            pass

    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except:
        return None

def open_connection_socks(ip, port, timeout, socks_proxy):
    """
    Connect to user-supplied SOCKS proxy, do handshake, then connect to ip:port.
    """
    proxy_ip, proxy_port_str = socks_proxy.split(":", 1)
    proxy_port = int(proxy_port_str)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_ip, proxy_port))

    # Socks5 greeting
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) != 2 or resp[0] != 0x05:
        s.close()
        raise ConnectionError("SOCKS5 proxy handshake failed (invalid response)")

    if resp[1] != 0x00:
        s.close()
        raise ConnectionError("SOCKS5 proxy requires unsupported auth method.")

    # Build connect request
    try:
        ip_bytes = socket.inet_pton(socket.AF_INET, str(ip))
        atyp = 0x01
    except OSError:
        ip_bytes = socket.inet_pton(socket.AF_INET6, str(ip))
        atyp = 0x04

    port_hi = (port >> 8) & 0xFF
    port_lo = port & 0xFF

    req = bytearray([0x05, 0x01, 0x00, atyp]) + ip_bytes + bytearray([port_hi, port_lo])
    s.sendall(req)

    resp = s.recv(10)
    if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
        s.close()
        raise ConnectionError("SOCKS5 proxy connection failed (status != 0x00)")

    return s

def open_connection_http(ip, port, timeout, http_proxy):
    """
    Connect to user-supplied HTTP proxy, do a CONNECT to ip:port.
    """
    proxy_ip, proxy_port_str = http_proxy.split(":", 1)
    proxy_port = int(proxy_port_str)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_ip, proxy_port))

    connect_line = f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n"
    s.sendall(connect_line.encode("utf-8"))

    data = s.recv(4096)
    if not data:
        s.close()
        raise ConnectionError("No response from HTTP proxy on CONNECT.")

    # Expecting something with 200
    if b"200" not in data and b"Connection" not in data and b"Established" not in data:
        if not data.startswith(b"HTTP/1."):
            s.close()
            raise ConnectionError("Invalid or no HTTP response from proxy on CONNECT.")
        if b" 200 " not in data:
            s.close()
            raise ConnectionError("HTTP proxy CONNECT returned non-200 status.")

    return s

def open_connection(ip, port, timeout=1.0, socks_proxy=None, http_proxy=None):
    """
    Decide how to open the connection (direct, SOCKS, or HTTP proxy).
    """
    if socks_proxy:
        return open_connection_socks(ip, port, timeout, socks_proxy)
    elif http_proxy:
        return open_connection_http(ip, port, timeout, http_proxy)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((str(ip), port))
        return s

def is_port_open(ip, port, timeout=1.0, socks_proxy=None, http_proxy=None):
    """
    Check if TCP port is open.
    """
    try:
        with open_connection(ip, port, timeout, socks_proxy, http_proxy) as s:
            return True
    except Exception:
        return False

def detect_http_proxy(ip, port, timeout=1.0, hostname=None, socks_proxy=None, http_proxy=None):
    """
    Attempt HTTP CONNECT to see if remote is an HTTP proxy.
    """
    try:
        with open_connection(ip, port, timeout, socks_proxy, http_proxy) as s:
            connect_host = hostname if hostname else str(ip)
            request = (
                f"CONNECT {connect_host}:443 HTTP/1.1\r\n"
                f"Host: {connect_host}:443\r\n"
                "User-Agent: dmzbuster\r\n"
                "\r\n"
            ).encode("utf-8")

            s.sendall(request)
            data = s.recv(2048)
            if b"HTTP/" in data:
                data_str = data.decode(errors="ignore")
                first_line = data_str.split('\r\n', 1)[0].upper()
                if ("200" in first_line or
                    "403" in first_line or
                    "407" in first_line or
                    "PROXY-" in data_str.upper()):
                    fingerprint = data_str.replace('\n', ' ').replace('\r', '')[:300]
                    return True, fingerprint
    except Exception:
        pass
    return False, ""

def detect_socks4_proxy(ip, port, timeout=1.0, socks_proxy=None, http_proxy=None):
    """
    Attempt a SOCKS4 handshake on remote host.
    """
    try:
        with open_connection(ip, port, timeout, socks_proxy, http_proxy) as s:
            req = b"\x04\x01\x00\x50\x01\x01\x01\x01\x00"
            s.sendall(req)
            resp = s.recv(8)
            if len(resp) >= 2 and resp[0] == 0x00 and resp[1] == 0x5A:
                return True, f"SOCKS4 handshake success (raw: {resp.hex()})"
    except Exception:
        pass
    return False, ""

def detect_socks5_proxy(ip, port, timeout=1.0, socks_proxy=None, http_proxy=None):
    """
 ttempt a SOCKS5 handshake on remote host.
    """
    try:
        with open_connection(ip, port, timeout, socks_proxy, http_proxy) as s:
            s.sendall(b"\x05\x01\x00")  # version 5, no-auth
            resp = s.recv(2)
            if len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00:
                return True, f"SOCKS5 handshake success (raw: {resp.hex()})"
    except Exception:
        pass
    return False, ""

def scan_ports_on_host(ip, ports, timeout=1.0, hostname=None, socks_proxy=None, http_proxy=None):
    """
    Top 50 port proxy logic detection
    """
    findings = []
    for port in ports:
        if is_port_open(ip, port, timeout, socks_proxy, http_proxy):
            # Check HTTP proxy
            is_http, http_fp = detect_http_proxy(ip, port, timeout, hostname, socks_proxy, http_proxy)
            if is_http:
                findings.append((str(ip), port, "HTTP Proxy", http_fp))
                continue

            # Check SOCKS4
            is_s4, s4_fp = detect_socks4_proxy(ip, port, timeout, socks_proxy, http_proxy)
            if is_s4:
                findings.append((str(ip), port, "SOCKS4 Proxy", s4_fp))
                continue

            # Check SOCKS5
            is_s5, s5_fp = detect_socks5_proxy(ip, port, timeout, socks_proxy, http_proxy)
            if is_s5:
                findings.append((str(ip), port, "SOCKS5 Proxy", s5_fp))
                continue
    return findings


# Example default ports, edit if more are needed.
FOOTHOLD_PORTS = [80, 443, 8080, 8443, 8844, 9191]

def http_get(ip, port, path, timeout=3.0, http_proxy=None):
    """
    Perform a basic HTTP GET request for "ip:port/path".
    If --http_proxy is supplied, route via that proxy using open_connection_http().
    Otherwise, direct connection.

    We also IGNORE invalid SSL certs if the port is typically HTTPS. 
    Returns (status_code, body_string) - 'body_string' excludes headers.
    """
    try:
        # 1) Create or open connection
        if http_proxy:
            sock = open_connection_http(ip, port, timeout, http_proxy)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((str(ip), port))

        # If typical HTTPS port, wrap with SSL ignoring cert validity
        if port in [443, 8443, 8844, 9191]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=str(ip))

        # 2) Build GET request
        host_str = f"{ip}:{port}"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_str}\r\n"
            "User-Agent: dmzbuster-foothold\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")

        sock.sendall(req)

        # 3) Read response
        data_chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data_chunks.append(chunk)
        except socket.timeout:
            pass

        resp_data = b"".join(data_chunks)
        sock.close()

        # 4) Separate headers from body
        parts = resp_data.split(b"\r\n\r\n", 1)
        header_part = parts[0] if len(parts) > 0 else b""
        body_part = parts[1] if len(parts) > 1 else b""

        # 5) Parse status code
        first_line = header_part.split(b"\r\n", 1)[0]
        status_code = None
        if b"HTTP/" in first_line:
            try:
                elements = first_line.split()
                status_code = int(elements[1])
            except:
                pass

        body_str = body_part.decode("utf-8", errors="ignore")

        return (status_code, body_str)
    except Exception:
        return (None, "")

def fingerprint_foothold(ip, port, timeout=3.0, http_proxy=None):
    """Detection for:
      - HP iLO
      - PaperCut
      - WhatsUp Gold
      - Spring Boot
      - ColdFusion
      - Tomcat Invoker
    """

    found_products = []

    # ============= HP iLO + PaperCut on GET /
    st_main, body_main = http_get(ip, port, "/", timeout, http_proxy)
    if st_main == 200:
        # HP iLO => must see iLO indicator in the body
        if ("src=js/iLO.js" in body_main) or ("Hewlett Packard Enterprise Development LP" in body_main):
            found_products.append("HP iLO")
        # PaperCut => also only if 200 => body contains "PaperCut Login"
        if ("<title>PaperCut Login" in body_main) or ("PaperCut Login" in body_main):
            found_products.append("PaperCut")

    # ============= WhatsUp Gold =============
    # Forcefully browse to /NmConsole/, check 200 + body text
    st_wug, body_wug = http_get(ip, port, "/NmConsole/", timeout, http_proxy)
    # We require 200, plus some mention of "WhatsUp" or "NmConsole" in the body
    if st_wug == 200 and ("WhatsUp" in body_wug or "NmConsole" in body_wug or "WUG" in body_wug):
        found_products.append("WhatsUp Gold")

    # ============= Spring Boot =============
    # Force-browse /actutor/env or /h2-console/login.jsp
    spring_paths = ["/actutor/env", "/h2-console/login.jsp"]
    for sp in spring_paths:
        st_spring, body_spring = http_get(ip, port, sp, timeout, http_proxy)
        # We'll consider it Spring Boot if we get 2xx, 401, or 500 AND 
        # the body has something referencing "Spring" or "actuator" or "h2"
        if st_spring in ([c for c in range(200, 300)] + [401, 500]):
            if ("Spring" in body_spring or "spring" in body_spring or "actuator" in body_spring or "H2" in body_spring):
                found_products.append("Spring Boot")
                break

    # ============= ColdFusion =============
    # GET /CFIDE/wizards/common/utils.cfc => only if st==200 
    # + body has .cfm/.cfc or "Adobe ColdFusion"
    st_cf, body_cf = http_get(ip, port, "/CFIDE/wizards/common/utils.cfc", timeout, http_proxy)
    if st_cf == 200:
        lc = body_cf.lower()
        if (".cfm" in lc or ".cfc" in lc or "coldfusion" in lc):
            found_products.append("ColdFusion")

    # ============= Tomcat Invoker Servlet =============
    # Forcefully check known paths => only if st=200 + mention of "Tomcat" or "jboss" or "MBean" 
    tomcat_paths = [
        "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
        "/invoker/JMXInvokerServlet",
        "/web-console/Invoker",
        "/admin-console/"
    ]
    for tp in tomcat_paths:
        st_t, bd_t = http_get(ip, port, tp, timeout, http_proxy)
        if st_t == 200:
            # minimal text check: "Tomcat", "JMXInvoker", "jboss.system", etc.
            if ("Tomcat" in bd_t or "jboss.system" in bd_t or "JMXInvoker" in bd_t or "web-console" in bd_t):
                found_products.append("Tomcat Invoker Servlet")
                break

    return found_products

def scan_foothold_host(ip, ports, timeout=3.0, http_proxy=None):
    """
    Check each port; if open, run fingerprint_foothold() for known products.
    Returns a list of (ip, port, product).
    """
    results = []
    for p in ports:
        if is_port_open(ip, p, timeout=timeout, http_proxy=http_proxy):
            products = fingerprint_foothold(ip, p, timeout=timeout, http_proxy=http_proxy)
            for prod in products:
                results.append((str(ip), p, prod))
    return results

# main

def main():
    parser = argparse.ArgumentParser(
        description="Scan a CIDR range or single IP for (HTTP, SOCKS4, SOCKS5) proxies on ~50 common proxy ports, "
                    "and optionally do foothold scans for exploitable HTTP services"
    )

    # Args
    parser.add_argument("--range",
                        help="CIDR range or single IP to scan (e.g. 192.168.0.0/24). Not required if using --find-foothold alone.")
    parser.add_argument("--output",
                        help="Output filename (plain text) to store found proxy results.")
    parser.add_argument("--threads", type=int, default=50,
                        help="Number of worker threads to use (default=50).")
    parser.add_argument("--resolve", action="store_true",
                        help="Attempt reverse DNS and use hostname in the CONNECT request for HTTP proxy detection.")
    parser.add_argument("--dns",
                        help="Use the specified DNS server for reverse lookups (requires dnspython). Example: --dns 8.8.8.8")

    # Proxy arguments
    parser.add_argument("--socks_proxy",
                        help="Supply a SOCKS5 proxy in IP:Port format for scanning (e.g. 127.0.0.1:9050).")
    parser.add_argument("--http_proxy",
                        help="Supply an HTTP proxy in IP:Port format for scanning (e.g. 127.0.0.1:8080).")

    # Foothold arguments
    parser.add_argument("--find-foothold", action="store_true",
                        help="Enable special HTTP-based scans to identify potentially exploitable devices/products via HTTP (HP iLO, PaperCut, etc.). YOU MUST SUPPLY --http_proxy FOR THIS TO WORK")
    parser.add_argument("--foothold_range",
                        help="CIDR range used for foothold scanning (e.g. 192.168.0.0/16). Only ports 80,443,8080,8443,8844,9191 are tested.")

    args = parser.parse_args()

    # If the user didn't supply --range and didn't use --find-foothold, there's nothing to do
    if not args.range and not args.find_foothold:
        print("[!] You must specify either --range or --find-foothold (with --foothold_range).")
        sys.exit(1)

    # If both proxies are given => conflict
    if args.socks_proxy and args.http_proxy:
        print("[!] You cannot specify both --socks_proxy and --http_proxy at the same time.")
        sys.exit(1)

# Proxy scan 
    all_findings = []
    if args.range:
        try:
            if '/' in args.range:
                network = ipaddress.ip_network(args.range, strict=False)
                ip_list = list(network.hosts())
            else:
                single_ip = ipaddress.ip_address(args.range)
                ip_list = [single_ip]
        except ValueError as e:
            print(f"[!] Invalid input '{args.range}': {e}")
            sys.exit(1)

        total_hosts = len(ip_list)
        print(f"[*] Scanning {total_hosts} host(s) with up to {args.threads} threads on ~50 common proxy ports...")

        if args.output:
            print(f"[*] Results will be written to: {args.output}")

        hostname_map = {}
        if args.resolve:
            print(f"[*] Reverse DNS lookups enabled. Using {args.dns if args.dns else 'system default DNS'}.")
            for ip in ip_list:
                host = reverse_dns_lookup(ip, dns_server=args.dns)
                hostname_map[str(ip)] = host

        done_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_ip = {}
            for ip in ip_list:
                hostname = hostname_map.get(str(ip), None) if args.resolve else None
                future = executor.submit(
                    scan_ports_on_host,
                    ip,
                    COMMON_PROXY_PORTS,
                    hostname=hostname,
                    socks_proxy=args.socks_proxy,
                    http_proxy=args.http_proxy
                )
                future_to_ip[future] = ip

            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                done_count += 1
                # Print progress
                percent = (done_count / total_hosts) * 100
                sys.stdout.write(
                    f"\r[Progress] {done_count}/{total_hosts} hosts scanned ({percent:.2f}%)"
                )
                sys.stdout.flush()
                try:
                    results = future.result()
                    if results:
                        for item in results:
                            ip_addr, port, proxy_type, fingerprint = item
                            print(f"\n{ip_addr}:{port} -> {proxy_type}")
                            print(f"   Fingerprint: {fingerprint}")
                        all_findings.extend(results)
                except Exception as ex:
                    print(f"\n[!] Error scanning {ip}: {ex}")

        print("\n[*] Main proxy scan complete.")

        if args.output and all_findings:
            try:
                with open(args.output, 'w') as f:
                    for ip_addr, port, proxy_type, fingerprint in all_findings:
                        f.write(f"{ip_addr}:{port} -> {proxy_type} | Fingerprint: {fingerprint}\n")
                print(f"[*] Wrote proxy-scan results to: {args.output}")
            except Exception as e:
                print(f"[!] Failed to write output to {args.output}: {e}")
    else:
        # If no --range was provided, we skip the main proxy scan entirely
        print("[*] No --range provided. Skipping main proxy scan.")

    # ------------------------
    # Foothold scanning logic
    # ------------------------
    if args.find_foothold:
        if args.foothold_range:
            print("\n[*] Starting foothold scan...")
            try:
                fh_net = ipaddress.ip_network(args.foothold_range, strict=False)
                fh_ips = list(fh_net.hosts())
            except ValueError as e:
                print(f"[!] Invalid foothold_range '{args.foothold_range}': {e}")
                fh_ips = []

            if len(fh_ips) == 0:
                print("[!] No hosts found in foothold_range. Skipping foothold scan.")
            else:
                print(f"[*] Foothold scanning {len(fh_ips)} host(s) on ports {FOOTHOLD_PORTS}.")
                foothold_results = []
                done_count_2 = 0

                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                    future_to_ip_2 = {}
                    for ip in fh_ips:
                        future2 = executor.submit(
                            scan_foothold_host,
                            ip,
                            FOOTHOLD_PORTS,
                            timeout=3.0,
                            http_proxy=args.http_proxy  # We only do HTTP proxy for foothold
                        )
                        future_to_ip_2[future2] = ip

                    for fut in concurrent.futures.as_completed(future_to_ip_2):
                        ip_2 = future_to_ip_2[fut]
                        done_count_2 += 1
                        pct_2 = (done_count_2 / len(fh_ips)) * 100
                        sys.stdout.write(
                            f"\r[Foothold Progress] {done_count_2}/{len(fh_ips)} hosts scanned ({pct_2:.2f}%)"
                        )
                        sys.stdout.flush()

                        try:
                            host_findings = fut.result()
                            if host_findings:
                                for (fhip, fhport, prod) in host_findings:
                                    foothold_results.append((fhip, fhport, prod))
                                    print(f"\n{fhip}:{fhport} ({prod})")
                        except Exception as ex:
                            print(f"\n[!] Error scanning foothold host {ip_2}: {ex}")

                print("\n[*] Foothold scan complete.")
        else:
            print("\n[!] You used --find-foothold but did not specify --foothold_range. No foothold scanning performed.")


if __name__ == "__main__":
    main()
