#!/usr/bin/env python3
"""
pentool.py - Multi-function recon & assessment toolkit
Dành cho kiểm thử xâm nhập được ủy quyền.
Usage:
    python3 pentool.py scan  <host> -p 1-1000
    python3 pentool.py banner <host> -p 80,443,22
    python3 pentool.py dirs  <url> -w wordlist.txt
    python3 pentool.py sub   <domain> -w subdomains.txt
"""

import argparse
import socket
import ssl
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib.request
import urllib.error

# ---------- 1. Port Scanner (TCP Connect + thread pool) ----------

def scan_port(host, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
    except (socket.error, socket.gaierror):
        pass
    return None

def cmd_scan(args):
    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.host} ({len(ports)} ports)...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, args.host, p): p for p in ports}
        for f in as_completed(futures):
            port = f.result()
            if port:
                service = get_banner(args.host, port)
                open_ports.append(port)
                print(f"  [+] {port}/tcp open  {service or ''}")
    print(f"[*] Done. {len(open_ports)} open port(s): {open_ports}")

def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ---------- 2. Banner Grabbing ----------

def get_banner(host, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    return ss.recv(512).decode(errors="replace").strip()
            # Gửi HEAD đơn giản để kích HTTP server trả banner
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            return s.recv(512).decode(errors="replace").split("\r\n")[0]
    except Exception:
        return None

def cmd_banner(args):
    for port in parse_ports(args.ports):
        b = get_banner(args.host, port)
        status = b if b else "(no banner / filtered)"
        print(f"  {args.host}:{port} -> {status}")

# ---------- 3. Directory / File Brute-forcer ----------

def check_path(base_url, path, timeout=5):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "pentool/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return path, r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return path, e.code, 0
    except Exception:
        return path, None, 0

def cmd_dirs(args):
    base = args.url if urlparse(args.url).scheme else "http://" + args.url
    print(f"[*] Bruteforcing directories on {base}")
    with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
        words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_path, base, w): w for w in words}
        for f in as_completed(futures):
            path, status, size = f.result()
            if status and status not in (404, 400):
                print(f"  [{status}] /{path}  ({size} bytes)")

# ---------- 4. Subdomain Enumeration ----------

def check_subdomain(domain, sub, timeout=3):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return None

def cmd_sub(args):
    print(f"[*] Enumerating subdomains of {args.domain}")
    with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
        subs = [w.strip() for w in fh if w.strip()]
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_subdomain, args.domain, s): s for s in subs}
        for f in as_completed(futures):
            r = f.result()
            if r:
                print(f"  [+] {r[0]} -> {r[1]}")

# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="Pentest recon toolkit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="TCP port scan")
    p.add_argument("host"); p.add_argument("-p", "--ports", default="1-1024")
    p.add_argument("-t", "--threads", type=int, default=100)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("banner", help="Banner grab")
    p.add_argument("host"); p.add_argument("-p", "--ports", required=True)
    p.set_defaults(func=cmd_banner)

    p = sub.add_parser("dirs", help="Directory brute-force")
    p.add_argument("url"); p.add_argument("-w", "--wordlist", required=True)
    p.add_argument("-t", "--threads", type=int, default=20)
    p.set_defaults(func=cmd_dirs)

    p = sub.add_parser("sub", help="Subdomain enumeration")
    p.add_argument("domain"); p.add_argument("-w", "--wordlist", required=True)
    p.add_argument("-t", "--threads", type=int, default=50)
    p.set_defaults(func=cmd_sub)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()