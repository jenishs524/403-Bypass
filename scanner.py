#!/usr/bin/env python3
"""Automated attack-point tester for an authorised OWASP Juice Shop instance.

Attack points: (A) authentication state, (B) product-search input,
(C) HTTP security headers. Usage:
    python3 scanner.py --url http://127.0.0.1:3000 [--token JWT]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import requests

TIMEOUT = 10
SEARCH_CASES = {
    "normal": "apple",
    "special_characters": "'\"`;(){}<>",
    "sql_syntax_probe": "' OR 1=1--",
}
ERROR_SIGNATURES = ["sqlite", "sequelize", "sql syntax", "syntax error",
                    "traceback", "stack trace", "unexpected token"]
REQUIRED_HEADERS = ["Content-Security-Policy"]
results = []


def record(point, test, level, message, status=None):
    results.append({"attack_point": point, "test": test, "severity": level,
                    "message": message, "status_code": status})
    label = f"{test} : " if test else ""
    print(f"{label}{level}: {message}")


def fetch(session, url, params=None):
    """GET with timeout; returns a Response or None on network failure."""
    try:
        return session.get(url, params=params, timeout=TIMEOUT)
    except requests.RequestException as exc:
        print(f"ERROR: request failed ({exc.__class__.__name__})")
        return None


def check_authentication(session, base, token):
    print("\n[+]  Authentication")
    r = fetch(session, base + "/rest/user/whoami")
    if r is None:
        record("authentication", "", "ERROR", "Endpoint unreachable")
        return
    try:
        user = r.json().get("user")
    except ValueError:
        record("authentication", "", "ERROR", "Non-JSON response", r.status_code)
        return
    if not user and not token:
        record("authentication", "", "INFO", "Empty anonymous user object", r.status_code)
    elif not user:
        record("authentication", "", "REVIEW", "Token supplied but user object is empty",
            r.status_code)
    elif token:
        record("authentication", "", "INFO", "Authenticated user object returned",
            r.status_code)
    else:
        record("authentication", "", "REVIEW", "User data returned without credentials",
            r.status_code)


def check_search(session, base):
    print("\n[+]  Search Input")
    for name, payload in SEARCH_CASES.items():
        r = fetch(session, base + "/rest/products/search", {"q": payload})
        if r is None:
            record("search", name, "ERROR", "No response")
            continue
        body = r.text.lower()
        if r.status_code >= 500 or any(s in body for s in ERROR_SIGNATURES):
            record("search", name, "REVIEW", "Possible database error disclosure",
                r.status_code)
        else:
            record("search", name, "INFO", "No obvious error signature", r.status_code)


def check_headers(session, base):
    print("\n[+]  Security Headers")
    r = fetch(session, base + "/")
    if r is None:
        record("headers", "", "ERROR", "Target unreachable")
        return
    for header in REQUIRED_HEADERS:
        if header.lower() not in {k.lower() for k in r.headers}:
            record("headers", "", "REVIEW", "Missing " + header.replace("-", " "),
                r.status_code)
        else:
            record("headers", "", "INFO", header + " present", r.status_code)


def main():
    ap = argparse.ArgumentParser(description="Juice Shop automated tester")
    ap.add_argument("--url", required=True, help="e.g. http://127.0.0.1:3000")
    ap.add_argument("--token", default=None, help="optional JWT")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    token = (args.token or "").strip() or None
    session = requests.Session()
    if token:
        session.headers["Authorization"] = "Bearer " + token
        session.cookies.set("token", token)
    elif args.token is not None:
        print("WARNING: empty --token supplied; continuing anonymously")
    print("=== AUTOMATED SECURITY TESTING ===")
    print("Target:", base)
    check_authentication(session, base, token)
    check_search(session, base)
    check_headers(session, base)
    os.makedirs("results", exist_ok=True)
    report = {"target": base, "token_supplied": bool(token),
              "timestamp": datetime.now(timezone.utc).isoformat(),
              "results": results}
    with open("results/test_results.json", "w") as fh:
        json.dump(report, fh, indent=2)
    print("\nReport saved: results/test_results.json")


if __name__ == "__main__":
    sys.exit(main())
