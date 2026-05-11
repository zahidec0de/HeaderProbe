#!/usr/bin/env python3
"""
HeaderProbe - Security Header Analysis Script
Analyzes HTTP security headers for any domain with landing page.
"""

import requests
import ssl
import socket
import sys
import json
import urllib3
from urllib.parse import urlparse
from datetime import datetime
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class C:
    HEADER  = '\033[95m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    BOLD    = '\033[1m'
    END     = '\033[0m'


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces browsers to use HTTPS",
        "recommendation": "max-age=31536000; includeSubDomains",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "description": "Controls resources the browser is allowed to load",
        "recommendation": "Define a strict policy limiting sources",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "recommendation": "DENY or SAMEORIGIN",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommendation": "nosniff",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "recommendation": "strict-origin-when-cross-origin",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "recommendation": "Restrict camera, microphone, geolocation, etc.",
        "severity": "MEDIUM"
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (still useful for older browsers)",
        "recommendation": "1; mode=block",
        "severity": "LOW"
    },
    "Cache-Control": {
        "description": "Controls caching of sensitive content",
        "recommendation": "no-store for sensitive pages",
        "severity": "LOW"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context from cross-origin documents",
        "recommendation": "same-origin",
        "severity": "MEDIUM"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls which origins can load the resource",
        "recommendation": "same-origin or same-site",
        "severity": "MEDIUM"
    }
}

INSECURE_HEADERS = {
    "Server": "Exposes server software and version",
    "X-Powered-By": "Exposes backend technology",
    "X-AspNet-Version": "Exposes ASP.NET version",
    "X-AspNetMvc-Version": "Exposes ASP.NET MVC version",
}

# Fetch headers with multiple fallback strategies
def fetch_headers(url):
    """
    Attempts to fetch headers using multiple strategies to handle
    common connectivity issues like redirects, SSL mismatches, and timeouts.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    domain = parsed.netloc or parsed.path
    results = {"url": url, "domain": domain, "headers": {}, "strategy_used": "", "error": None, "redirects": []}

    strategies = [
        {"label": "HTTPS direct",          "url": f"https://{domain}",  "verify": True,  "timeout": 10},
        {"label": "HTTPS (skip SSL verify)","url": f"https://{domain}",  "verify": False, "timeout": 10},
        {"label": "HTTP fallback",          "url": f"http://{domain}",   "verify": False, "timeout": 10},
        {"label": "HTTPS with www",         "url": f"https://www.{domain}", "verify": False, "timeout": 10},
    ]

    # Remove duplicate strategies if user already included www
    if domain.startswith("www."):
        strategies = [s for s in strategies if "www." not in s["label"]]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "curl/7.88.1",
        "python-requests/2.31.0"
    ]

    session = requests.Session()
    session.max_redirects = 10

    for strategy in strategies:
        for ua in user_agents:
            try:
                headers_to_send = {
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1"
                }

                resp = session.get(
                    strategy["url"],
                    headers=headers_to_send,
                    verify=strategy["verify"],
                    timeout=strategy["timeout"],
                    allow_redirects=True
                )

                # Capture redirect chain
                if resp.history:
                    results["redirects"] = [r.url for r in resp.history]

                results["headers"]        = dict(resp.headers)
                results["status_code"]    = resp.status_code
                results["strategy_used"]  = f"{strategy['label']} | UA: {ua[:30]}..."
                results["final_url"]      = resp.url
                return results

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

    results["error"] = "Could not reach the host after trying all strategies."
    return results

def analyse_headers(raw_headers):
    found     = {}
    missing   = {}
    leaking   = {}
    warnings  = []

    # Normalize keys for case-insensitive comparison
    normalized = {k.lower(): (k, v) for k, v in raw_headers.items()}

    for header, meta in SECURITY_HEADERS.items():
        key = header.lower()
        if key in normalized:
            orig_key, value = normalized[key]
            found[header] = {"value": value, **meta}

            # Specific value checks
            if header == "Strict-Transport-Security":
                if "max-age" not in value.lower():
                    warnings.append(f"HSTS is present but missing max-age directive.")
                elif "includesubdomains" not in value.lower():
                    warnings.append(f"HSTS: consider adding includeSubDomains.")
            if header == "X-Frame-Options" and value.upper() not in ["DENY", "SAMEORIGIN"]:
                warnings.append(f"X-Frame-Options value '{value}' may not be effective.")
            if header == "X-Content-Type-Options" and value.lower() != "nosniff":
                warnings.append(f"X-Content-Type-Options should be 'nosniff', got '{value}'.")
        else:
            missing[header] = meta

    for header, reason in INSECURE_HEADERS.items():
        key = header.lower()
        if key in normalized:
            orig_key, value = normalized[key]
            leaking[header] = {"value": value, "reason": reason}

    return found, missing, leaking, warnings

# Scoring
def calculate_score(found, missing, leaking):
    weights = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    total   = sum(weights[m["severity"]] for m in SECURITY_HEADERS.values())
    earned  = sum(weights[m["severity"]] for m in found.values())
    penalty = len(leaking) * 5
    score   = max(0, int((earned / total) * 100) - penalty)

    if score >= 80:
        grade, color = "A", C.GREEN
    elif score >= 60:
        grade, color = "B", C.CYAN
    elif score >= 40:
        grade, color = "C", C.YELLOW
    else:
        grade, color = "D", C.RED

    return score, grade, color

# Report printer
def print_report(result, found, missing, leaking, warnings, score, grade, color):
    w = 65
    print()
    print(C.BOLD + C.HEADER + "=" * w + C.END)
    print(C.BOLD + "  HeaderProbe — Security Header Analysis Report".center(w) + C.END)
    print(C.BOLD + C.HEADER + "=" * w + C.END)
    print(f"  {C.BOLD}Target   :{C.END} {result['domain']}")
    print(f"  {C.BOLD}Final URL:{C.END} {result.get('final_url', result['url'])}")
    print(f"  {C.BOLD}Status   :{C.END} {result.get('status_code', 'N/A')}")
    print(f"  {C.BOLD}Strategy :{C.END} {result.get('strategy_used', 'N/A')}")
    print(f"  {C.BOLD}Scanned  :{C.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if result["redirects"]:
        print(f"  {C.BOLD}Redirects:{C.END} {' → '.join(result['redirects'])}")
    print(C.HEADER + "-" * w + C.END)

    # Score
    print(f"\n  {C.BOLD}Security Score: {color}{score}/100  |  Grade: {grade}{C.END}\n")
    print(C.HEADER + "-" * w + C.END)

    # Present headers
    print(f"\n{C.BOLD}{C.GREEN}  PRESENT SECURITY HEADERS ({len(found)}){C.END}")
    if found:
        for h, meta in found.items():
            sev_color = C.RED if meta["severity"] == "HIGH" else C.YELLOW if meta["severity"] == "MEDIUM" else C.CYAN
            print(f"\n  {C.BOLD}{C.GREEN}+ {h}{C.END}")
            print(f"    Value      : {meta['value']}")
            print(f"    Severity   : {sev_color}{meta['severity']}{C.END}")
            print(f"    Description: {meta['description']}")
    else:
        print(f"  {C.RED}None found.{C.END}")

    # Missing headers
    print(f"\n{C.BOLD}{C.RED}  MISSING SECURITY HEADERS ({len(missing)}){C.END}")
    if missing:
        for h, meta in missing.items():
            sev_color = C.RED if meta["severity"] == "HIGH" else C.YELLOW if meta["severity"] == "MEDIUM" else C.CYAN
            print(f"\n  {C.BOLD}{C.RED}- {h}{C.END}")
            print(f"    Severity      : {sev_color}{meta['severity']}{C.END}")
            print(f"    Description   : {meta['description']}")
            print(f"    Recommendation: {meta['recommendation']}")
    else:
        print(f"  {C.GREEN}None missing. Well configured!{C.END}")

    # Information leakage
    print(f"\n{C.BOLD}{C.YELLOW}  INFORMATION LEAKAGE ({len(leaking)}){C.END}")
    if leaking:
        for h, meta in leaking.items():
            print(f"\n  {C.BOLD}{C.YELLOW}! {h}{C.END}")
            print(f"    Value : {meta['value']}")
            print(f"    Risk  : {meta['reason']}")
    else:
        print(f"  {C.GREEN}No sensitive headers exposed.{C.END}")

    # Warnings
    if warnings:
        print(f"\n{C.BOLD}{C.YELLOW}  CONFIGURATION WARNINGS{C.END}")
        for w_msg in warnings:
            print(f"  {C.YELLOW}⚠ {w_msg}{C.END}")

    # All raw headers
    print(f"\n{C.BOLD}{C.BLUE}  ALL RESPONSE HEADERS{C.END}")
    for k, v in result["headers"].items():
        print(f"  {C.CYAN}{k}{C.END}: {v}")

    print()
    print(C.BOLD + C.HEADER + "=" * w + C.END)
    print()

# Main execution
def main():
    print(f"\n{C.BOLD}{C.CYAN}")
    print("  ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ")
    print("  ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗")
    print("  ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝")
    print("  ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗")
    print("  ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║")
    print("  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝")
    print(f"  {'P R O B E':^48}")
    print(f"{C.END}")
    print(f"  {C.YELLOW}Security Header Analysis Script{C.END}")

    if len(sys.argv) < 2:
        target = input("  Enter domain or URL to scan: ").strip()
    else:
        target = sys.argv[1].strip()

    if not target:
        print(f"{C.RED}  No target provided. Exiting.{C.END}")
        sys.exit(1)

    print(f"\n  {C.CYAN}Fetching headers for: {target}{C.END}")
    print(f"  {C.CYAN}Trying multiple strategies...{C.END}\n")

    result = fetch_headers(target)

    if result["error"]:
        print(f"\n  {C.RED}Error: {result['error']}{C.END}\n")
        sys.exit(1)

    found, missing, leaking, warnings = analyse_headers(result["headers"])
    score, grade, color = calculate_score(found, missing, leaking)
    print_report(result, found, missing, leaking, warnings, score, grade, color)

if __name__ == "__main__":
    main()