#!/usr/bin/env python3
"""
HeaderProbe - Security Header Analysis Tool
Analyzes HTTP security headers and cookie flags for any domain you have permission to test.
"""

import requests
import sys
import urllib3
from urllib.parse import urlparse
from datetime import datetime

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

# Fetch headers collecting cookies from ALL redirect steps
def fetch_headers(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    domain = parsed.netloc or parsed.path
    results = {
        "url": url, "domain": domain, "headers": {},
        "all_set_cookie": [], "jar_cookies": [],
        "strategy_used": "", "error": None, "redirects": []
    }

    strategies = [
        {"label": "HTTPS direct",           "url": f"https://{domain}",     "verify": True,  "timeout": 10},
        {"label": "HTTPS (skip SSL verify)", "url": f"https://{domain}",     "verify": False, "timeout": 10},
        {"label": "HTTP fallback",           "url": f"http://{domain}",      "verify": False, "timeout": 10},
        {"label": "HTTPS with www",          "url": f"https://www.{domain}", "verify": False, "timeout": 10},
    ]
    if domain.startswith("www."):
        strategies = [s for s in strategies if "www." not in s["label"]]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "curl/7.88.1",
        "python-requests/2.31.0"
    ]

    for strategy in strategies:
        for ua in user_agents:
            try:
                session = requests.Session()
                session.max_redirects = 10

                req_headers = {
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1"
                }

                resp = session.get(
                    strategy["url"],
                    headers=req_headers,
                    verify=strategy["verify"],
                    timeout=strategy["timeout"],
                    allow_redirects=True
                )

                # Capture redirect chain URLs
                if resp.history:
                    results["redirects"] = [r.url for r in resp.history]

                # Collect Set-Cookie from every step: redirects + final response
                all_set_cookie = []
                for step in list(resp.history) + [resp]:
                    for k, v in step.headers.items():
                        if k.lower() == "set-cookie":
                            all_set_cookie.append(v)

                # Also collect from cookie jar (catches cookies absorbed silently)
                jar_cookies = []
                for cookie in session.cookies:
                    httponly = (
                        cookie.has_nonstandard_attr("HttpOnly") or
                        cookie.has_nonstandard_attr("httponly") or
                        "HttpOnly" in cookie._rest or
                        "httponly" in [k.lower() for k in cookie._rest.keys()]
                    )
                    samesite = cookie._rest.get("SameSite") or cookie._rest.get("samesite") or "Not set"
                    jar_cookies.append({
                        "name":     cookie.name,
                        "secure":   cookie.secure,
                        "httponly": httponly,
                        "samesite": samesite,
                        "domain":   cookie.domain,
                    })

                results["headers"]        = dict(resp.headers)
                results["all_set_cookie"] = all_set_cookie
                results["jar_cookies"]    = jar_cookies
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
    found, missing, leaking, warnings = {}, {}, {}, []
    normalized = {k.lower(): (k, v) for k, v in raw_headers.items()}

    for header, meta in SECURITY_HEADERS.items():
        key = header.lower()
        if key in normalized:
            _, value = normalized[key]
            found[header] = {"value": value, **meta}
            if header == "Strict-Transport-Security":
                if "max-age" not in value.lower():
                    warnings.append("HSTS is present but missing max-age directive.")
                elif "includesubdomains" not in value.lower():
                    warnings.append("HSTS: consider adding includeSubDomains.")
            if header == "X-Frame-Options" and value.upper() not in ["DENY", "SAMEORIGIN"]:
                warnings.append(f"X-Frame-Options value '{value}' may not be effective.")
            if header == "X-Content-Type-Options" and value.lower() != "nosniff":
                warnings.append(f"X-Content-Type-Options should be 'nosniff', got '{value}'.")
        else:
            missing[header] = meta

    for header, reason in INSECURE_HEADERS.items():
        if header.lower() in normalized:
            _, value = normalized[header.lower()]
            leaking[header] = {"value": value, "reason": reason}

    return found, missing, leaking, warnings

# Analyse cookies from Set-Cookie headers + jar
def analyse_cookies(all_set_cookie, jar_cookies):
    """
    Parses raw Set-Cookie strings AND the session cookie jar.
    The jar catches cookies set during redirects that may not appear
    in the final response Set-Cookie header.
    """
    cookie_results = []
    seen_names = set()

    # Parse raw Set-Cookie strings (from all redirect steps + final response)
    for raw in all_set_cookie:
        for cookie_line in raw.split("\n"):
            cookie_line = cookie_line.strip()
            if not cookie_line:
                continue
            parts        = [p.strip() for p in cookie_line.split(";")]
            name_value   = parts[0]
            cookie_name  = name_value.split("=")[0].strip() if "=" in name_value else name_value
            directives   = [p.lower() for p in parts[1:]]
            has_secure   = any(d == "secure"   for d in directives)
            has_httponly = any(d == "httponly"  for d in directives)
            has_samesite = any(d.startswith("samesite") for d in directives)
            samesite_val = next((d for d in directives if d.startswith("samesite")), None)
            samesite_str = samesite_val.split("=")[1].capitalize() if samesite_val and "=" in samesite_val else "Not set"

            issues = []
            if not has_secure:
                issues.append("Missing Secure flag — cookie can be sent over HTTP")
            if not has_httponly:
                issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
            if not has_samesite:
                issues.append("Missing SameSite attribute — vulnerable to CSRF attacks")
            elif samesite_str.lower() == "none" and not has_secure:
                issues.append("SameSite=None requires the Secure flag")

            seen_names.add(cookie_name)
            cookie_results.append({
                "name": cookie_name, "secure": has_secure,
                "httponly": has_httponly, "samesite": samesite_str,
                "issues": issues, "source": "Set-Cookie header"
            })

    # Fill in from cookie jar anything not already captured above
    for ck in jar_cookies:
        if ck["name"] in seen_names:
            continue
        seen_names.add(ck["name"])
        issues = []
        if not ck["secure"]:
            issues.append("Missing Secure flag — cookie can be sent over HTTP")
        if not ck["httponly"]:
            issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
        samesite = ck["samesite"] if ck["samesite"] != "Not set" else "Not set"
        if samesite == "Not set":
            issues.append("Missing SameSite attribute — vulnerable to CSRF attacks")
        cookie_results.append({
            "name": ck["name"], "secure": ck["secure"],
            "httponly": ck["httponly"], "samesite": samesite,
            "issues": issues, "source": f"Cookie jar (domain: {ck['domain']})"
        })

    return cookie_results


def calculate_score(found, missing, leaking):
    weights = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    total   = sum(weights[m["severity"]] for m in SECURITY_HEADERS.values())
    earned  = sum(weights[m["severity"]] for m in found.values())
    penalty = len(leaking) * 5
    score   = max(0, int((earned / total) * 100) - penalty)
    if score >= 80:   grade, color = "A", C.GREEN
    elif score >= 60: grade, color = "B", C.CYAN
    elif score >= 40: grade, color = "C", C.YELLOW
    else:             grade, color = "D", C.RED
    return score, grade, color

def print_report(result, found, missing, leaking, warnings, score, grade, color, cookies):
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

    print(f"\n  {C.BOLD}Security Score: {color}{score}/100  |  Grade: {grade}{C.END}\n")
    print(C.HEADER + "-" * w + C.END)

    # Present headers
    print(f"\n{C.BOLD}{C.GREEN}  PRESENT SECURITY HEADERS ({len(found)}){C.END}")
    if found:
        for h, meta in found.items():
            sc = C.RED if meta["severity"] == "HIGH" else C.YELLOW if meta["severity"] == "MEDIUM" else C.CYAN
            print(f"\n  {C.BOLD}{C.GREEN}+ {h}{C.END}")
            print(f"    Value      : {meta['value']}")
            print(f"    Severity   : {sc}{meta['severity']}{C.END}")
            print(f"    Description: {meta['description']}")
    else:
        print(f"  {C.RED}None found.{C.END}")

    # Missing headers
    print(f"\n{C.BOLD}{C.RED}  MISSING SECURITY HEADERS ({len(missing)}){C.END}")
    if missing:
        for h, meta in missing.items():
            sc = C.RED if meta["severity"] == "HIGH" else C.YELLOW if meta["severity"] == "MEDIUM" else C.CYAN
            print(f"\n  {C.BOLD}{C.RED}- {h}{C.END}")
            print(f"    Severity      : {sc}{meta['severity']}{C.END}")
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

    # Cookie security
    print(f"\n{C.BOLD}{C.BLUE}  COOKIE SECURITY ANALYSIS ({len(cookies)}){C.END}")
    if cookies:
        for ck in cookies:
            status_color = C.GREEN if not ck["issues"] else C.RED
            print(f"\n  {C.BOLD}{status_color}~ {ck['name']}{C.END}")
            print(f"    Source   : {ck['source']}")
            print(f"    Secure   : {C.GREEN + 'Yes' + C.END if ck['secure']   else C.RED + 'No' + C.END}")
            print(f"    HttpOnly : {C.GREEN + 'Yes' + C.END if ck['httponly'] else C.RED + 'No' + C.END}")
            print(f"    SameSite : {ck['samesite']}")
            if ck["issues"]:
                for issue in ck["issues"]:
                    print(f"    {C.YELLOW}⚠ {issue}{C.END}")
            else:
                print(f"    {C.GREEN}✓ All cookie flags correctly set{C.END}")
    else:
        print(f"  {C.CYAN}No cookies found in HTTP response or redirect chain.{C.END}")
        print(f"  {C.CYAN}Note: cookies set by JavaScript after page load are not visible at the HTTP level.{C.END}")

    # All raw headers
    print(f"\n{C.BOLD}{C.BLUE}  ALL RESPONSE HEADERS{C.END}")
    for k, v in result["headers"].items():
        print(f"  {C.CYAN}{k}{C.END}: {v}")

    print()
    print(C.BOLD + C.HEADER + "=" * w + C.END)
    print()


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
    print(f"  {C.YELLOW}Security Header Analysis Tool{C.END}")
    print(f"  {C.RED}Only use on domains you own or have permission to test.{C.END}\n")

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
    cookies = analyse_cookies(result["all_set_cookie"], result["jar_cookies"])
    score, grade, color = calculate_score(found, missing, leaking)
    print_report(result, found, missing, leaking, warnings, score, grade, color, cookies)

if __name__ == "__main__":
    main()