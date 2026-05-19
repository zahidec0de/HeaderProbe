#!/usr/bin/env python3
"""
HeaderProbe v2.0 — Security Header & HTTP Analysis Tool
Analyzes HTTP security headers, validates directives, checks cookie
flags, and performs HTTP probing to raw curl for security assessments.
"""

import sys
import os
import json
import time
import socket
import ssl
import argparse
import hashlib
import re
import concurrent.futures
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from collections import defaultdict

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[FATAL] 'requests' not installed. Run: pip install requests")
    sys.exit(1)


class C:
    HEADER = '\033[95m'; BLUE  = '\033[94m'; CYAN   = '\033[96m'
    GREEN  = '\033[92m'; AMBER = '\033[93m'; RED    = '\033[91m'
    BOLD   = '\033[1m';  DIM   = '\033[2m';  RESET  = '\033[0m'
    ITALIC = '\033[3m';  UL    = '\033[4m'

NO_COLOR = not sys.stdout.isatty()

def c(code, text):
    return text if NO_COLOR else f"{code}{text}{C.RESET}"

def bold(t):    return c(C.BOLD,   t)
def dim(t):     return c(C.DIM,    t)
def red(t):     return c(C.RED,    t)
def green(t):   return c(C.GREEN,  t)
def amber(t):   return c(C.AMBER,  t)
def cyan(t):    return c(C.CYAN,   t)
def blue(t):    return c(C.BLUE,   t)
def magenta(t): return c(C.HEADER, t)

# SECURITY HEADER DEFINITIONS with full directive validation rules

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections for the domain",
        "severity": "HIGH",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "directives": {
            "valid": {"max-age", "includesubdomains", "preload"},
            "required": {"max-age"},
            "value_validators": {
                "max-age": lambda v: v.isdigit() and int(v) > 0,
            },
            "warn_if_low": {"max-age": 86400},        # < 1 day is suspicious
            "warn_if_missing": {"includesubdomains"},
        }
    },
    "Content-Security-Policy": {
        "description": "Controls which resources the browser may load",
        "severity": "HIGH",
        "recommendation": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
        "directives": {
            "valid": {
                "default-src","script-src","style-src","img-src","font-src",
                "connect-src","media-src","object-src","frame-src","frame-ancestors",
                "child-src","worker-src","manifest-src","prefetch-src","form-action",
                "base-uri","sandbox","report-uri","report-to","upgrade-insecure-requests",
                "block-all-mixed-content","require-trusted-types-for","trusted-types",
                "navigate-to","plugin-types","disown-opener",
            },
            "unsafe_values": {"'unsafe-inline'","'unsafe-eval'","*","data:","http:"},
            "deprecated": {"plugin-types","prefetch-src","disown-opener","block-all-mixed-content"},
            "report_only_equivalent": "Content-Security-Policy-Report-Only",
        }
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling frame embedding",
        "severity": "MEDIUM",
        "recommendation": "DENY",
        "note": "Superseded by CSP frame-ancestors but still needed for older browsers",
        "directives": {
            "valid_values": {"DENY", "SAMEORIGIN"},
            "invalid_note": "ALLOWFROM is deprecated and widely unsupported"
        }
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "nosniff",
        "directives": {
            "valid_values": {"nosniff"},
        }
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is sent with requests",
        "severity": "LOW",
        "recommendation": "strict-origin-when-cross-origin",
        "directives": {
            "valid_values": {
                "no-referrer","no-referrer-when-downgrade","origin",
                "origin-when-cross-origin","same-origin","strict-origin",
                "strict-origin-when-cross-origin","unsafe-url",""
            },
            "weak_values": {"unsafe-url","no-referrer-when-downgrade"},
        }
    },
    "Permissions-Policy": {
        "description": "Controls access to browser APIs and hardware features",
        "severity": "MEDIUM",
        "recommendation": "camera=(), microphone=(), geolocation=(), payment=()",
        "directives": {
            "known_features": {
                "accelerometer","ambient-light-sensor","autoplay","battery","bluetooth",
                "camera","ch-device-memory","ch-dpr","ch-downlink","ch-ect","ch-lang",
                "ch-rtt","ch-ua","ch-ua-arch","ch-ua-bitness","ch-ua-full-version",
                "ch-ua-full-version-list","ch-ua-mobile","ch-ua-model","ch-ua-platform",
                "ch-ua-platform-version","ch-ua-wow64","ch-width","ch-viewport-width",
                "clipboard-read","clipboard-write","conversion-measurement",
                "cross-origin-isolated","display-capture","document-domain",
                "encrypted-media","execution-while-not-rendered",
                "execution-while-out-of-viewport","focus-without-user-activation",
                "fullscreen","gamepad","geolocation","gyroscope","hid","idle-detection",
                "interest-cohort","keyboard-map","magnetometer","microphone","midi",
                "navigation-override","otp-credentials","payment","picture-in-picture",
                "publickey-credentials-get","screen-wake-lock","serial",
                "shared-autofill","speaker-selection","storage-access","sync-script",
                "sync-xhr","trust-token-redemption","unload","usb","vertical-scroll",
                "web-share","window-placement","xr-spatial-tracking",
            },
        }
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates the browsing context to prevent cross-origin attacks",
        "severity": "MEDIUM",
        "recommendation": "same-origin",
        "directives": {
            "valid_values": {"unsafe-none","same-origin-allow-popups","same-origin"},
            "report_only_equivalent": "Cross-Origin-Opener-Policy-Report-Only",
        }
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls which origins can read this resource",
        "severity": "MEDIUM",
        "recommendation": "same-origin",
        "directives": {
            "valid_values": {"same-site","same-origin","cross-origin"},
        }
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Requires cross-origin resources to opt-in to being embedded",
        "severity": "MEDIUM",
        "recommendation": "require-corp",
        "directives": {
            "valid_values": {"unsafe-none","require-corp","credentialless"},
            "report_only_equivalent": "Cross-Origin-Embedder-Policy-Report-Only",
        }
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (browsers are deprecating it)",
        "severity": "LOW",
        "recommendation": "0  (disable — rely on CSP instead)",
        "note": "Modern guidance is to set this to '0' and use CSP",
        "directives": {
            "valid_values": {"0","1","1; mode=block","1; report="},
        }
    },
    "Cache-Control": {
        "description": "Controls caching behaviour for sensitive responses",
        "severity": "LOW",
        "recommendation": "no-store, no-cache, must-revalidate (for authenticated pages)",
        "directives": {
            "valid": {
                "no-store","no-cache","no-transform","must-revalidate",
                "proxy-revalidate","private","public","max-age","s-maxage",
                "max-stale","min-fresh","only-if-cached","immutable",
                "stale-while-revalidate","stale-if-error",
            },
            "invalid": {"no-store=","no-cache="},  # These directives take no value
        }
    },
    "Clear-Site-Data": {
        "description": "Instructs the browser to clear stored data (useful on logout)",
        "severity": "LOW",
        "recommendation": '"cache", "cookies", "storage" (on logout endpoint)',
        "directives": {
            "valid_values": {'"cache"','"cookies"','"storage"','"executionContexts"','"*"'},
        }
    },
    "Expect-CT": {
        "description": "Certificate Transparency enforcement (deprecated in 2021+)",
        "severity": "LOW",
        "recommendation": "Remove — Chrome ignores it; rely on browser-native CT",
        "deprecated": True,
    },
    "Feature-Policy": {
        "description": "Predecessor to Permissions-Policy (deprecated)",
        "severity": "LOW",
        "recommendation": "Replace with Permissions-Policy",
        "deprecated": True,
    },
}

LEAK_HEADERS = {
    "Server":              "Exposes web server software/version",
    "X-Powered-By":        "Reveals backend language/framework",
    "X-AspNet-Version":    "Reveals ASP.NET runtime version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
    "X-Generator":         "Reveals CMS or site generator",
    "X-Drupal-Cache":      "Reveals Drupal CMS usage",
    "X-Varnish":           "Reveals Varnish cache usage",
    "Via":                 "Exposes proxy infrastructure details",
    "X-Backend-Server":    "Exposes internal backend hostnames",
    "X-Forwarded-For":     "May expose internal IP topology if echoed back",
    "X-Forwarded-Host":    "May expose internal hostnames",
    "X-CF-Powered-By":     "Reveals ColdFusion usage",
    "X-OWA-Version":       "Reveals Microsoft OWA version",
    "MicrosoftSharePointTeamServices": "Reveals SharePoint version",
    "X-Content-Encoded-By": "Reveals content encoding system",
    "Liferay-Portal":      "Reveals Liferay portal",
}

# DIRECTIVE VALIDATORS

def validate_hsts(value: str):
    issues, warnings, info = [], [], []
    parts = [p.strip().lower() for p in value.split(";") if p.strip()]
    directives = {}
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip()] = v.strip()
        else:
            directives[part] = None

    known = {"max-age", "includesubdomains", "preload"}
    for d in directives:
        if d not in known:
            issues.append(f"Unknown directive '{d}' — will be ignored by browsers")

    if "max-age" not in directives:
        issues.append("Missing required 'max-age' directive")
    else:
        age_str = directives["max-age"]
        if not age_str or not age_str.isdigit():
            issues.append(f"'max-age' must be a non-negative integer, got: '{age_str}'")
        else:
            age = int(age_str)
            if age == 0:
                warnings.append("max-age=0 effectively disables HSTS")
            elif age < 86400:
                warnings.append(f"max-age={age} is very short (< 1 day)")
            elif age < 2592000:
                warnings.append(f"max-age={age} is less than 30 days — consider ≥ 31536000")
            else:
                info.append(f"max-age={age} ({age//86400} days) ✓")

    if "includesubdomains" not in directives:
        warnings.append("'includeSubDomains' not set — subdomains may still be reached over HTTP")
    if "preload" in directives and "includesubdomains" not in directives:
        issues.append("'preload' requires 'includeSubDomains'")
    if "preload" not in directives:
        info.append("Consider adding 'preload' and submitting to the HSTS preload list")

    return issues, warnings, info


def validate_csp(value: str):
    issues, warnings, info = [], [], []
    meta = SECURITY_HEADERS["Content-Security-Policy"]["directives"]
    valid_directives   = meta["valid"]
    unsafe_values      = meta["unsafe_values"]
    deprecated_dirs    = meta["deprecated"]

    # Split on ';', each part is a directive
    raw_parts = [p.strip() for p in value.split(";") if p.strip()]
    seen_dirs = set()

    for part in raw_parts:
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        sources   = [t.lower() for t in tokens[1:]]

        if directive in deprecated_dirs:
            warnings.append(f"'{directive}' is deprecated and may be removed from browsers")

        if directive not in valid_directives:
            issues.append(f"Unknown CSP directive: '{directive}'")
            continue

        if directive in seen_dirs:
            issues.append(f"Duplicate directive: '{directive}' — later one is ignored")
        seen_dirs.add(directive)

        for src in sources:
            if src in unsafe_values:
                if src == "'unsafe-inline'":
                    warnings.append(f"'{directive}' uses 'unsafe-inline' — XSS risk; use nonces/hashes")
                elif src == "'unsafe-eval'":
                    warnings.append(f"'{directive}' uses 'unsafe-eval' — allows dynamic code execution")
                elif src == "*":
                    warnings.append(f"'{directive}' uses wildcard '*' — allows any source")
                elif src == "data:":
                    warnings.append(f"'{directive}' allows 'data:' — can enable XSS via data URIs")
                elif src == "http:":
                    warnings.append(f"'{directive}' allows insecure 'http:' — downgrade risk")

            # Check for nonce/hash syntax
            if src.startswith("'nonce-") and not re.match(r"^'nonce-[A-Za-z0-9+/=_-]+'$", src):
                issues.append(f"Malformed nonce in '{directive}': {src}")
            if src.startswith("'sha") and not re.match(r"^'sha(256|384|512)-[A-Za-z0-9+/=]+'$", src):
                issues.append(f"Malformed hash in '{directive}': {src}")

            # Suspicious: allowing all subdomains via wildcard
            if re.match(r"^\*\.[a-z0-9\-]+\.[a-z]{2,}$", src):
                warnings.append(f"'{directive}' allows wildcard subdomain: {src}")

    if "default-src" not in seen_dirs and "script-src" not in seen_dirs:
        warnings.append("No 'default-src' or 'script-src' — scripts can be loaded from anywhere")
    if "object-src" not in seen_dirs:
        if "default-src" in seen_dirs:
            info.append("'object-src' not explicitly set — inherits from default-src")
        else:
            warnings.append("'object-src' not set — plugins (Flash, Java applets) unrestricted")
    if "base-uri" not in seen_dirs:
        warnings.append("'base-uri' not set — allows base tag injection attacks")
    if "frame-ancestors" in seen_dirs and "X-Frame-Options" in seen_dirs:
        info.append("Both 'frame-ancestors' (CSP) and X-Frame-Options are set — CSP takes precedence in modern browsers")

    if not issues and not warnings:
        info.append("CSP looks well-formed")
    return issues, warnings, info


def validate_x_frame_options(value: str):
    issues, warnings, info = [], [], []
    v = value.strip().upper()
    if v == "DENY":
        info.append("DENY — strongest setting, prevents all framing ✓")
    elif v == "SAMEORIGIN":
        info.append("SAMEORIGIN — allows same-origin framing")
    elif v.startswith("ALLOWFROM"):
        issues.append("ALLOWFROM is deprecated and widely unsupported (use CSP frame-ancestors instead)")
    else:
        issues.append(f"Invalid value '{value}' — must be DENY or SAMEORIGIN")
    return issues, warnings, info


def validate_x_content_type(value: str):
    issues, warnings, info = [], [], []
    if value.strip().lower() != "nosniff":
        issues.append(f"Value must be 'nosniff', got: '{value}'")
    else:
        info.append("nosniff ✓")
    return issues, warnings, info


def validate_referrer_policy(value: str):
    issues, warnings, info = [], [], []
    meta = SECURITY_HEADERS["Referrer-Policy"]["directives"]
    vals = [v.strip().lower() for v in value.split(",")]
    for v in vals:
        if v not in meta["valid_values"]:
            issues.append(f"Invalid Referrer-Policy value: '{v}'")
        elif v in meta["weak_values"]:
            warnings.append(f"'{v}' sends full URL to third parties — use 'strict-origin-when-cross-origin'")
        elif v in ("strict-origin-when-cross-origin","no-referrer","same-origin","strict-origin"):
            info.append(f"'{v}' is a secure choice ✓")
    return issues, warnings, info


def validate_permissions_policy(value: str):
    issues, warnings, info = [], [], []
    known = SECURITY_HEADERS["Permissions-Policy"]["directives"]["known_features"]
    parts = [p.strip() for p in value.split(",") if p.strip()]
    seen = set()
    for part in parts:
        m = re.match(r'^([a-z0-9\-]+)\s*=\s*(.+)$', part.strip())
        if not m:
            issues.append(f"Malformed directive: '{part}' — expected 'feature=allowlist'")
            continue
        feature, allowlist = m.group(1), m.group(2).strip()
        if feature in seen:
            warnings.append(f"Duplicate feature: '{feature}'")
        seen.add(feature)
        if feature not in known:
            warnings.append(f"Unknown feature policy: '{feature}' — may be experimental/future")
        # Validate allowlist syntax
        if allowlist not in ("()", "*", "self") and not re.match(r'^\(.*\)$', allowlist):
            issues.append(f"'{feature}' allowlist should be (), *, self, or a parenthesized list")
        if allowlist == "*":
            warnings.append(f"'{feature}=*' grants access to all origins")
    return issues, warnings, info


def validate_coep(value: str):
    issues, warnings, info = [], [], []
    v = value.strip().lower()
    valid = SECURITY_HEADERS["Cross-Origin-Embedder-Policy"]["directives"]["valid_values"]
    if v not in valid:
        issues.append(f"Invalid value '{value}' — must be one of: {', '.join(valid)}")
    elif v == "require-corp":
        info.append("require-corp — strict; enables SharedArrayBuffer and other isolation features ✓")
    elif v == "credentialless":
        info.append("credentialless — moderate; allows embedding without CORP if credentials stripped")
    elif v == "unsafe-none":
        warnings.append("unsafe-none is the default — no cross-origin isolation")
    return issues, warnings, info


def validate_coop(value: str):
    issues, warnings, info = [], [], []
    v = value.strip().lower()
    valid = SECURITY_HEADERS["Cross-Origin-Opener-Policy"]["directives"]["valid_values"]
    if v not in valid:
        issues.append(f"Invalid value '{value}' — must be one of: {', '.join(valid)}")
    elif v == "same-origin":
        info.append("same-origin — full isolation ✓")
    elif v == "same-origin-allow-popups":
        warnings.append("same-origin-allow-popups allows popups to break isolation")
    elif v == "unsafe-none":
        warnings.append("unsafe-none is the default — no opener isolation")
    return issues, warnings, info


def validate_corp(value: str):
    issues, warnings, info = [], [], []
    v = value.strip().lower()
    valid = SECURITY_HEADERS["Cross-Origin-Resource-Policy"]["directives"]["valid_values"]
    if v not in valid:
        issues.append(f"Invalid value '{value}' — must be one of: {', '.join(valid)}")
    elif v == "same-origin":
        info.append("same-origin — most restrictive ✓")
    elif v == "cross-origin":
        warnings.append("cross-origin — allows any origin to read this resource (Spectre risk)")
    return issues, warnings, info


def validate_cache_control(value: str):
    issues, warnings, info = [], [], []
    meta = SECURITY_HEADERS["Cache-Control"]["directives"]
    no_value_dirs = {"no-store","no-cache","no-transform","must-revalidate",
                     "proxy-revalidate","private","public","only-if-cached",
                     "immutable","upgrade-insecure-requests"}
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    seen = set()
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k in no_value_dirs:
                issues.append(f"'{k}' must not have a value (got '={v}')")
            elif k not in meta["valid"]:
                warnings.append(f"Non-standard directive: '{k}'")
            else:
                if k in ("max-age","s-maxage","stale-while-revalidate","stale-if-error"):
                    if not v.isdigit():
                        issues.append(f"'{k}' must be an integer, got: '{v}'")
        else:
            if part not in meta["valid"]:
                warnings.append(f"Non-standard directive: '{part}'")
        if part.split("=")[0] in seen:
            warnings.append(f"Duplicate Cache-Control directive: '{part.split('=')[0]}'")
        seen.add(part.split("=")[0])
    return issues, warnings, info


def validate_xxss(value: str):
    issues, warnings, info = [], [], []
    v = value.strip()
    if v == "0":
        info.append("'0' — disabled; correct modern practice (rely on CSP) ✓")
    elif v == "1":
        warnings.append("'1' enables XSS filter in reflection mode only — set 'mode=block' or just use 0")
    elif v.lower() == "1; mode=block":
        warnings.append("'1; mode=block' — still enabled; modern guidance is to disable with 0 and use CSP")
    elif v.lower().startswith("1; report="):
        warnings.append("Report mode for X-XSS-Protection is non-standard")
    else:
        issues.append(f"Invalid X-XSS-Protection value: '{v}'")
    return issues, warnings, info


HEADER_VALIDATORS = {
    "strict-transport-security":   validate_hsts,
    "content-security-policy":     validate_csp,
    "x-frame-options":             validate_x_frame_options,
    "x-content-type-options":      validate_x_content_type,
    "referrer-policy":             validate_referrer_policy,
    "permissions-policy":          validate_permissions_policy,
    "cross-origin-embedder-policy": validate_coep,
    "cross-origin-opener-policy":  validate_coop,
    "cross-origin-resource-policy": validate_corp,
    "cache-control":               validate_cache_control,
    "x-xss-protection":            validate_xxss,
}

# HTTP PROBING 

# Realistic browser fingerprints with full header sets
PROBE_PROFILES = [
    {
        "label": "Chrome/Windows",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Cache-Control": "max-age=0",
            "DNT": "1",
        }
    },
    {
        "label": "Firefox/Linux",
        "headers": {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "TE": "trailers",
        }
    },
    {
        "label": "Safari/macOS",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
    },
    {
        "label": "curl/8.x",
        "headers": {
            "User-Agent": "curl/8.7.1",
            "Accept": "*/*",
        }
    },
    {
        "label": "Googlebot",
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
        }
    },
]

HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"]


def resolve_dns(hostname):
    """Resolve A and AAAA records for a hostname."""
    results = {"ipv4": [], "ipv6": [], "cname": None}
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            addr = info[4][0]
            if ":" in addr:
                if addr not in results["ipv6"]:
                    results["ipv6"].append(addr)
            else:
                if addr not in results["ipv4"]:
                    results["ipv4"].append(addr)
    except Exception:
        pass
    return results


def probe_ssl(hostname, port=443):
    """Inspect TLS certificate details."""
    info = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(8)
            s.connect((hostname, port))
            cert = s.getpeercert()
            info["subject"]    = dict(x[0] for x in cert.get("subject", []))
            info["issuer"]     = dict(x[0] for x in cert.get("issuer", []))
            info["notBefore"]  = cert.get("notBefore")
            info["notAfter"]   = cert.get("notAfter")
            info["version"]    = cert.get("version")
            info["serialNumber"] = cert.get("serialNumber")
            san = cert.get("subjectAltName", [])
            info["san"]        = [v for _, v in san]
            info["protocol"]   = s.version()
            info["cipher"]     = s.cipher()
            # Check expiry
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            delta = exp - datetime.now(tz=timezone.utc)
            info["days_until_expiry"] = delta.days
    except ssl.SSLError as e:
        info["error"] = f"SSL error: {e}"
    except Exception as e:
        info["error"] = str(e)
    return info


def measure_timing(session, url, method="GET", req_headers=None, verify=True, timeout=10):
    """Measure connection + TTFB timing like curl -w."""
    t0 = time.perf_counter()
    try:
        resp = session.request(
            method, url, headers=req_headers or {},
            verify=verify, timeout=timeout, allow_redirects=False, stream=True
        )
        ttfb = time.perf_counter() - t0
        resp.content  # drain
        total = time.perf_counter() - t0
        return {
            "status": resp.status_code,
            "ttfb_ms": round(ttfb * 1000, 1),
            "total_ms": round(total * 1000, 1),
            "size_bytes": len(resp.content),
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {"error": str(e), "ttfb_ms": None}


def probe_http_methods(base_url, verify=True, timeout=10):
    """Test which HTTP methods the server accepts — like curl -X METHOD."""
    session = requests.Session()
    results = {}
    parsed = urlparse(base_url)
    probe_url = f"{parsed.scheme}://{parsed.netloc}/"
    for method in HTTP_METHODS:
        try:
            resp = session.request(
                method, probe_url,
                headers={"User-Agent": "HeaderProbe/2.0"},
                verify=verify, timeout=timeout,
                allow_redirects=False
            )
            results[method] = {
                "status": resp.status_code,
                "allow": resp.headers.get("Allow", ""),
                "dangerous": method in ("TRACE","PUT","DELETE","PATCH") and resp.status_code < 400
            }
        except Exception as e:
            results[method] = {"error": str(e)}
    return results


def fetch_headers(url, args):
    """
    Main fetching engine. Tries multiple strategies and UA profiles.
    Collects cookies from full redirect chain.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.strip("/")

    result = {
        "url": url, "domain": domain,
        "headers": {}, "all_set_cookie": [],
        "jar_cookies": [], "strategy_used": "",
        "error": None, "redirects": [],
        "status_code": None, "final_url": url,
        "response_time_ms": None,
        "http2": False,
    }

    strategies = []
    if not domain.startswith("www."):
        strategies += [
            {"label": "HTTPS direct",           "url": f"https://{domain}",     "verify": True,  "timeout": args.timeout},
            {"label": "HTTPS (no SSL verify)",  "url": f"https://{domain}",     "verify": False, "timeout": args.timeout},
            {"label": "HTTP fallback",           "url": f"http://{domain}",      "verify": False, "timeout": args.timeout},
            {"label": "HTTPS with www",          "url": f"https://www.{domain}", "verify": False, "timeout": args.timeout},
        ]
    else:
        strategies += [
            {"label": "HTTPS direct",          "url": f"https://{domain}",      "verify": True,  "timeout": args.timeout},
            {"label": "HTTPS (no SSL verify)", "url": f"https://{domain}",      "verify": False, "timeout": args.timeout},
            {"label": "HTTP fallback",          "url": f"http://{domain}",       "verify": False, "timeout": args.timeout},
        ]

    for strategy in strategies:
        for profile in PROBE_PROFILES[:2]:  # Use first 2 profiles by default
            try:
                session = requests.Session()
                session.max_redirects = 15

                t0 = time.perf_counter()
                resp = session.get(
                    strategy["url"],
                    headers=profile["headers"],
                    verify=strategy["verify"],
                    timeout=strategy["timeout"],
                    allow_redirects=True
                )
                elapsed = round((time.perf_counter() - t0) * 1000, 1)

                if resp.history:
                    result["redirects"] = [r.url for r in resp.history]

                all_set_cookie = []
                for step in list(resp.history) + [resp]:
                    for k, v in step.headers.items():
                        if k.lower() == "set-cookie":
                            all_set_cookie.append(v)

                jar_cookies = []
                for cookie in session.cookies:
                    httponly = (
                        cookie.has_nonstandard_attr("HttpOnly") or
                        cookie.has_nonstandard_attr("httponly") or
                        any(k.lower() == "httponly" for k in cookie._rest)
                    )
                    samesite = (cookie._rest.get("SameSite") or
                                cookie._rest.get("samesite") or "Not set")
                    jar_cookies.append({
                        "name": cookie.name, "secure": cookie.secure,
                        "httponly": httponly, "samesite": samesite,
                        "domain": cookie.domain,
                    })

                result.update({
                    "headers": dict(resp.headers),
                    "all_set_cookie": all_set_cookie,
                    "jar_cookies": jar_cookies,
                    "status_code": resp.status_code,
                    "strategy_used": f"{strategy['label']} | {profile['label']}",
                    "final_url": resp.url,
                    "response_time_ms": elapsed,
                    "http2": resp.raw.version == 20 if hasattr(resp.raw, "version") else False,
                })
                return result

            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout):
                continue
            except Exception:
                continue

    result["error"] = "Could not reach host after exhausting all probe strategies."
    return result


# ANALYSIS

def analyse_headers(raw_headers):
    """
    For each security header: detect presence, run directive-level
    validation, flag missing headers, flag information-leaking headers.
    """
    normalized = {k.lower(): (k, v) for k, v in raw_headers.items()}
    found, missing, leaking, deprecated = {}, {}, {}, {}

    for header, meta in SECURITY_HEADERS.items():
        key = header.lower()
        if key in normalized:
            _, value = normalized[key]
            issues, warnings, info = [], [], []

            if meta.get("deprecated"):
                deprecated[header] = {"value": value, **meta}
                continue

            validator = HEADER_VALIDATORS.get(key)
            if validator:
                issues, warnings, info = validator(value)

            found[header] = {
                **meta,
                "value": value,
                "directive_issues": issues,
                "directive_warnings": warnings,
                "directive_info": info,
            }
        else:
            if not meta.get("deprecated"):
                missing[header] = meta

    for header, reason in LEAK_HEADERS.items():
        if header.lower() in normalized:
            _, value = normalized[header.lower()]
            leaking[header] = {"value": value, "reason": reason}

    # Check for report-only equivalents when main header is missing
    report_only_hints = {}
    for header, meta in SECURITY_HEADERS.items():
        ro = meta.get("directives", {}).get("report_only_equivalent")
        if ro and ro.lower() in normalized and header not in found:
            _, ro_value = normalized[ro.lower()]
            report_only_hints[header] = {"report_only_header": ro, "value": ro_value}

    return found, missing, leaking, deprecated, report_only_hints


def analyse_cookies(all_set_cookie, jar_cookies):
    cookie_results = []
    seen = set()

    for raw in all_set_cookie:
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            parts       = [p.strip() for p in line.split(";")]
            name_val    = parts[0]
            name        = name_val.split("=")[0].strip() if "=" in name_val else name_val
            directives  = {p.split("=")[0].strip().lower(): (p.split("=",1)[1].strip() if "=" in p else True)
                           for p in parts[1:]}
            has_secure   = "secure"   in directives
            has_httponly = "httponly" in directives
            samesite_raw = directives.get("samesite")
            samesite     = str(samesite_raw).capitalize() if samesite_raw and samesite_raw is not True else \
                           ("None" if samesite_raw is True else "Not set")

            # Check for unknown cookie directives
            known_dirs = {"secure","httponly","samesite","path","domain","expires",
                          "max-age","partitioned","priority"}
            unknown    = [d for d in directives if d not in known_dirs]

            issues = []
            if not has_secure:
                issues.append("Missing Secure — cookie transmitted over HTTP")
            if not has_httponly:
                issues.append("Missing HttpOnly — readable via JavaScript (XSS risk)")
            if samesite == "Not set":
                issues.append("Missing SameSite — defaults to Lax in modern browsers; set explicitly")
            elif samesite.lower() == "none" and not has_secure:
                issues.append("SameSite=None requires the Secure flag")
            elif samesite.lower() == "none":
                issues.append("SameSite=None — cookie sent on all cross-site requests (CSRF risk)")
            for u in unknown:
                issues.append(f"Unknown cookie directive: '{u}'")

            seen.add(name)
            cookie_results.append({
                "name": name, "secure": has_secure,
                "httponly": has_httponly, "samesite": samesite,
                "issues": issues, "source": "Set-Cookie header"
            })

    for ck in jar_cookies:
        if ck["name"] in seen:
            continue
        seen.add(ck["name"])
        issues = []
        if not ck["secure"]:
            issues.append("Missing Secure — cookie transmitted over HTTP")
        if not ck["httponly"]:
            issues.append("Missing HttpOnly — readable via JavaScript (XSS risk)")
        if ck["samesite"] == "Not set":
            issues.append("Missing SameSite attribute")
        cookie_results.append({
            "name": ck["name"], "secure": ck["secure"],
            "httponly": ck["httponly"], "samesite": ck["samesite"],
            "issues": issues, "source": f"Cookie jar ({ck['domain']})"
        })
    return cookie_results


def calculate_score(found, missing, leaking, deprecated, directive_issues_total):
    weights    = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    sec_subset = {k: v for k, v in SECURITY_HEADERS.items() if not v.get("deprecated")}
    total      = sum(weights[m["severity"]] for m in sec_subset.values())
    earned     = sum(weights[m["severity"]] for m in found.values())
    penalty    = len(leaking) * 5 + directive_issues_total * 3 + len(deprecated) * 2
    score      = max(0, int((earned / total) * 100) - penalty)
    if   score >= 90: grade, col = "A+", C.GREEN
    elif score >= 80: grade, col = "A",  C.GREEN
    elif score >= 70: grade, col = "B+", C.CYAN
    elif score >= 60: grade, col = "B",  C.CYAN
    elif score >= 50: grade, col = "C",  C.AMBER
    elif score >= 40: grade, col = "D",  C.AMBER
    else:             grade, col = "F",  C.RED
    return score, grade, col


# OUTPUT / REPORT

W = 72

def sep(ch="─"): print(dim(ch * W))
def section(title): print(f"\n{bold(title)}")

def severity_color(sev):
    return {"HIGH": red, "MEDIUM": amber, "LOW": cyan}.get(sev, dim)

def yn(val):
    return green("Yes") if val else red("No")


def print_banner():
    banner = r"""
  ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗
  ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝
  ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗
  ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
  P  R  O  B  E"""
    print(magenta(bold(banner)))
    print(f"\n  {amber('Security Header & HTTP Analysis Tool')}")


def print_report(result, found, missing, leaking, deprecated, ro_hints,
                 score, grade, score_color, cookies, ssl_info, dns_info,
                 method_probe, args):

    print(bold("Analysis Results").center(W + 10))

    # Meta
    def field(label, value):
        print(f"  {bold(label):<22}{value}")

    field("Target:",       result["domain"])
    field("Final URL:",    result.get("final_url", result["url"]))
    field("HTTP Status:",  result.get("status_code", "N/A"))
    field("Strategy:",     result.get("strategy_used", "N/A"))
    field("Response Time:",f"{result.get('response_time_ms','?')} ms")
    field("Scanned:",      datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))

    if result["redirects"]:
        chain = " → ".join(result["redirects"])
        field("Redirects:", chain if len(chain) < 55 else chain[:52]+"…")

    sep()

    # Score
    sc = score_color
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"\n  {bold('Security Score:')}  ", end="")
    print((green if score >= 70 else amber if score >= 50 else red)(f"{score}/100  Grade: {grade}"))
    print(f"  [{(green if score >= 70 else amber if score >= 50 else red)(bar)}]")

    # Directive issue count for summary
    total_directive_issues = sum(len(v["directive_issues"]) for v in found.values())
    total_directive_warns  = sum(len(v["directive_warnings"]) for v in found.values())
    print(f"\n  {green(f'✓ {len(found)} headers present')}   "
          f"{red(f'✗ {len(missing)} missing')}   "
          f"{amber(f'⚠ {len(leaking)} leaking info')}   "
          f"{red(f'{total_directive_issues} directive errors')}   "
          f"{amber(f'{total_directive_warns} directive warnings')}")
    sep()

    #  DNS 
    if dns_info:
        section(f"  {cyan('DNS RESOLUTION')}")
        if dns_info.get("ipv4"):
            print(f"  IPv4  : {', '.join(dns_info['ipv4'])}")
        if dns_info.get("ipv6"):
            print(f"  IPv6  : {', '.join(dns_info['ipv6'])}")
        sep()

    #  TLS/SSL 
    if ssl_info and not ssl_info.get("error"):
        section(f"  {cyan('TLS / SSL CERTIFICATE')}")
        cn  = ssl_info.get("subject", {}).get("commonName", "?")
        org = ssl_info.get("issuer", {}).get("organizationName", "?")
        exp = ssl_info.get("notAfter", "?")
        days = ssl_info.get("days_until_expiry", "?")
        proto = ssl_info.get("protocol", "?")
        cipher_info = ssl_info.get("cipher", ("?", "?", "?"))

        print(f"  Subject       : {cn}")
        print(f"  Issuer        : {org}")
        print(f"  Expires       : {exp}")
        days_colored = green(str(days)) if isinstance(days, int) and days > 30 else \
                       amber(str(days)) if isinstance(days, int) and days > 7 else red(str(days))
        print(f"  Days to Expiry: {days_colored}")
        print(f"  Protocol      : {proto}")
        print(f"  Cipher        : {cipher_info[0]}  ({cipher_info[2]}-bit)")
        sans = ssl_info.get("san", [])
        if sans:
            print(f"  SANs ({len(sans)})      : {', '.join(sans[:6])}" +
                  (f" … +{len(sans)-6} more" if len(sans) > 6 else ""))
        sep()
    elif ssl_info and ssl_info.get("error"):
        section(f"  {red('TLS ERROR')}")
        print(f"  {red(ssl_info['error'])}")
        sep()

    #  PRESENT HEADERS 
    section(f"  {green(bold(f'PRESENT SECURITY HEADERS  ({len(found)})'))}")
    if found:
        for h, meta in found.items():
            sc_fn  = severity_color(meta["severity"])
            prefix = green("✓") if not meta["directive_issues"] else red("✗")
            print(f"\n  {prefix} {bold(green(h))}")
            print(f"    {'Value':<18}: {dim(meta['value'][:90] + ('…' if len(meta['value'])>90 else ''))}")
            print(f"    {'Severity':<18}: {sc_fn(meta['severity'])}")

            if meta["directive_issues"]:
                for issue in meta["directive_issues"]:
                    print(f"    {red('✗')} {red('INVALID')}: {issue}")
            if meta["directive_warnings"]:
                for warn in meta["directive_warnings"]:
                    print(f"    {amber('⚠')} {amber('WARN')}: {warn}")
            if meta["directive_info"] and args.verbose:
                for info_line in meta["directive_info"]:
                    print(f"    {cyan('ℹ')} {dim(info_line)}")
    else:
        print(f"  {red('No security headers found.')}")
    sep()

    #  MISSING HEADERS 
    section(f"  {red(bold(f'MISSING SECURITY HEADERS  ({len(missing)})'))}")
    if missing:
        for h, meta in missing.items():
            sc_fn = severity_color(meta["severity"])
            print(f"\n  {red('✗')} {bold(red(h))}")
            print(f"    {'Severity':<18}: {sc_fn(meta['severity'])}")
            print(f"    {'Description':<18}: {meta['description']}")
            print(f"    {'Recommendation':<18}: {dim(meta['recommendation'])}")
            if h in ro_hints:
                hint = ro_hints[h]
                print(f"    {amber('ℹ')} Report-Only variant found: {hint['report_only_header']}")
                print(f"      {dim(hint['value'][:80])}")
    else:
        print(f"  {green('None missing — well configured!')}")
    sep()

    #  DEPRECATED HEADERS 
    if deprecated:
        section(f"  {amber(bold(f'DEPRECATED HEADERS  ({len(deprecated)})'))}")
        for h, meta in deprecated.items():
            print(f"\n  {amber('⚠')} {bold(amber(h))}")
            print(f"    Value: {dim(meta['value'][:90])}")
            print(f"    {dim(meta.get('recommendation','Remove this header'))}")
        sep()

    #  INFORMATION LEAKAGE 
    section(f"  {amber(bold(f'INFORMATION LEAKAGE  ({len(leaking)})'))}")
    if leaking:
        for h, meta in leaking.items():
            print(f"\n  {amber('!')} {bold(amber(h))}")
            print(f"    Value : {dim(meta['value'][:80])}")
            print(f"    Risk  : {meta['reason']}")
    else:
        print(f"  {green('No sensitive headers exposed.')}")
    sep()

    #  COOKIE SECURITY 
    section(f"  {blue(bold(f'COOKIE SECURITY ANALYSIS  ({len(cookies)})'))}")
    if cookies:
        for ck in cookies:
            ok = not ck["issues"]
            prefix = green("✓") if ok else red("✗")
            print(f"\n  {prefix} {bold(green(ck['name']) if ok else red(ck['name']))}")
            print(f"    Source   : {dim(ck['source'])}")
            print(f"    Secure   : {yn(ck['secure'])}")
            print(f"    HttpOnly : {yn(ck['httponly'])}")
            ss = ck["samesite"]
            ss_colored = (green(ss) if ss.lower() in ("strict","lax") else
                          amber(ss) if ss.lower() == "none" else red(ss))
            print(f"    SameSite : {ss_colored}")
            for issue in ck["issues"]:
                print(f"    {amber('⚠')} {issue}")
            if ok:
                print(f"    {green('All security flags correctly set ✓')}")
    else:
        print(f"  {cyan('No cookies found in HTTP response.')}")
        print(f"  {dim('Note: JS-set cookies are invisible at the HTTP level.')}")
    sep()

    #  HTTP METHOD PROBE 
    if method_probe:
        section(f"  {cyan(bold('HTTP METHOD PROBE  (curl-equivalent)'))}")
        for method, data in method_probe.items():
            if "error" in data:
                print(f"  {dim(method):<10} {dim('error: ' + data['error'][:40])}")
                continue
            status = data["status"]
            danger = data.get("dangerous", False)
            status_color = (red if danger or status < 300 else
                            amber if status < 400 else dim)
            danger_tag = f" {red('[DANGEROUS — should be blocked]')}" if danger else ""
            print(f"  {bold(method):<10} {status_color(str(status))}{danger_tag}")
            if data.get("allow"):
                print(f"  {'':10} Allow: {dim(data['allow'])}")
        sep()

    #  ALL RAW RESPONSE HEADERS
    if args.show_all_headers:
        section(f"  {blue(bold('ALL RESPONSE HEADERS'))}")
        for k, v in result["headers"].items():
            print(f"  {cyan(k)}: {dim(v)}")
        sep()

    #  FOOTER
    print(f"\n  {dim('HeaderProbe v2.0 — https://github.com/zahidec0de/HeaderProbe')}")
    print(magenta("═" * W))
    print()


def print_json_report(result, found, missing, leaking, deprecated, ro_hints,
                      score, grade, cookies, ssl_info, dns_info, method_probe):
    report = {
        "meta": {
            "target": result["domain"],
            "final_url": result.get("final_url"),
            "status_code": result.get("status_code"),
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "response_time_ms": result.get("response_time_ms"),
            "strategy_used": result.get("strategy_used"),
            "redirects": result.get("redirects", []),
        },
        "score": {"value": score, "grade": grade},
        "dns": dns_info,
        "ssl": ssl_info,
        "headers": {
            "present": {
                h: {
                    "value": v["value"],
                    "severity": v["severity"],
                    "directive_issues": v["directive_issues"],
                    "directive_warnings": v["directive_warnings"],
                }
                for h, v in found.items()
            },
            "missing": {h: {"severity": v["severity"], "recommendation": v["recommendation"]}
                        for h, v in missing.items()},
            "leaking": leaking,
            "deprecated": {h: {"value": v["value"]} for h, v in deprecated.items()},
            "report_only_hints": ro_hints,
        },
        "cookies": cookies,
        "http_methods": method_probe,
    }
    print(json.dumps(report, indent=2))


# MULTI-TARGET COMPARISON MODE

def compare_targets(targets, args):
    """Scan multiple targets in parallel and print a side-by-side summary."""
    print(f"\n  {cyan(bold(f'Scanning {len(targets)} targets in parallel…'))}\n")
    scores = {}
    all_results = {}

    def scan_one(target):
        result = fetch_headers(target, args)
        if result["error"]:
            return target, None
        found, missing, leaking, deprecated, ro_hints = analyse_headers(result["headers"])
        cookies = analyse_cookies(result["all_set_cookie"], result["jar_cookies"])
        di = sum(len(v["directive_issues"]) for v in found.values())
        score, grade, _ = calculate_score(found, missing, leaking, deprecated, di)
        return target, {"score": score, "grade": grade, "found": len(found),
                        "missing": len(missing), "leaking": len(leaking),
                        "directive_issues": di}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(targets), 10)) as pool:
        futures = {pool.submit(scan_one, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            target, data = future.result()
            all_results[target] = data

    print(magenta("═" * W))
    print(bold(f"  {'Domain':<35} {'Score':>6} {'Grade':>6} {'Present':>8} {'Missing':>8} {'Leaking':>8} {'Dir.Err':>8}"))
    sep()
    for t in targets:
        d = all_results.get(t)
        if not d:
            print(f"  {t:<35} {red('ERROR')}")
            continue
        score_fn = green if d["score"] >= 70 else amber if d["score"] >= 50 else red
        print(f"  {t:<35} {score_fn(str(d['score'])):>15} {d['grade']:>6} "
              f"{d['found']:>8} {d['missing']:>8} {d['leaking']:>8} {d['directive_issues']:>8}")
    print(magenta("═" * W))
    print()


# CLI

def parse_args():
    p = argparse.ArgumentParser(
        prog="headerprobe",
        description="Enterprise HTTP Security Header Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  headerprobe example.com
  headerprobe https://example.com --verbose --methods
  headerprobe example.com --ssl --dns
  headerprobe --compare a.com b.com c.com
  headerprobe example.com --json > report.json
  headerprobe example.com --show-all-headers
  headerprobe example.com --timeout 20 --methods --ssl --dns --verbose
        """
    )
    p.add_argument("target",            nargs="?",       help="Domain or URL to scan")
    p.add_argument("--compare",         nargs="+",       metavar="TARGET",
                   help="Compare multiple targets side by side")
    p.add_argument("--json",            action="store_true",
                   help="Output full report as JSON")
    p.add_argument("--verbose", "-v",   action="store_true",
                   help="Show additional info-level notes on directives")
    p.add_argument("--methods", "-m",   action="store_true",
                   help="Probe which HTTP methods the server accepts")
    p.add_argument("--ssl", "-s",       action="store_true",
                   help="Inspect TLS certificate details")
    p.add_argument("--dns", "-d",       action="store_true",
                   help="Perform DNS resolution (A/AAAA records)")
    p.add_argument("--show-all-headers",action="store_true",
                   help="Print all raw response headers at the end")
    p.add_argument("--timeout", "-t",   type=int, default=12, metavar="SECONDS",
                   help="Request timeout in seconds (default: 12)")
    p.add_argument("--no-color",        action="store_true",
                   help="Disable ANSI color output")
    return p


def main():
    parser = parse_args()
    args   = parser.parse_args()

    global NO_COLOR
    if args.no_color or not sys.stdout.isatty():
        NO_COLOR = True

    if not args.json:
        print_banner()

    #  Compare mode 
    if args.compare:
        compare_targets(args.compare, args)
        return

    #  Single target 
    target = args.target
    if not target:
        try:
            target = input(f"  {cyan('Enter domain or URL to scan')}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
    if not target:
        print(red("  No target provided. Exiting."))
        sys.exit(1)

    if not args.json:
        print(f"  {cyan('Probing:')} {bold(target)}")
        print(f"  {dim('Trying multiple methods and UA profiles…')}\n")

    result = fetch_headers(target, args)

    if result["error"]:
        print(red(f"\n  Error: {result['error']}\n"))
        sys.exit(1)

    parsed = urlparse(result.get("final_url", target))
    hostname = parsed.hostname or result["domain"]

    # Optional probes (run in parallel if multiple requested)
    dns_info    = resolve_dns(hostname)    if args.dns     else {}
    ssl_info    = probe_ssl(hostname)      if args.ssl     else {}
    method_probe= probe_http_methods(result["final_url"], timeout=args.timeout) \
                                           if args.methods else {}

    found, missing, leaking, deprecated, ro_hints = analyse_headers(result["headers"])
    cookies = analyse_cookies(result["all_set_cookie"], result["jar_cookies"])
    directive_issues_total = sum(len(v["directive_issues"]) for v in found.values())
    score, grade, score_color = calculate_score(found, missing, leaking, deprecated,
                                                directive_issues_total)

    if args.json:
        print_json_report(result, found, missing, leaking, deprecated, ro_hints,
                          score, grade, cookies, ssl_info, dns_info, method_probe)
    else:
        print_report(result, found, missing, leaking, deprecated, ro_hints,
                     score, grade, score_color, cookies, ssl_info, dns_info,
                     method_probe, args)


if __name__ == "__main__":
    main()
