# HeaderProbe

A Python script that analyzes HTTP security headers and cookie security flags on domains you own or have permission to test. Useful for researchers and developers to quickly assess how well a site protects its visitors.

## What it does

- Checks for missing and misconfigured security headers
- Analyzes cookies for Secure, HttpOnly, and SameSite flags
- Collects cookies from the full redirect chain, not just the final response
- Detects information leakage headers (Server, X-Powered-By, etc.)
- Gives a security score out of 100 with a grade (A to D)
- Tries multiple connection strategies automatically to handle SSL and redirect issues
- Shows all raw response headers

## Requirements

```bash
pip install requests
```

## Usage

```bash
python3 headerprobe.py example.com
```

Or run without arguments and enter the domain when prompted:

```bash
python3 headerprobe.py
```

## Headers checked

Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cache-Control, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy

## Cookie flags checked

Secure, HttpOnly, SameSite

## Note on cookie detection

HeaderProbe checks cookies at the HTTP level, including those set across redirect chains. Cookies injected by JavaScript after the page loads (such as those from Google or Cloudflare scripts) are not visible at the HTTP level and cannot be detected by any HTTP-based tool.

## Ethical use

Only use HeaderProbe on domains you own or have explicit permission to test. This tool is intended for security researchers and developers auditing their own systems.