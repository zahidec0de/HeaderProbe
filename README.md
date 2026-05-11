# HeaderProbe

A Python script that analyzes HTTP security headers on domains you own or have permission to test. Useful for researchers and developers to quickly assess how well a site protects its visitors.

## What it does

- Checks for missing and misconfigured security headers
- Detects information leakage headers.
- Gives a security score out of 100 with a grade (A to D)
- Tries multiple connection methods automatically to handle SSL and redirect issues
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

## Ethical use

Only use HeaderProbe on domains you own or have explicit permission to test. This tool is intended for security researchers and developers auditing their own systems.
