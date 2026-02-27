#!/usr/bin/env python3

import argparse
import socket
import requests
import dns.resolver
import whois
import ssl
import json
from datetime import datetime

# ---------------------------
# 1. DNS Lookup
# ---------------------------
def dns_lookup(target):
    try:
        result = dns.resolver.resolve(target, 'A')
        return [ip.to_text() for ip in result]
    except:
        return []

# ---------------------------
# 2. IP Resolve
# ---------------------------
def get_ip(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

# ---------------------------
# 3. WHOIS
# ---------------------------
def get_whois(target):
    try:
        data = whois.whois(target)
        return str(data.creation_date)
    except:
        return "Unknown"

# ---------------------------
# 4. HTTP Headers
# ---------------------------
def get_headers(target):
    try:
        r = requests.get(f"http://{target}", timeout=5)
        return dict(r.headers)
    except:
        return {}

# ---------------------------
# 5. HTTPS Check
# ---------------------------
def https_check(target):
    try:
        r = requests.get(f"https://{target}", timeout=5)
        return r.status_code
    except:
        return "No HTTPS"

# ---------------------------
# 6. SSL Info
# ---------------------------
def ssl_info(target):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.connect((target, 443))
            cert = s.getpeercert()
            return cert['issuer']
    except:
        return "No SSL"

# ---------------------------
# 7. Open Ports (basic)
# ---------------------------
def scan_ports(target):
    open_ports = []
    for port in [21, 22, 80, 443, 8080]:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

# ---------------------------
# 8. Server Info
# ---------------------------
def server_info(headers):
    return headers.get("Server", "Unknown")

# ---------------------------
# 9. Content Length
# ---------------------------
def content_length(target):
    try:
        r = requests.get(f"http://{target}", timeout=5)
        return len(r.text)
    except:
        return 0

# ---------------------------
# 10. Redirect Check
# ---------------------------
def check_redirect(target):
    try:
        r = requests.get(f"http://{target}", allow_redirects=False)
        return r.status_code in [301, 302]
    except:
        return False

# ---------------------------
# 11. Cookies
# ---------------------------
def get_cookies(target):
    try:
        r = requests.get(f"http://{target}")
        return r.cookies.get_dict()
    except:
        return {}

# ---------------------------
# 12. Robots.txt
# ---------------------------
def robots_txt(target):
    try:
        r = requests.get(f"http://{target}/robots.txt")
        return r.text[:200]
    except:
        return "Not Found"

# ---------------------------
# 13. Sitemap
# ---------------------------
def sitemap(target):
    try:
        r = requests.get(f"http://{target}/sitemap.xml")
        return r.status_code
    except:
        return "Not Found"

# ---------------------------
# 14. Basic Security Headers
# ---------------------------
def security_headers(headers):
    sec = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]
    return {h: headers.get(h, "Missing") for h in sec}

# ---------------------------
# 15. Simple Tech Detection
# ---------------------------
def tech_detect(headers):
    return headers.get("X-Powered-By", "Unknown")

# ---------------------------
# MAIN
# ---------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Target domain")
    args = parser.parse_args()

    target = args.target

    print(f"\n[+] Scanning: {target}\n")

    headers = get_headers(target)

    results = {
        "IP": get_ip(target),
        "DNS": dns_lookup(target),
        "WHOIS": get_whois(target),
        "Headers": headers,
        "HTTPS": https_check(target),
        "SSL": ssl_info(target),
        "Open Ports": scan_ports(target),
        "Server": server_info(headers),
        "Content Length": content_length(target),
        "Redirect": check_redirect(target),
        "Cookies": get_cookies(target),
        "Robots.txt": robots_txt(target),
        "Sitemap": sitemap(target),
        "Security Headers": security_headers(headers),
        "Technology": tech_detect(headers)
    }

    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
