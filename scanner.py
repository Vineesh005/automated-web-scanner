import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlparse
import requests
import urllib3
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)
# Suppress SSL warnings if scanning sites with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define expected Security Headers and their purpose
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections and prevents MITM/downgrade attacks (HSTS).",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
        "recommendation": "Implement a strict Content-Security-Policy header restricting script sources."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Protects against Clickjacking attacks by preventing iframe embedding.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-sniffing vulnerabilities.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is included with requests.",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls which browser features and APIs (camera, mic, geolocation) can be used.",
        "recommendation": "Add a Permissions-Policy header disabling unused browser features."
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "description": "Legacy header for browser XSS filters (largely superseded by CSP).",
        "recommendation": "Set 'X-XSS-Protection: 0' (if strong CSP is present) or '1; mode=block'"
    }
}

# Headers that leak server version information
INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def normalize_url(url: str) -> str:
    """Ensure the URL has a valid scheme (http/https)."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def check_security_headers(headers: dict) -> dict:
    """Audit HTTP response headers for missing security headers and info leaks."""
    results = {"present": {}, "missing": {}, "info_leak": {}}
    
    # Case-insensitive dictionary lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in lower_headers:
            results["present"][header] = lower_headers[header.lower()]
        else:
            results["missing"][header] = meta

    for leak_header in INFO_DISCLOSURE_HEADERS:
        if leak_header.lower() in lower_headers:
            results["info_leak"][leak_header] = lower_headers[leak_header.lower()]

    return results


def check_cors_flaws(url: str) -> list:
    """Test target URL with crafted Origin headers to detect CORS misconfigurations."""
    parsed = urlparse(url)
    domain = parsed.netloc
    flaws = []

    test_cases = [
        {
            "name": "Arbitrary Origin Reflection",
            "origin": "https://evil-attacker.com",
            "desc": "Server reflects arbitrary external Origin headers."
        },
        {
            "name": "Null Origin Allowed",
            "origin": "null",
            "desc": "Server trusts 'null' origin (exploitable via sandboxed iframes)."
        },
        {
            "name": "Prefix Origin Bypass",
            "origin": f"https://{domain}.evil-attacker.com",
            "desc": "Server poorly validates domain suffix, allowing attacker subdomains."
        },
        {
            "name": "Suffix Origin Bypass",
            "origin": f"https://evil{domain}",
            "desc": "Server poorly validates domain prefix."
        }
    ]

    for test in test_cases:
        try:
            req_headers = {
                "User-Agent": "Mozilla/5.0 (Security-Audit-Scanner/1.0)",
                "Origin": test["origin"]
            }
            resp = requests.get(url, headers=req_headers, timeout=8, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao:
                # 1. Wildcard check
                if acao == "*":
                    if acac == "true":
                        flaws.append({
                            "type": "Wildcard Origin with Credentials",
                            "severity": "CRITICAL",
                            "origin_sent": test["origin"],
                            "acao_received": acao,
                            "acac_received": acac,
                            "details": "ACAO is '*' alongside Allow-Credentials: true."
                        })
                    else:
                        flaws.append({
                            "type": "Public Wildcard CORS (Access-Control-Allow-Origin: *)",
                            "severity": "LOW",
                            "origin_sent": test["origin"],
                            "acao_received": acao,
                            "acac_received": acac or "false",
                            "details": "Allows any website to read responses (unsafe if endpoint contains private data)."
                        })
                    break  # no need to repeat

                # 2. Reflected Origin check
                elif acao.lower() == test["origin"].lower():
                    severity = "CRITICAL" if acac == "true" else "HIGH"
                    flaws.append({
                        "type": test["name"],
                        "severity": severity,
                        "origin_sent": test["origin"],
                        "acao_received": acao,
                        "acac_received": acac or "false",
                        "details": f"{test['desc']} Credentials allowed: {acac == 'true'}."
                    })

        except requests.RequestException:
            continue

    return flaws


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=" * 65)
    print(Fore.CYAN + Style.BRIGHT + "   🛡️  AUTOMATED WEB SECURITY SCANNER (Headers & CORS Auditor)")
    print(Fore.CYAN + Style.BRIGHT + "=" * 65)


def run_scan(target_url: str, output_file: str = None):
    print_banner()
    url = normalize_url(target_url)
    print(f"\n[*] Target URL : {Fore.YELLOW}{url}")
    print(f"[*] Scan Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Security-Audit-Scanner/1.0)"},
            timeout=10,
            verify=False
        )
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error connecting to {url}: {e}")
        sys.exit(1)

    print(f"[*] HTTP Status: {Fore.GREEN}{response.status_code}")

    # 1. Audit Security Headers
    print(Fore.CYAN + Style.BRIGHT + "\n[+] 1. Auditing HTTP Security Headers...")
    header_results = check_security_headers(response.headers)

    for h, val in header_results["present"].items():
        print(f"  {Fore.GREEN}[PASS]{Style.RESET_ALL} {h}: {Style.DIM}{val[:60]}")

    for h, meta in header_results["missing"].items():
        sev_color = Fore.RED if meta["severity"] == "HIGH" else (Fore.YELLOW if meta["severity"] == "MEDIUM" else Fore.BLUE)
        print(f"  {sev_color}[MISS - {meta['severity']}]{Style.RESET_ALL} {h}")
        print(f"         ↳ {Style.DIM}{meta['recommendation']}")

    # 2. Information Disclosure Headers
    print(Fore.CYAN + Style.BRIGHT + "\n[+] 2. Checking Information Disclosure Headers...")
    if header_results["info_leak"]:
        for h, val in header_results["info_leak"].items():
            print(f"  {Fore.YELLOW}[WARN]{Style.RESET_ALL} {h}: {val} (Consider removing/obfuscating)")
    else:
        print(f"  {Fore.GREEN}[PASS]{Style.RESET_ALL} No obvious server version headers leaked.")

    # 3. Audit CORS Configuration
    print(Fore.CYAN + Style.BRIGHT + "\n[+] 3. Testing for CORS Misconfigurations...")
    cors_flaws = check_cors_flaws(url)

    if cors_flaws:
        for flaw in cors_flaws:
            sev_color = Fore.RED if flaw["severity"] in ["CRITICAL", "HIGH"] else Fore.YELLOW
            print(f"  {sev_color}[VULN - {flaw['severity']}]{Style.RESET_ALL} {flaw['type']}")
            print(f"         ↳ Origin Sent   : {flaw['origin_sent']}")
            print(f"         ↳ ACAO Received : {flaw['acao_received']} (Credentials: {flaw['acac_received']})")
            print(f"         ↳ Details       : {Style.DIM}{flaw['details']}")
    else:
        print(f"  {Fore.GREEN}[PASS]{Style.RESET_ALL} No insecure CORS policies detected.")

    # Calculate Security Score
    total_headers = len(SECURITY_HEADERS)
    present_count = len(header_results["present"])
    score = int((present_count / total_headers) * 100)
    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 65)
    print(f"[*] Header Security Score: {score}/100 ({present_count}/{total_headers} headers present)")
    print(Fore.CYAN + Style.BRIGHT + "=" * 65 + "\n")

    # Save JSON Report if requested
    if output_file:
        report_data = {
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "status_code": response.status_code,
            "security_score": score,
            "security_headers": header_results,
            "cors_findings": cors_flaws
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        print(Fore.GREEN + f"[✓] Detailed JSON report saved to: {output_file}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Web Scanner for Secure Headers and CORS Flaws")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Optional filename to save JSON report (e.g., report.json)")
    args = parser.parse_args()

    run_scan(args.url, args.output)