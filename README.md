# 🛡️ Automated Web Scanner: HTTP Security Headers & CORS Auditor

##  Project Overview
This project is a Python-based automated web security scanner designed to audit web applications for missing HTTP security headers, server information disclosure, and Cross-Origin Resource Sharing (CORS) misconfigurations. It helps security analysts and developers quickly identify web configuration weaknesses and provides actionable remediation advice.

---

## Key Features
1. **HTTP Security Header Audit:** 
   Audits targets for 7 essential security headers and assigns risk severities (`HIGH`, `MEDIUM`, `LOW`, `INFO`):
   - `Strict-Transport-Security` (HSTS)
   - `Content-Security-Policy` (CSP)
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
   - `Permissions-Policy`
   - `X-XSS-Protection`

2. **Information Disclosure Detection:** 
   Identifies response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`) that leak backend server details.

3. **Active CORS Misconfiguration Testing:** 
   Sends crafted `Origin` headers to detect insecure Cross-Origin policies:
   - Arbitrary Origin Reflection
   - Null Origin Trust (`Origin: null`)
   - Prefix & Suffix Domain Bypass
   - Wildcard Origin (`*`) with Credentials

4. **Automated Scoring & JSON Reporting:** 
   Calculates an overall **Header Security Score (out of 100)** and exports structured JSON reports for documentation and compliance tracking.

---

##  Tech Stack & Prerequisites
- **Language:** Python 3.x
- **Libraries Used:** `requests`, `urllib3`, `colorama`, `argparse`, `json`

---

##  Project Structure
```text
automated_web_scanner/
├── scanner.py          # Main Python scanning script
├── requirements.txt    # Required Python dependencies
├── scan_report.json    # Generated JSON security audit report
└── README.md           # Project documentation
```

---

## 🚀 Installation & Usage

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run a Scan
```bash
python scanner.py -u [https://www.youtube.com/](https://www.youtube.com/) -o scan_report.json
```

---

## Sample Scan Output

```text
=================================================================
   🛡️  AUTOMATED WEB SECURITY SCANNER (Headers & CORS Auditor)
=================================================================

[*] Target URL : [https://www.youtube.com/](https://www.youtube.com/)
[*] Scan Time  : 2026-10-23 12:50:41

[*] HTTP Status: 200

[+] 1. Auditing HTTP Security Headers...
  [PASS] Strict-Transport-Security: max-age=31536000
  [PASS] Content-Security-Policy: require-trusted-types-for 'script', base-uri 'self';object-s
  [PASS] X-Frame-Options: SAMEORIGIN
  [PASS] X-Content-Type-Options: nosniff
  [PASS] Permissions-Policy: ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, ch-ua-f
  [PASS] X-XSS-Protection: 0
  [MISS - LOW] Referrer-Policy
         ↳ Add 'Referrer-Policy: strict-origin-when-cross-origin'

[+] 2. Checking Information Disclosure Headers...
  [WARN] Server: ESF (Consider removing/obfuscating)

[+] 3. Testing for CORS Misconfigurations...
  [PASS] No insecure CORS policies detected.

=================================================================
[*] Header Security Score: 85/100 (6/7 headers present)
=================================================================

[✓] Detailed JSON report saved to: scan_report.json
```

---

##  Remediation Summary
| Finding | Severity | Recommended Fix |
| :--- | :--- | :--- |
| Missing `Strict-Transport-Security` | High | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| Missing `Content-Security-Policy` | High | Define a strict CSP policy restricting untrusted script sources |
| Missing `X-Frame-Options` | Medium | Set `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent Clickjacking |
| Missing `X-Content-Type-Options` | Medium | Set `X-Content-Type-Options: nosniff` |
| Missing `Referrer-Policy` | Low | Set `Referrer-Policy: strict-origin-when-cross-origin` |
| Insecure CORS Reflection | Critical / High | Validate Origins against a strict allowlist and avoid reflecting arbitrary Origins with `Access-Control-Allow-Credentials: true` |