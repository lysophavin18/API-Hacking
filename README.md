# 🔐  API Penetration Testing Framework

Complete automation framework for API security testing, vulnerability detection, and exploitation.

## 🎯 Overview

This framework provides automated penetration testing capabilities covering **10 critical API security categories** mapped to **OWASP Top 10 API**.

### Key Features

- ✅ **10 Attack Categories** - Comprehensive API vulnerability coverage
- ✅ **40+ Integrated Tools** - curl, httpie, ffuf, sqlmap, mitmproxy, and more
- ✅ **Automatic Routing** - Intelligent attack selection based on API type
- ✅ **OWASP Mapping** - Vulnerabilities mapped to OWASP Top 10 API
- ✅ **Workflow Automation** - Pre-built attack workflows
- ✅ **Detailed Reporting** - JSON reports with recommendations

## 🔑 10 API Pentest Categories

| # | Category | Attack Techniques |
|---|----------|-------------------|
| 1 | **Discovery & Enumeration** | Endpoint fuzzing, version detection, Swagger abuse |
| 2 | **Authentication Attacks** | JWT bypass, token tampering, weak secrets |
| 3 | **Authorization (BOLA/BFLA)** | IDOR, privilege escalation, role manipulation |
| 4 | **Injection Attacks** | SQL/NoSQL injection, command injection, XXE |
| 5 | **Business Logic** | Payment bypass, race conditions, workflow abuse |
| 6 | **Mass Assignment** | Hidden field discovery, admin injection, overposting |
| 7 | **Rate Limiting & DoS** | Brute force, resource exhaustion, bypass techniques |
| 8 | **GraphQL Attacks** | Introspection abuse, query complexity DoS, field enum |
| 9 | **File Upload & Deserialization** | Malicious upload, MIME bypass, code execution |
| 10 | **Secrets & Token Abuse** | API key leakage, credential exposure, privilege escalation |

## 📋 Supported API Types

- REST APIs (JSON, XML)
- GraphQL APIs
- SOAP APIs
- Custom APIs

## 🚀 Quick Start

### Installation

```bash
# Clone or navigate to project
cd API-Hacking

# Install Python dependencies
pip3 install -r requirements.txt

# Install system tools (optional, for enhanced testing)
bash install_dependencies.sh

# Verify installation
python3 test_installation.py
```

### Basic Usage

```bash
# Run complete API pentest
python3 api_pentest_orchestrator.py http://api.target.com

# With authentication token
python3 api_pentest_orchestrator.py http://api.target.com --token YOUR_TOKEN

# Custom output directory
python3 api_pentest_orchestrator.py http://api.target.com -o ./my_results

# Verbose output
python3 api_pentest_orchestrator.py http://api.target.com --verbose
```

## 📊 Output

Results include:
- `pentest_results.json` - Full test results
- `pentest_report.json` - Structured vulnerability report
- `pentest_summary.md` - Executive summary

## 🛠️ Tools Integrated

### HTTP & Fuzzing
- curl, httpie, wget
- ffuf, gobuster
- dirbuster

### Database Testing
- sqlmap
- NoSQLMap

### Proxy & Interception
- mitmproxy
- Burp Suite

### API Testing
- Postman
- GraphQL tools

### Load Testing
- Apache Bench
- locust

### Token Analysis
- jwt-tool
- PyJWT

## 📚 Architecture

```
modules/              # 10 attack category modules
  ├── discovery_enumeration.py
  ├── authentication_attacks.py
  ├── authorization_attacks.py
  ├── injection_attacks.py
  ├── business_logic_attacks.py
  ├── mass_assignment.py
  ├── rate_limiting_dos.py
  ├── graphql_attacks.py
  ├── file_upload_deserialization.py
  ├── secrets_token_abuse.py
  └── __init__.py

utils/                # Utilities
  └── request_builder.py  # HTTP requests, payload generation

workflows/            # Attack workflows
  └── auto_pentest.py     # Automated pentesting orchestration

api_pentest_orchestrator.py  # Main entry point
requirements.txt            # Python dependencies
install_dependencies.sh     # Tool installation
test_installation.py        # Verification script
```

## 🔍 Example Workflows

### Full API Pentest
```python
from workflows.auto_pentest import AutoPentest

pentest = AutoPentest("http://api.target.com", token="your_token")
results = pentest.run_full_scan()
report = pentest.generate_report()
```

### Specific Attack Category
```python
from modules.authentication_attacks import AuthenticationAttackAnalyzer

auth = AuthenticationAttackAnalyzer("http://api.target.com", token="token")
results = auth.analyze()
```

### Payload Generation
```python
from utils.request_builder import PayloadGenerator

payloads = PayloadGenerator.sql_injection_payloads()
payloads = PayloadGenerator.jwt_payloads()
payloads = PayloadGenerator.xxe_payloads()
```

## 📖 OWASP Top 10 API Mapping

| OWASP ID | Vulnerability | Framework Module |
|----------|----------------|------------------|
| API1 | Broken Object Level Authorization | authorization_attacks |
| API2 | Broken Authentication | authentication_attacks |
| API3 | Excessive Data Exposure | secrets_token_abuse |
| API4 | Lack of Rate Limiting | rate_limiting_dos |
| API5 | Broken Function Level Authorization | authorization_attacks |
| API6 | Mass Assignment | mass_assignment |
| API7 | Security Misconfiguration | file_upload_deserialization |
| API8 | Injection | injection_attacks |
| API9 | Improper Asset Management | discovery_enumeration |
| API10 | Insufficient Logging & Monitoring | secrets_token_abuse |

## 💾 Database Support

- SQLite (forensics)
- MySQL/MariaDB
- PostgreSQL
- MongoDB (NoSQL injection)

## 🔗 Supported Protocols

- HTTP/HTTPS
- GraphQL
- REST
- SOAP
- WebSockets (via tools)

## 📝 Logging

All tests are logged with detailed information:
- Entry/exit points
- Test results
- Vulnerabilities found
- Error details

## ⚙️ Configuration

Customize testing behavior by modifying:

```python
# In api_pentest_orchestrator.py
orchestrator = APIPentestOrchestrator(
    base_url="http://api.target.com",
    token="optional_token",
    output_dir="custom_results"
)
```

## 🚨 Disclaimer

This framework is designed for **authorized security testing only**.

- Only test APIs you own or have explicit permission to test
- Unauthorized testing is illegal
- Follow all applicable laws and regulations

## 📞 Support

For issues, refer to:
- Framework architecture
- Individual module documentation
- Test output logs
- OWASP Top 10 API resources

## 📈 Statistics

- **10** API attack categories
- **40+** integrated tools
- **150+** test methods
- **20+** attack workflows
- **100%** OWASP Top 10 API coverage

## 🎓 Learning Resources

- OWASP API Security Top 10
- API Security Best Practices
- Common Vulnerability Patterns
- Exploitation Techniques

---

**Ready to pentest your APIs? Start with:**
```bash
python3 api_pentest_orchestrator.py http://your-api.com
```
