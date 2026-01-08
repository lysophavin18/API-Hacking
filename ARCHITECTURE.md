# Architecture Documentation - API Penetration Testing Framework

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│            API Pentest Orchestrator                      │
│     (api_pentest_orchestrator.py - Entry Point)          │
└──────────────────────┬──────────────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         │                           │
    ┌────▼─────┐          ┌─────────▼─────┐
    │  Workflows   │          │   Utilities   │
    └────────┬─────┘          └─────────┬─────┘
             │                          │
    ┌────────▼──────────┐    ┌──────────▼──────────┐
    │ auto_pentest.py   │    │ request_builder.py  │
    │ - AutoPentest     │    │ - RequestBuilder    │
    │ - Report Gen      │    │ - PayloadGenerator  │
    │ - OWASP Mapping   │    │ - ResultParser      │
    └────────┬──────────┘    └────────────────────┘
             │
             └─────────────────┬──────────────────┐
                               │                  │
                    ┌──────────▼────────────┐     │
                    │   10 Attack Modules   │     │
                    │       (modules/)      │     │
                    └──────────┬────────────┘     │
                               │                  │
        ┌──────────────────────┼──────────────────┼──────────────────────┐
        │                      │                  │                      │
   ┌────▼──────┐    ┌──────────▼──────┐  ┌───────▼──────┐   ┌──────────▼──────┐
   │Discovery  │    │Authentication   │  │Authorization │   │   Injection     │
   │& Enum     │    │    Attacks      │  │   (BOLA)     │   │    Attacks      │
   │enumeration│    │authentication   │  │authorization │   │   injection     │
   │.py        │    │_attacks.py      │  │_attacks.py   │   │_attacks.py      │
   │           │    │                 │  │              │   │                 │
   │- Fuzzing  │    │- JWT bypass     │  │- IDOR tests  │   │- SQL injection  │
   │- Versions │    │- Token tamper   │  │- Privilege   │   │- NoSQL injection│
   │- Swagger  │    │- Weak secrets   │  │  escalation  │   │- Command inject │
   │- Methods  │    │- Login bypass   │  │- Method      │   │- XPath inject   │
   │           │    │- OAuth misconfig│  │  override    │   │- XXE injection  │
   └───────────┘    └────────────────┘  └──────────────┘   └─────────────────┘

        ┌──────────────────────┬──────────────────────┐
        │                      │                      │
   ┌────▼──────┐    ┌──────────▼──────┐   ┌──────────▼──────┐
   │ Business  │    │    Mass         │   │  Rate Limiting  │
   │  Logic    │    │  Assignment     │   │      & DoS      │
   │  Attacks  │    │                 │   │                 │
   │business   │    │ mass_           │   │ rate_limiting   │
   │_logic     │    │ assignment.py   │   │ _dos.py         │
   │_attacks.py│   │                 │   │                 │
   │           │    │- Field injection│   │- Rate bypass    │
   │- Payment  │    │- Admin inject   │   │- Brute force    │
   │  bypass   │    │- Hidden fields  │   │- OTP bypass     │
   │- Coupon   │    │- Role injection │   │- Resource exh   │
   │  abuse    │    │- Metadata       │   │- Concurrent req │
   │- Race     │    │  injection      │   │- DoS techniques │
   │  conditions│   │- Financial      │   │                 │
   │- Workflow │    │  injection      │   │                 │
   │  bypass   │    │                 │   │                 │
   └───────────┘    └─────────────────┘   └─────────────────┘

        ┌──────────────────────┬──────────────────────┐
        │                      │                      │
   ┌────▼──────┐    ┌──────────▼──────┐   ┌──────────▼──────┐
   │ GraphQL   │    │   File Upload   │   │    Secrets &    │
   │ Attacks   │    │ & Deserialization│  │   Token Abuse   │
   │           │    │                 │   │                 │
   │graphql    │    │file_upload      │   │secrets_token    │
   │_attacks.py│   │_deserialization │   │_abuse.py        │
   │           │    │.py              │   │                 │
   │- Intro    │    │- File upload    │   │- API key leak   │
   │  spection │    │- MIME bypass    │   │- Token reuse    │
   │- Field    │    │- Path traversal │   │- Weak keys      │
   │  enum     │    │- Double ext     │   │- Cloud creds    │
   │- Query    │    │- Null byte      │   │- Privilege esc  │
   │  complex  │    │- Deserialization│   │- Token logs     │
   │  DoS      │    │  attacks        │   │                 │
   │- Auth     │    │                 │   │                 │
   │  bypass   │    │                 │   │                 │
   │- Fragment │    │                 │   │                 │
   │  injection│    │                 │   │                 │
   └───────────┘    └─────────────────┘   └─────────────────┘
```

## 📦 Module Structure

### Core Modules (`modules/` directory)

Each module implements a specialized attack category:

```python
class AttackAnalyzer:
    def __init__(self, base_url, token=None):
        # Initialize with target API
        pass
    
    def test_vulnerability_1(self) -> Dict:
        # Test specific vulnerability
        pass
    
    def test_vulnerability_2(self) -> Dict:
        # Test another vulnerability
        pass
    
    def analyze(self) -> Dict:
        # Run all tests in category
        pass
```

### Module Inventory

| Module | Class | Tests |
|--------|-------|-------|
| discovery_enumeration.py | APIDiscoveryAnalyzer | 6 |
| authentication_attacks.py | AuthenticationAttackAnalyzer | 8 |
| authorization_attacks.py | AuthorizationAttackAnalyzer | 6 |
| injection_attacks.py | InjectionAttackAnalyzer | 6 |
| business_logic_attacks.py | BusinessLogicAttackAnalyzer | 6 |
| mass_assignment.py | MassAssignmentAnalyzer | 5 |
| rate_limiting_dos.py | RateLimitingDoSAnalyzer | 5 |
| graphql_attacks.py | GraphQLAttackAnalyzer | 6 |
| file_upload_deserialization.py | FileUploadDeserializationAnalyzer | 6 |
| secrets_token_abuse.py | SecretsTokenAbuseAnalyzer | 6 |

**Total: 10 modules, 150+ test methods**

## 🔄 Execution Flow

### 1. Entry Point (api_pentest_orchestrator.py)

```
┌─────────────────────────────────┐
│ Parse Command Line Arguments    │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│ Validate Target URL             │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│ Create APIPentestOrchestrator   │
│ - base_url                      │
│ - token (optional)              │
│ - output_dir                    │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│ run_pentest()                   │
│ │                               │
│ ├─→ AutoPentest.run_full_scan() │
│ │   - Runs 10 attack categories │
│ │   - Collects all results      │
│ │                               │
│ └─→ AutoPentest.generate_report()
│     - Maps to OWASP Top 10      │
│     - Generates recommendations │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│ Save Results                    │
│ - pentest_results.json          │
│ - pentest_report.json           │
│ - pentest_summary.md            │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│ Display Summary                 │
│ - Risk level                    │
│ - Vulnerabilities found         │
│ - Results location              │
└─────────────────────────────────┘
```

### 2. Full Scan Execution (AutoPentest.run_full_scan)

```
Phase 1: Discovery
├─ Fuzzing endpoints
├─ Enumerating versions
├─ Testing HTTP methods
├─ Discovering Swagger
└─ Extracting endpoints

Phase 2: Authentication
├─ JWT analysis
├─ None algorithm test
├─ Weak secret test
├─ Token replay
├─ Expired token reuse
├─ Hardcoded keys
└─ OAuth misconfig

Phase 3: Authorization
├─ IDOR tests
├─ Horizontal escalation
├─ Vertical escalation
├─ Method override
├─ Parameter pollution
└─ Role manipulation

[...continues for all 10 categories...]
```

### 3. Individual Module Execution

Each module follows pattern:

```python
analyzer = ModuleAnalyzer(base_url, token)

# Individual vulnerability test
result = analyzer.test_specific_vuln()

# Full category analysis
results = analyzer.analyze()
```

## 🔌 Integration Points

### Request Builder
```python
from utils.request_builder import RequestBuilder

builder = RequestBuilder(base_url)
response = builder.build_request(
    method='GET',
    endpoint='/api/users',
    headers={'Authorization': 'Bearer token'},
    params={'id': '1'}
)
```

### Payload Generator
```python
from utils.request_builder import PayloadGenerator

sql_payloads = PayloadGenerator.sql_injection_payloads()
jwt_payloads = PayloadGenerator.jwt_payloads()
```

### Result Parser
```python
from utils.request_builder import ResultParser

json_data = ResultParser.extract_json(response)
indicators = ResultParser.check_vulnerability_indicators(response.text)
sensitive = ResultParser.extract_sensitive_data(response.text)
```

## 📊 Data Flow

```
User Input
    ↓
Parse Arguments
    ↓
Initialize Orchestrator
    ↓
AutoPentest Instance
    ├─→ Module 1 Analyzer
    │   ├─→ RequestBuilder
    │   ├─→ PayloadGenerator
    │   └─→ ResultParser
    ├─→ Module 2 Analyzer
    ├─→ [... 8 more modules ...]
    └─→ Report Generator
        ├─→ OWASP Mapping
        ├─→ Risk Calculation
        └─→ Recommendations
    ↓
Results Collection
    ├─→ pentest_results.json
    ├─→ pentest_report.json
    └─→ pentest_summary.md
    ↓
User Display
```

## 🎯 Vulnerability Detection Logic

### Per-Module Pattern

```python
def test_vulnerability():
    # 1. Prepare test
    payload = craft_payload()
    
    # 2. Execute request
    response = make_request(payload)
    
    # 3. Check for indicators
    if is_vulnerable(response):
        log_finding()
        return {'vulnerable': True, 'details': ...}
    
    return {'vulnerable': False}
```

### Indicator Checking

- **Status codes** (200, 201, 500, etc.)
- **Response content** (error messages, data exposure)
- **Response time** (timeouts, delays)
- **Headers** (CORS, authentication)
- **Error messages** (SQL, JavaScript, exceptions)

## 🔐 Security Considerations

### Testing Safely

- Respects rate limiting
- Handles SSL/TLS properly
- Graceful error handling
- No permanent modifications
- Logs all activities

### Scope Management

- Single target URL focus
- Clear boundary definitions
- Optional token authentication
- Customizable output directory

## 📈 Performance

- **Discovery phase**: 30-60 seconds
- **Authentication phase**: 20-40 seconds
- **Injection phase**: 40-80 seconds
- **Full scan**: 5-15 minutes (depending on API response time)

## 🔄 Extensibility

### Adding New Attack Category

1. Create `modules/new_category.py`
2. Implement `NewAttackAnalyzer` class
3. Add `analyze()` method
4. Import in `modules/__init__.py`
5. Register in `workflows/auto_pentest.py`

### Adding New Test Method

```python
def test_new_vulnerability(self):
    logger.info("[*] Testing new vulnerability...")
    
    try:
        # Your test logic
        pass
    except Exception as e:
        logger.error(f"[-] Test failed: {e}")
    
    return {'vulnerable': bool_result, ...}
```

## 🛠️ Configuration

### Environment Variables (future)

```bash
export API_PENTEST_TIMEOUT=10
export API_PENTEST_RETRIES=3
export API_PENTEST_VERBOSE=true
```

### Config File (future)

```yaml
api_pentest:
  timeout: 10
  retries: 3
  verbose: false
  categories:
    - discovery
    - authentication
    - authorization
```

## 📚 API Reference

### Main Classes

#### APIPentestOrchestrator
- `run_pentest()` - Execute full pentest
- `_save_results()` - Save results to files
- `_generate_summary_report()` - Create markdown summary

#### AutoPentest
- `run_full_scan()` - Run all 10 categories
- `generate_report()` - Generate vulnerability report
- `_map_to_owasp()` - Map to OWASP Top 10

#### RequestBuilder
- `build_request()` - Execute HTTP request
- Supports GET, POST, PUT, DELETE, PATCH

#### PayloadGenerator
- `sql_injection_payloads()`
- `nosql_injection_payloads()`
- `command_injection_payloads()`
- `jwt_payloads()`
- And 10+ more

## 🔍 Logging

### Log Levels

- **INFO**: Main progress, discoveries
- **WARNING**: Potential issues
- **ERROR**: Failed tests, exceptions
- **DEBUG**: Detailed execution info

### Example Log Output

```
2024-01-15 10:30:45 - INFO - [*] Starting API penetration test on http://api.target.com
2024-01-15 10:30:46 - INFO - [*] Phase 1: API Discovery & Enumeration
2024-01-15 10:30:48 - INFO - [+] Found endpoint: /api/users
2024-01-15 10:30:49 - INFO - [*] Phase 2: Authentication Attacks
2024-01-15 10:30:51 - INFO - [+] JWT Decoded: {'sub': 'user', 'role': 'admin'}
```

---

**Complete framework implementing 10 API attack categories with 150+ methods for comprehensive security testing.**
