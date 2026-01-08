"""
Secrets & Token Abuse Module
- API key leakage
- Token reuse and misuse
- Weak cryptographic keys
- Cloud credential abuse
"""

import requests
import re
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class SecretsTokenAbuseAnalyzer:
    """Analyze secrets and token abuse vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        
    def scan_api_key_exposure(self, response_text: str) -> List[str]:
        """Scan for exposed API keys in responses"""
        logger.info("[*] Scanning for API key exposure...")
        
        api_patterns = {
            'AWS': r'AKIA[0-9A-Z]{16}',
            'GitHub': r'ghp_[0-9a-zA-Z]{36}',
            'Stripe': r'sk_live_[0-9a-zA-Z]{24}',
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'Slack': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9A-Za-z]{24}',
            'Private Key': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----'
        }
        
        exposed_keys = []
        
        for key_type, pattern in api_patterns.items():
            matches = re.findall(pattern, response_text)
            if matches:
                exposed_keys.append({
                    'type': key_type,
                    'count': len(matches),
                    'sample': matches[0][:20] + '...'
                })
                logger.info(f"[+] Exposed {key_type}: {len(matches)} found")
        
        return exposed_keys
    
    def test_hardcoded_secrets(self, endpoint: str) -> Dict[str, Any]:
        """Test for hardcoded secrets in API responses"""
        logger.info(f"[*] Testing for hardcoded secrets on {endpoint}...")
        
        try:
            resp = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            exposed = self.scan_api_key_exposure(resp.text)
            
            if exposed:
                return {
                    'vulnerable': True,
                    'exposed_secrets': exposed,
                    'response_snippet': resp.text[:500]
                }
        except Exception as e:
            logger.error(f"[-] Secret scan failed: {e}")
        
        return {'vulnerable': False}
    
    def test_token_reuse(self, endpoints: List[str]) -> Dict[str, Any]:
        """Test if token can be reused across services"""
        logger.info("[*] Testing token reuse...")
        
        if not self.token:
            return {'vulnerable': False}
        
        accessible_services = []
        
        for endpoint in endpoints:
            try:
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    accessible_services.append(endpoint)
                    logger.info(f"[+] Token accepted at: {endpoint}")
            except:
                pass
        
        return {
            'vulnerable': len(accessible_services) > 1,
            'accessible_services': accessible_services
        }
    
    def test_weak_signing_key(self, endpoint: str) -> Dict[str, Any]:
        """Test for weak cryptographic signing keys"""
        logger.info(f"[*] Testing weak signing keys on {endpoint}...")
        
        weak_keys = [
            'secret', 'password', '123456', 'key', 'default',
            'test', 'admin', 'changeme'
        ]
        
        found_weak_keys = []
        
        for key in weak_keys:
            try:
                # Try signing with weak key
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json={'key': key},
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    found_weak_keys.append(key)
                    logger.info(f"[+] Weak key accepted: {key}")
            except:
                pass
        
        return {
            'vulnerable': len(found_weak_keys) > 0,
            'weak_keys': found_weak_keys
        }
    
    def test_cloud_credential_exposure(self) -> Dict[str, Any]:
        """Test for cloud credential exposure (AWS, Azure, GCP)"""
        logger.info("[*] Testing for cloud credential exposure...")
        
        cloud_endpoints = [
            '/api/config', '/api/settings', '/api/metadata',
            '/.aws/credentials', '/gcp-credentials.json',
            '/azure-credentials.json'
        ]
        
        exposed_credentials = []
        
        for endpoint in cloud_endpoints:
            try:
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    if any(x in resp.text for x in ['aws_access_key', 'PRIVATE_KEY', 'azure_secret']):
                        exposed_credentials.append({
                            'endpoint': endpoint,
                            'status': resp.status_code
                        })
                        logger.info(f"[+] Cloud credentials exposed at: {endpoint}")
            except:
                pass
        
        return {
            'vulnerable': len(exposed_credentials) > 0,
            'exposed_endpoints': exposed_credentials
        }
    
    def test_token_privilege_escalation(self) -> Dict[str, Any]:
        """Test if token can be used for privilege escalation"""
        logger.info("[*] Testing token privilege escalation...")
        
        if not self.token:
            return {'vulnerable': False}
        
        try:
            # Try accessing admin endpoints with regular token
            admin_endpoints = [
                '/api/admin/users',
                '/api/admin/settings',
                '/api/admin/reports'
            ]
            
            accessed = []
            for endpoint in admin_endpoints:
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    accessed.append(endpoint)
                    logger.info(f"[+] Admin endpoint accessed: {endpoint}")
            
            return {
                'vulnerable': len(accessed) > 0,
                'accessed_endpoints': accessed
            }
        except:
            pass
        
        return {'vulnerable': False}
    
    def test_token_in_logs(self) -> Dict[str, Any]:
        """Test if tokens are logged/exposed"""
        logger.info("[*] Testing token logging...")
        
        try:
            resp = requests.get(
                f"{self.base_url}/api/logs",
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            if self.token in resp.text:
                logger.info(f"[+] Token found in logs!")
                return {
                    'vulnerable': True,
                    'technique': 'Token in Logs',
                    'evidence': resp.text[:200]
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full secrets and token abuse analysis"""
        logger.info("[*] Starting secrets and token abuse analysis...")
        
        results = {
            'hardcoded_secrets': self.test_hardcoded_secrets('/api/config'),
            'token_reuse': self.test_token_reuse(['/api/data', '/api/users', '/api/reports']),
            'weak_signing_keys': self.test_weak_signing_key('/api/sign'),
            'cloud_credentials': self.test_cloud_credential_exposure(),
            'token_escalation': self.test_token_privilege_escalation(),
            'token_in_logs': self.test_token_in_logs()
        }
        
        return results
