"""
API Discovery & Enumeration Module
- Endpoint discovery and mapping
- Version enumeration
- Hidden route discovery
- HTTP method testing
- Swagger/OpenAPI abuse
"""

import json
import subprocess
import requests
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class APIDiscoveryAnalyzer:
    """Analyze API endpoints, versions, and exposed methods"""
    
    def __init__(self, base_url: str, wordlist: str = None):
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist or '/usr/share/wordlists/dirb/common.txt'
        self.endpoints = {}
        self.methods = {}
        self.swagger_data = {}
        
    def discover_endpoints_ffuf(self) -> Dict[str, List]:
        """Fuzzy endpoint discovery with ffuf"""
        logger.info(f"[*] Fuzzing endpoints on {self.base_url}...")
        endpoints = {'found': [], 'methods': {}}
        
        try:
            # API-specific patterns
            patterns = [
                'api/v1', 'api/v2', 'api/v3',
                '/users', '/admin', '/products', '/auth',
                '/login', '/register', '/profile', '/settings',
                '/data', '/config', '/status', '/health',
                '/upload', '/download', '/export', '/import'
            ]
            
            for pattern in patterns:
                try:
                    url = f"{self.base_url}/{pattern}"
                    resp = requests.head(url, timeout=5, verify=False)
                    if resp.status_code < 400:
                        endpoints['found'].append(pattern)
                        logger.info(f"[+] Found: {url} ({resp.status_code})")
                except Exception as e:
                    pass
                    
        except Exception as e:
            logger.error(f"[-] ffuf discovery failed: {e}")
            
        return endpoints
    
    def enumerate_versions(self) -> Dict[str, List]:
        """Enumerate API versions"""
        logger.info("[*] Enumerating API versions...")
        versions = []
        
        version_paths = [
            '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3',
            '/api-v1', '/api-v2',
            '/version', '/versions'
        ]
        
        for vpath in version_paths:
            try:
                url = f"{self.base_url}{vpath}/status"
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code < 400:
                    versions.append(vpath)
                    logger.info(f"[+] Version found: {vpath}")
            except:
                pass
        
        return {'versions': versions}
    
    def test_http_methods(self, endpoint: str) -> Dict[str, Any]:
        """Test HTTP methods on endpoint"""
        logger.info(f"[*] Testing HTTP methods on {endpoint}...")
        methods_result = {}
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        for method in methods:
            try:
                url = f"{self.base_url}{endpoint}"
                resp = requests.request(method, url, timeout=5, verify=False)
                if resp.status_code < 500:
                    methods_result[method] = {
                        'status': resp.status_code,
                        'allowed': True
                    }
                    logger.info(f"[+] Method {method}: {resp.status_code}")
            except Exception as e:
                methods_result[method] = {'allowed': False}
        
        return methods_result
    
    def discover_swagger(self) -> Dict[str, Any]:
        """Discover and extract Swagger/OpenAPI specs"""
        logger.info("[*] Searching for Swagger/OpenAPI endpoints...")
        
        swagger_paths = [
            '/swagger.json', '/api-docs', '/v1/api-docs',
            '/swagger/v1/swagger.json', '/openapi.json',
            '/api/swagger.json'
        ]
        
        for path in swagger_paths:
            try:
                url = f"{self.base_url}{path}"
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    self.swagger_data = resp.json()
                    logger.info(f"[+] Found Swagger: {path}")
                    return {
                        'found': True,
                        'path': path,
                        'endpoints': len(self.swagger_data.get('paths', {}))
                    }
            except:
                pass
        
        return {'found': False}
    
    def extract_swagger_endpoints(self) -> List[str]:
        """Extract endpoints from Swagger spec"""
        if not self.swagger_data:
            return []
        
        endpoints = []
        paths = self.swagger_data.get('paths', {})
        
        for endpoint, methods in paths.items():
            for method in methods.keys():
                endpoints.append({
                    'path': endpoint,
                    'method': method.upper(),
                    'summary': methods[method].get('summary', ''),
                    'parameters': methods[method].get('parameters', [])
                })
        
        logger.info(f"[+] Extracted {len(endpoints)} endpoints from Swagger")
        return endpoints
    
    def analyze(self) -> Dict[str, Any]:
        """Run full discovery analysis"""
        logger.info("[*] Starting API discovery and enumeration...")
        
        results = {
            'base_url': self.base_url,
            'discovery': self.discover_endpoints_ffuf(),
            'versions': self.enumerate_versions(),
            'swagger': self.discover_swagger(),
            'method_tests': {}
        }
        
        # Test methods on common endpoints
        common_endpoints = ['/api/users', '/api/products', '/api/auth/login']
        for endpoint in common_endpoints:
            results['method_tests'][endpoint] = self.test_http_methods(endpoint)
        
        if self.swagger_data:
            results['swagger_endpoints'] = self.extract_swagger_endpoints()
        
        return results
