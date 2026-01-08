"""
API Pentest Modules Package
Complete set of 10 API security testing modules
"""

from .discovery_enumeration import APIDiscoveryAnalyzer
from .authentication_attacks import AuthenticationAttackAnalyzer
from .authorization_attacks import AuthorizationAttackAnalyzer
from .injection_attacks import InjectionAttackAnalyzer
from .business_logic_attacks import BusinessLogicAttackAnalyzer
from .mass_assignment import MassAssignmentAnalyzer
from .rate_limiting_dos import RateLimitingDoSAnalyzer
from .graphql_attacks import GraphQLAttackAnalyzer
from .file_upload_deserialization import FileUploadDeserializationAnalyzer
from .secrets_token_abuse import SecretsTokenAbuseAnalyzer

__all__ = [
    'APIDiscoveryAnalyzer',
    'AuthenticationAttackAnalyzer',
    'AuthorizationAttackAnalyzer',
    'InjectionAttackAnalyzer',
    'BusinessLogicAttackAnalyzer',
    'MassAssignmentAnalyzer',
    'RateLimitingDoSAnalyzer',
    'GraphQLAttackAnalyzer',
    'FileUploadDeserializationAnalyzer',
    'SecretsTokenAbuseAnalyzer'
]

VERSION = "1.0.0"
OWASP_TOP_10_API = {
    1: "Broken Object Level Authorization",
    2: "Broken Authentication",
    3: "Excessive Data Exposure",
    4: "Lack of Rate Limiting",
    5: "Broken Function Level Authorization",
    6: "Mass Assignment",
    7: "Security Misconfiguration",
    8: "Injection",
    9: "Improper Asset Management",
    10: "Insufficient Logging & Monitoring"
}

ATTACK_CATEGORIES = {
    'discovery': APIDiscoveryAnalyzer,
    'authentication': AuthenticationAttackAnalyzer,
    'authorization': AuthorizationAttackAnalyzer,
    'injection': InjectionAttackAnalyzer,
    'business_logic': BusinessLogicAttackAnalyzer,
    'mass_assignment': MassAssignmentAnalyzer,
    'rate_limiting': RateLimitingDoSAnalyzer,
    'graphql': GraphQLAttackAnalyzer,
    'file_upload': FileUploadDeserializationAnalyzer,
    'secrets': SecretsTokenAbuseAnalyzer
}
