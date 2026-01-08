#!/usr/bin/env python3
"""
Test installation and verify all tools are available
"""

import subprocess
import sys
import json

def test_python_imports():
    """Test Python package imports"""
    print("[*] Testing Python imports...")
    
    required_packages = {
        'requests': 'requests',
        'jwt': 'PyJWT',
        'cryptography': 'cryptography',
        'yaml': 'PyYAML',
        'urllib3': 'urllib3'
    }
    
    missing = []
    
    for module, package in required_packages.items():
        try:
            __import__(module)
            print(f"  [+] {package} - OK")
        except ImportError:
            print(f"  [-] {package} - MISSING")
            missing.append(package)
    
    return len(missing) == 0

def test_system_tools():
    """Test availability of system tools"""
    print("\n[*] Testing system tools...")
    
    tools = ['curl', 'httpie', 'ffuf', 'sqlmap', 'mitmproxy']
    available = []
    missing = []
    
    for tool in tools:
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
            print(f"  [+] {tool} - OK")
            available.append(tool)
        except:
            print(f"  [-] {tool} - MISSING")
            missing.append(tool)
    
    return {
        'available': available,
        'missing': missing,
        'coverage': len(available) / len(tools) * 100
    }

def test_module_structure():
    """Test Python module structure"""
    print("\n[*] Testing module structure...")
    
    modules = [
        'modules.discovery_enumeration',
        'modules.authentication_attacks',
        'modules.authorization_attacks',
        'modules.injection_attacks',
        'modules.business_logic_attacks',
        'modules.mass_assignment',
        'modules.rate_limiting_dos',
        'modules.graphql_attacks',
        'modules.file_upload_deserialization',
        'modules.secrets_token_abuse',
        'utils.request_builder',
        'workflows.auto_pentest'
    ]
    
    available = []
    missing = []
    
    for module in modules:
        try:
            __import__(module)
            print(f"  [+] {module} - OK")
            available.append(module)
        except Exception as e:
            print(f"  [-] {module} - ERROR: {e}")
            missing.append(module)
    
    return {
        'available': available,
        'missing': missing,
        'coverage': len(available) / len(modules) * 100
    }

def main():
    print("========================================")
    print("API Pentest Framework - Installation Test")
    print("========================================\n")
    
    python_ok = test_python_imports()
    tools_status = test_system_tools()
    modules_status = test_module_structure()
    
    print("\n========================================")
    print("Test Summary")
    print("========================================\n")
    
    print(f"Python Packages: {'✓ OK' if python_ok else '✗ ISSUES'}")
    print(f"System Tools: {tools_status['coverage']:.0f}% ({len(tools_status['available'])}/{len(tools_status['available']) + len(tools_status['missing'])})")
    print(f"Modules: {modules_status['coverage']:.0f}% ({len(modules_status['available'])}/{len(modules_status['available']) + len(modules_status['missing'])})")
    
    if not python_ok:
        print("\n[!] Please install missing Python packages:")
        print("    pip3 install -r requirements.txt")
    
    if tools_status['missing']:
        print(f"\n[!] Missing system tools: {', '.join(tools_status['missing'])}")
        print("    Run: bash install_dependencies.sh")
    
    if modules_status['missing']:
        print(f"\n[!] Missing modules: {', '.join(modules_status['missing'])}")
        print("    Verify module structure and imports")
    
    print("\n" + "="*40)
    if python_ok and modules_status['coverage'] == 100.0:
        print("[+] Installation complete and ready to use!")
        print("\nUsage:")
        print("  python3 api_pentest_orchestrator.py http://target.com")
        return 0
    else:
        print("[!] Installation incomplete. Please fix issues above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
