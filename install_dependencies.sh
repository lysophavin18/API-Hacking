#!/bin/bash

# API Pentesting Tools Installation Script
# Installs 40+ tools for comprehensive API security testing

set -e

echo "========================================="
echo "API Pentesting Framework Setup"
echo "========================================="
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -f /etc/debian_version ]; then
        OS="debian"
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/arch-release ]; then
        OS="arch"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
fi

echo "[*] Detected OS: $OS"
echo "[*] Installing dependencies..."
echo ""

# Update package manager
if [ "$OS" = "debian" ]; then
    sudo apt-get update -qq
    INSTALL_CMD="sudo apt-get install -y"
elif [ "$OS" = "rhel" ]; then
    INSTALL_CMD="sudo yum install -y"
elif [ "$OS" = "arch" ]; then
    INSTALL_CMD="sudo pacman -S --noconfirm"
elif [ "$OS" = "macos" ]; then
    INSTALL_CMD="brew install"
fi

# Install Python dependencies
echo "[*] Installing Python packages..."
pip3 install -r requirements.txt -q

# Install system tools
echo "[*] Installing API testing tools..."

# HTTP tools
echo "  - Installing curl, httpie, wget..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD curl httpie wget 2>/dev/null || true
else
    brew install curl httpie wget 2>/dev/null || true
fi

# API Testing
echo "  - Installing API testing tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD postman 2>/dev/null || true
fi

# Fuzzing & Enumeration
echo "  - Installing fuzzing tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD ffuf gobuster dirbuster 2>/dev/null || true
fi

# SQL/Database Testing
echo "  - Installing database testing tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD sqlmap 2>/dev/null || true
fi

# Proxy & Interception
echo "  - Installing proxy tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD mitmproxy burpsuite 2>/dev/null || true
fi

# Token Analysis
echo "  - Installing token analysis tools..."
pip3 install jwt-tool pyjwt -q 2>/dev/null || true

# GraphQL Testing
echo "  - Installing GraphQL tools..."
pip3 install graphql-core -q 2>/dev/null || true

# Load Testing
echo "  - Installing load testing tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD apache2-utils locust 2>/dev/null || true
fi

# Encoding/Decoding
echo "  - Installing encoding tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD base64 xxd od 2>/dev/null || true
fi

# Network Tools
echo "  - Installing network tools..."
if [ "$OS" != "macos" ]; then
    $INSTALL_CMD nmap netcat-openbsd tcpdump 2>/dev/null || true
fi

# Install pip packages
echo "[*] Installing Python packages..."
pip3 install --upgrade requests pyjwt cryptography pyyaml urllib3 -q 2>/dev/null || true
pip3 install sqlmap 2>/dev/null || true
pip3 install graphql-core 2>/dev/null || true

echo ""
echo "========================================="
echo "[+] Installation Complete!"
echo "========================================="
echo ""
echo "To run API penetration tests:"
echo ""
echo "  python3 api_pentest_orchestrator.py http://target.com"
echo "  python3 api_pentest_orchestrator.py http://target.com --token YOUR_TOKEN"
echo ""
echo "For help:"
echo "  python3 api_pentest_orchestrator.py --help"
echo ""
