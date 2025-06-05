import base64
import hashlib
import socket
import os
import subprocess
import re
import requests
from bs4 import BeautifulSoup
import bcrypt
import zxcvbn
import ipaddress
import platform
import secrets
import string
import ssl
import html
import time
from urllib.parse import urljoin
from datetime import datetime
from PIL import Image
import exifread
import logging
from cryptography.fernet import Fernet
import psutil
import json
from typing import List, Dict, Union, Optional
import importlib.util
import sys
import unittest

"""
The Ultimate Cybersecurity Toolkit by Mohammed Muhaimin - 54 Tools Implemented

Requirements:
- Python 3.8+
- Install dependencies: pip install requests beautifulsoup4 bcrypt python-zxcvbn scapy dnspython psutil Pillow exifread cryptography
- Some tools (e.g., packet_sniffer, list_connected_devices) require root/admin privileges for scapy.
- WARNING: Use only on systems you have permission to test. Unauthorized use of tools like port scanning, packet sniffing, or SQL injection testing is illegal and unethical.

Usage:
- Run the script and select a tool by entering its number.
- Follow prompts to provide required inputs.
- Use option 99 for a quick test of select tools.
- Run tests by answering 'y' to the initial prompt.
"""

# Configure logging
logging.basicConfig(
    filename='cybersecurity_toolkit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_dependencies():
    """Check if required libraries are installed."""
    required = [
        'requests', 'bs4', 'bcrypt', 'zxcvbn', 'scapy', 'dns', 'psutil', 'PIL', 'exifread', 'cryptography'
    ]
    missing = []
    for module in required:
        if not importlib.util.find_spec(module):
            missing.append(module)
    if missing:
        print("Error: Missing dependencies:", ", ".join(missing))
        print("Install them using: pip install", " ".join(missing))
        sys.exit(1)

check_dependencies()

# ====================================
# CRYPTOGRAPHY & ENCRYPTION TOOLS (1-7)
# ====================================

def caesar_cipher(text: str, shift: Union[int, str], mode: str = 'encrypt') -> Union[str, Dict[str, str]]:
    """
    1. Caesar Cipher
    Encrypts or decrypts text using a Caesar cipher with the specified shift.
    
    Args:
        text (str): The input text to encrypt/decrypt.
        shift (Union[int, str]): The number of positions to shift (integer).
        mode (str): 'encrypt' or 'decrypt' (default: 'encrypt').
    
    Returns:
        Union[str, Dict[str, str]]: The encrypted/decrypted text or an error message.
    """
    try:
        shift = int(shift)
    except ValueError:
        return {'error': 'Shift must be an integer'}
    if mode not in ['encrypt', 'decrypt']:
        return {'error': "Mode must be 'encrypt' or 'decrypt'"}
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + (-shift if mode == 'decrypt' else shift)) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    return ''.join(result)

def base64_encode_decode(text: str, mode: str = 'encode') -> Union[str, Dict[str, str]]:
    """
    2. Base64 Encode/Decode
    Encodes or decodes text using Base64.
    
    Args:
        text (str): The input text to encode/decode.
        mode (str): 'encode' or 'decode' (default: 'encode').
    
    Returns:
        Union[str, Dict[str, str]]: The encoded/decoded text or an error message.
    """
    try:
        if mode == 'encode':
            return base64.b64encode(text.encode()).decode()
        elif mode == 'decode':
            return base64.b64decode(text).decode()
        else:
            return {'error': "Mode must be 'encode' or 'decode'"}
    except Exception as e:
        return {'error': f'Base64 operation failed: {str(e)}'}

def sha256_hash(text: str) -> str:
    """
    3. SHA-256 Hash Generator
    Generates a SHA-256 hash of the input text.
    
    Args:
        text (str): The input text to hash.
    
    Returns:
        str: The SHA-256 hash.
    """
    return hashlib.sha256(text.encode()).hexdigest()

def check_password_strength(password: str) -> Dict:
    """
    4. Password Strength Checker
    Evaluates the strength of a password.
    
    Args:
        password (str): The password to check.
    
    Returns:
        Dict: Password strength score, feedback, and estimated crack time.
    """
    try:
        result = zxcvbn.zxcvbn(password)
        return {
            'score': result['score'],
            'feedback': result['feedback'],
            'crack_time': result['crack_times_display']['online_no_throttling_10_per_second']
        }
    except Exception as e:
        return {'error': f'Password strength check failed: {str(e)}'}

def verify_file_integrity(file_path: str, known_hash: str) -> Union[bool, Dict[str, str]]:
    """
    5. File Integrity Verifier
    Verifies file integrity by comparing its SHA-256 hash with a known hash.
    
    Args:
        file_path (str): Path to the file.
        known_hash (str): Expected SHA-256 hash.
    
    Returns:
        Union[bool, Dict[str, str]]: True if hashes match, False otherwise, or an error message.
    """
    if not os.path.isfile(file_path):
        return {'error': f'File {file_path} does not exist'}
    try:
        with open(file_path, 'rb') as f:
            computed_hash = hashlib.sha256(f.read()).hexdigest()
        return computed_hash == known_hash
    except Exception as e:
        return {'error': f'Failed to read file: {str(e)}'}

def xor_cipher(text: str, key: Union[int, str], mode: str = 'encode') -> Union[str, Dict[str, str]]:
    """
    6. XOR Cipher
    Encrypts or decrypts text using an XOR cipher with the specified key.
    
    Args:
        text (str): The input text to encode/decode.
        key (Union[int, str]): The integer key for XOR operation.
        mode (str): 'encode' or 'decode' (default: 'encode').
    
    Returns:
        Union[str, Dict[str, str]]: The encoded/decoded text or an error message.
    """
    try:
        key = int(key)
        if key < 0:
            return {'error': 'Key must be a non-negative integer'}
        if mode not in ['encode', 'decode']:
            return {'error': "Mode must be 'encode' or 'decode'"}
        if not text:
            return {'error': 'Input text cannot be empty'}
        
        result = ''.join(chr(ord(c) ^ key) for c in text)
        return result
    except ValueError:
        return {'error': 'Key must be an integer'}
    except Exception as e:
        return {'error': f'XOR operation failed: {str(e)}'}

def substitution_cipher(text: str, custom_map: Optional[Dict[str, str]] = None) -> str:
    """
    7. Substitution Cipher
    Encrypts text using a substitution cipher with a custom or random mapping.
    
    Args:
        text (str): The input text to encrypt.
        custom_map (Optional[Dict[str, str]]): Custom mapping for substitution (default: None).
    
    Returns:
        str: The encrypted text.
    """
    if not custom_map:
        alphabet = string.ascii_lowercase
        shuffled = list(alphabet)
        secrets.SystemRandom().shuffle(shuffled)
        custom_map = dict(zip(alphabet, shuffled))
    return ''.join(custom_map.get(c.lower(), c) for c in text)

# =============================
# PASSWORD SECURITY TOOLS (8-10)
# =============================

def hash_password(password: str, algorithm: str = 'sha256') -> Union[str, Dict[str, str]]:
    """
    8. Hash Passwords (hashlib)
    Hashes a password using the specified algorithm.
    
    Args:
        password (str): The password to hash.
        algorithm (str): Hash algorithm ('sha256' or 'sha512', default: 'sha256').
    
    Returns:
        Union[str, Dict[str, str]]: The hashed password or an error message.
    """
    try:
        if algorithm == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            return {'error': "Algorithm must be 'sha256' or 'sha512'"}
    except Exception as e:
        return {'error': f'Hashing failed: {str(e)}'}

def bcrypt_hash(password: str, rounds: int = 12) -> Union[str, Dict[str, str]]:
    """
    9. Salted Hash with bcrypt
    Hashes a password using bcrypt with the specified number of rounds.
    
    Args:
        password (str): The password to hash.
        rounds (int): Number of bcrypt rounds (default: 12).
    
    Returns:
        Union[str, Dict[str, str]]: The hashed password or an error message.
    """
    try:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds)).decode()
    except Exception as e:
        return {'error': f'Bcrypt hashing failed: {str(e)}'}

def generate_password(length: int = 16, include_special: bool = True) -> str:
    """
    10. Random Password Generator
    Generates a random password of the specified length.
    
    Args:
        length (int): Length of the password (default: 16).
        include_special (bool): Include special characters (default: True).
    
    Returns:
        str: The generated password.
    """
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

# =========================
# NETWORK SECURITY TOOLS (11-21)
# =========================

def port_scanner(target: str, ports: List[Union[int, str]]) -> Dict:
    """
    11. Port Scanner
    Scans specified ports on a target host.
    WARNING: Use only on systems you have permission to scan.
    
    Args:
        target (str): Target IP or hostname.
        ports (List[Union[int, str]]): List of ports to scan.
    
    Returns:
        Dict: Port status (open/closed) or error message.
    """
    try:
        ports = [int(p) for p in ports]
        if not all(0 <= p <= 65535 for p in ports):
            return {'error': 'Ports must be between 0 and 65535'}
        socket.gethostbyname(target)
    except (ValueError, socket.gaierror):
        return {'error': 'Invalid target or ports'}
    
    results = {}
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            results[port] = "open" if result == 0 else "closed"
    return results

def http_header_extractor(url: str) -> Dict:
    """
    12. HTTP Header Extractor
    Extracts HTTP headers from a URL.
    
    Args:
        url (str): The URL to query.
    
    Returns:
        Dict: HTTP headers or error message.
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        response = requests.get(url, timeout=5)
        return dict(response.headers)
    except requests.RequestException as e:
        return {'error': str(e)}

def ip_type_checker(ip_str: str) -> str:
    """
    13. IP Type Checker
    Determines the type of an IP address.
    
    Args:
        ip_str (str): The IP address to check.
    
    Returns:
        str: IP type (private, loopback, multicast, public, or invalid).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return "private"
        elif ip.is_loopback:
            return "loopback"
        elif ip.is_multicast:
            return "multicast"
        return "public"
    except ValueError:
        return "invalid"

def ping_host(host: str, count: int = 4) -> Dict:
    """
    14. Ping Tool
    Pings a host to check reachability.
    
    Args:
        host (str): The host to ping.
        count (int): Number of pings (default: 4).
    
    Returns:
        Dict: Ping results or error message.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout = '-w 1000' if platform.system().lower() == 'windows' else '-W 1'
    cmd = ['ping', param, str(count), timeout, host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {
            'success': result.returncode == 0,
            'output': result.stdout
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Ping timed out'}
    except Exception as e:
        return {'error': str(e)}

def packet_sniffer(count: int = 10) -> List[Dict]:
    """
    15. Packet Sniffer
    Captures network packets (requires scapy and root privileges).
    WARNING: Use only on networks you have permission to monitor.
    
    Args:
        count (int): Number of packets to capture (default: 10).
    
    Returns:
        List[Dict]: Captured packet details or error message.
    """
    try:
        from scapy.all import sniff
        packets = sniff(count=count)
        return [{
            'src': pkt[scapy.all.IP].src if scapy.all.IP in pkt else None,
            'dst': pkt[scapy.all.IP].dst if scapy.all.IP in pkt else None,
            'protocol': pkt.name
        } for pkt in packets]
    except ImportError:
        return [{'error': 'Scapy not installed. Install with: pip install scapy'}]
    except PermissionError:
        return [{'error': 'Root/admin privileges required for packet sniffing'}]
    except Exception as e:
        return [{'error': str(e)}]

def url_extractor(page_url: str) -> List[str]:
    """
    16. URL Extractor
    Extracts URLs from a webpage.
    
    Args:
        page_url (str): The URL to scrape.
    
    Returns:
        List[str]: List of extracted URLs or error message.
    """
    try:
        response = requests.get(page_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        return [urljoin(page_url, a['href']) for a in soup.find_all('a', href=True)]
    except Exception as e:
        return [f'Error: {str(e)}']

def mac_spoofing_detector() -> Dict[str, List[str]]:
    """
    17. MAC Spoofing Detector
    Detects potential MAC address spoofing via ARP table analysis.
    
    Returns:
        Dict[str, List[str]]: MAC addresses with multiple IPs or error message.
    """
    try:
        cmd = 'arp -a' if platform.system().lower() == 'windows' else 'arp -an'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        arp_table = result.stdout.splitlines()
        
        mac_ip_map = {}
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        mac_pattern = r'([0-9a-fA-F:]{17}|[0-9a-fA-F-]{12,17})'
        
        for line in arp_table:
            ip_match = re.search(ip_pattern, line)
            mac_match = re.search(mac_pattern, line)
            if ip_match and mac_match:
                ip, mac = ip_match.group(), mac_match.group()
                mac_ip_map.setdefault(mac, []).append(ip)
        
        return {mac: ips for mac, ips in mac_ip_map.items() if len(ips) > 1}
    except Exception as e:
        return {'error': str(e)}

def list_connected_devices(subnet: str = "192.168.1.0/24") -> List[Dict]:
    """
    18. Connected Devices Lister
    Lists devices on the network using ARP (requires scapy and root privileges).
    WARNING: Use only on networks you have permission to scan.
    
    Args:
        subnet (str): Subnet to scan (default: "192.168.1.0/24").
    
    Returns:
        List[Dict]: List of devices with IPs and MACs or error message.
    """
    try:
        from scapy.all import ARP, Ether, srp
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        return [{'ip': received.psrc, 'mac': received.hwsrc} 
                for sent, received in result]
    except ImportError:
        return [{'error': 'Scapy not installed. Install with: pip install scapy'}]
    except PermissionError:
        return [{'error': 'Root/admin privileges required for ARP scanning'}]
    except Exception as e:
        return [{'error': str(e)}]

def dns_resolver(domain: str, record_type: str = 'A') -> Union[str, List[str]]:
    """
    19. DNS Resolver
    Resolves DNS records for a domain.
    
    Args:
        domain (str): The domain to resolve.
        record_type (str): DNS record type ('A', 'MX', 'NS', 'TXT', default: 'A').
    
    Returns:
        Union[str, List[str]]: Resolved records or error message.
    """
    try:
        if record_type.upper() == 'A':
            return socket.gethostbyname(domain)
        elif record_type.upper() in ['MX', 'NS', 'TXT']:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, record_type)
                return [str(r) for r in answers]
            except ImportError:
                return "dnspython not installed. Install with: pip install dnspython"
        return "Unsupported record type"
    except Exception as e:
        return str(e)

def ssl_certificate_checker(hostname: str, port: int = 443) -> Dict:
    """
    20. SSL Certificate Checker
    Checks SSL certificate details for a host.
    
    Args:
        hostname (str): The hostname to check.
        port (int): Port number (default: 443).
    
    Returns:
        Dict: Certificate details or error message.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days
                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'expires': cert['notAfter'],
                    'days_left': days_left,
                    'valid': days_left > 0
                }
    except Exception as e:
        return {'error': str(e)}

def https_checker(domain: str) -> Dict:
    """
    21. HTTPS Checker
    Checks if a domain enforces HTTPS.
    
    Args:
        domain (str): The domain to check.
    
    Returns:
        Dict: HTTPS status or error message.
    """
    try:
        http_url = f"http://{domain}"
        response = requests.get(http_url, allow_redirects=True, timeout=5)
        return {
            'enforces_https': response.url.startswith('https://'),
            'final_url': response.url,
            'redirects': len(response.history)
        }
    except Exception as e:
        return {'error': str(e)}

# ========================
# WEB SECURITY TOOLS (22-30)
# ========================

def sql_injection_scanner(url: str, param: str, method: str = "GET") -> Dict:
    """
    22. SQL Injection Scanner
    Tests a URL parameter for SQL injection vulnerabilities.
    WARNING: Use only on systems you have permission to test.
    
    Args:
        url (str): The URL to test.
        param (str): The parameter to test.
        method (str): HTTP method ('GET' or 'POST', default: 'GET').
    
    Returns:
        Dict: Test results or error message.
    """
    payloads = [
        "' OR '1'='1",  # Basic tautology
        "' OR SLEEP(5)--",  # Time-based
        "' UNION SELECT NULL, NULL--",  # Union-based
        "1; DROP TABLE users--"  # Destructive (use with caution)
    ]
    results = []
    for payload in payloads:
        try:
            start_time = time.time()
            if method.upper() == "GET":
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=10)
            else:
                response = requests.post(url, data={param: payload}, timeout=10)
            
            time_taken = time.time() - start_time
            vulnerable = (
                any(indicator in response.text.lower() for indicator in ['sql', 'syntax', 'database']) or
                time_taken > 5
            )
            results.append({
                'payload': payload,
                'vulnerable': vulnerable,
                'status': response.status_code,
                'response_time': time_taken
            })
        except requests.RequestException:
            results.append({
                'payload': payload,
                'vulnerable': False,
                'status': None,
                'response_time': 0
            })
    return {'tests': results, 'vulnerable': any(r['vulnerable'] for r in results)}

def xss_sanitizer(input_str: str) -> str:
    """
    23. XSS Sanitizer
    Sanitizes input to prevent XSS attacks by escaping HTML characters.
    
    Args:
        input_str (str): The input string to sanitize.
    
    Returns:
        str: The sanitized string.
    """
    return html.escape(input_str)

def extract_web_metadata(url: str) -> Dict:
    """
    24. Metadata Extractor (Web)
    Extracts metadata from a webpage's headers.
    
    Args:
        url (str): The URL to query.
    
    Returns:
        Dict: Metadata or error message.
    """
    try:
        response = requests.get(url, timeout=5)
        headers = dict(response.headers)
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        return {
            'server': server,
            'powered_by': powered_by,
            'headers': headers
        }
    except Exception as e:
        return {'error': str(e)}

def clickjacking_detector(url: str) -> Dict:
    """
    25. Clickjacking Detector
    Checks for clickjacking protection headers.
    
    Args:
        url (str): The URL to check.
    
    Returns:
        Dict: Protection status or error message.
    """
    headers = http_header_extractor(url)
    if 'error' in headers:
        return headers
    
    protection = {
        'x-frame-options': headers.get('X-Frame-Options', 'missing'),
        'csp_frame_ancestors': 'frame-ancestors' in headers.get('Content-Security-Policy', '').lower(),
        'vulnerable': not (headers.get('X-Frame-Options') or 
                      'frame-ancestors' in headers.get('Content-Security-Policy', '').lower())
    }
    return protection

def brute_force_cracker(target_hash: str, wordlist: str, max_attempts: int = 10000) -> Optional[str]:
    """
    26. Brute-force Cracker
    Attempts to crack a SHA-256 hash using a wordlist.
    WARNING: Use only with permission. Unauthorized password cracking is illegal.
    
    Args:
        target_hash (str): The hash to crack.
        wordlist (str): Path to the wordlist file.
        max_attempts (int): Maximum attempts (default: 10000).
    
    Returns:
        Optional[str]: The cracked password or None.
    """
    if not os.path.isfile(wordlist):
        return None
    try:
        with open(wordlist, 'r') as f:
            for i, line in enumerate(f):
                if i >= max_attempts:
                    return None
                password = line.strip()
                if hashlib.sha256(password.encode()).hexdigest() == target_hash:
                    return password
    except Exception:
        pass
    return None

def check_security_headers(url: str) -> Dict:
    """
    27. Missing Security Headers Detector
    Checks for missing security headers.
    
    Args:
        url (str): The URL to check.
    
    Returns:
        Dict: Missing headers or status.
    """
    required_headers = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Strict-Transport-Security'
    ]
    headers = http_header_extractor(url)
    if 'error' in headers:
        return headers
    
    missing = [h for h in required_headers if h not in headers]
    return {'missing': missing} if missing else {'status': 'all_secure'}

def exposed_directory_checker(base_url: str) -> List[Dict]:
    """
    28. Exposed Directory Checker
    Checks for exposed directories.
    
    Args:
        base_url (str): The base URL to check.
    
    Returns:
        List[Dict]: Directory status results.
    """
    common_dirs = [
        'admin', 'backup', 'config', 'logs',
        'phpmyadmin', 'wp-admin', 'database'
    ]
    results = []
    for directory in common_dirs:
        url = f"{base_url.rstrip('/')}/{directory}/"
        try:
            response = requests.get(url, timeout=3)
            results.append({
                'url': url,
                'status': response.status_code,
                'exposed': response.status_code == 200
            })
        except requests.RequestException:
            continue
    return results

def broken_link_crawler(start_url: str, max_pages: int = 10, max_depth: int = 3) -> List[Dict]:
    """
    29. Broken Link Crawler
    Crawls a website to find broken links.
    
    Args:
        start_url (str): The starting URL.
        max_pages (int): Maximum pages to crawl (default: 10).
        max_depth (int): Maximum recursion depth (default: 3).
    
    Returns:
        List[Dict]: List of broken links.
    """
    visited = set()
    broken_links = []
    
    def crawl(url, depth=0):
        if depth > max_depth or len(visited) >= max_pages or url in visited:
            return
        visited.add(url)
        
        try:
            response = requests.get(url, timeout=5)
            time.sleep(0.5)
            if response.status_code == 404:
                broken_links.append({'url': url, 'status': 404})
            
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = urljoin(url, link['href'])
                if href.startswith('http') and href not in visited:
                    crawl(href, depth + 1)
        except requests.RequestException:
            pass
    
    crawl(start_url)
    return broken_links

def input_validator(input_str: str) -> Dict:
    """
    30. Input Validator
    Validates input for potential SQL injection or XSS patterns.
    
    Args:
        input_str (str): The input string to validate.
    
    Returns:
        Dict: Validation results.
    """
    sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union']
    xss_patterns = ['<script>', 'javascript:', 'onerror=']
    
    return {
        'length': len(input_str),
        'contains_sql': any(keyword in input_str.lower() for keyword in sql_keywords),
        'contains_xss': any(pattern in input_str.lower() for pattern in xss_patterns),
        'is_safe': not any(
            keyword in input_str.lower() for keyword in sql_keywords + xss_patterns
        )
    }

# ===========================
# FILE SYSTEM SECURITY (31-46)
# ===========================

def detect_suspicious_extensions(directory: str) -> List[str]:
    """
    31. Suspicious File Extensions Detector
    Detects files with suspicious extensions.
    
    Args:
        directory (str): The directory to scan.
    
    Returns:
        List[str]: List of suspicious file paths.
    """
    suspicious = ['.exe', '.bat', '.scr', '.dll', '.ps1', '.sh']
    found = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                if any(file.lower().endswith(ext) for ext in suspicious):
                    found.append(os.path.join(root, file))
    except Exception as e:
        logging.error(f"Suspicious extensions detection failed: {str(e)}")
    return found

def find_executable_files(directory: str) -> List[str]:
    """
    32. Executable Scanner
    Finds executable files in a directory.
    
    Args:
        directory (str): The directory to scan.
    
    Returns:
        List[str]: List of executable file paths.
    """
    executables = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                if os.access(path, os.X_OK):
                    executables.append(path)
    except Exception as e:
        logging.error(f"Executable scan failed: {str(e)}")
    return executables

def extract_strings_from_file(file_path: str, min_len: int = 4) -> List[str]:
    """
    33. String Extractor from Files
    Extracts printable strings from a file.
    
    Args:
        file_path (str): The file to process.
        min_len (int): Minimum string length (default: 4).
    
    Returns:
        List[str]: Extracted strings.
    """
    if not os.path.isfile(file_path):
        return []
    try:
        with open(file_path, 'rb') as f:
            result = []
            current = []
            for byte in f.read():
                if 32 <= byte <= 126:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        result.append(''.join(current))
                    current = []
            if current and len(current) >= min_len:
                result.append(''.join(current))
            return result
    except Exception as e:
        logging.error(f"String extraction failed: {str(e)}")
        return []

def compare_hashes(file_path: str, known_hashes: List[str]) -> Dict:
    """
    34. Hash Signature Comparator
    Compares a file's SHA-256 hash with known hashes.
    
    Args:
        file_path (str): The file to hash.
        known_hashes (List[str]): List of known hashes.
    
    Returns:
        Dict: Comparison results or error message.
    """
    if not os.path.isfile(file_path):
        return {'error': f'File {file_path} does not exist'}
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return {
            'file_hash': file_hash,
            'matches': file_hash in known_hashes,
            'known_hashes': known_hashes
        }
    except Exception as e:
        return {'error': f'Hash comparison failed: {str(e)}'}

def detect_keylogger_patterns(file_path: str) -> List[str]:
    """
    35. Keylogger Detector
    Detects keylogger patterns in a file.
    
    Args:
        file_path (str): The file to scan.
    
    Returns:
        List[str]: Detected patterns.
    """
    patterns = [
        r'keyboard\.hook',
        r'keylog',
        r'keystroke',
        r'GetAsyncKeyState',
        r'SetWindowsHookEx'
    ]
    matches = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    matches.append(pattern)
    except Exception as e:
        logging.error(f"Keylogger detection failed: {str(e)}")
    return matches

def detect_obfuscated_code(file_path: str) -> Dict:
    """
    36. Obfuscated Code Scanner
    Detects obfuscated code patterns in a file.
    
    Args:
        file_path (str): The file to scan.
    
    Returns:
        Dict: Detected patterns.
    """
    indicators = {
        'base64': r'base64\.b64decode',
        'exec': r'exec\(',
        'eval': r'eval\(',
        'hex': r'\\x[0-9a-f]{2}',
        'long_strings': r'\"\"\".*?\"\"\"|\'\'\'.*?\'\'\''
    }
    results = {}
    if not os.path.isfile(file_path):
        return {'error': f'File {file_path} does not exist'}
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for name, pattern in indicators.items():
                results[name] = bool(re.search(pattern, content))
    except Exception as e:
        logging.error(f"Obfuscated code scan failed: {str(e)}")
    return results

def check_malware_hashes(file_path: str, hash_db: List[str]) -> Union[bool, Dict[str, str]]:
    """
    37. Malware Sample Checker
    Checks if a file's SHA-256 hash matches known malware hashes.
    
    Args:
        file_path (str): The file to check.
        hash_db (List[str]): List of known malware hashes.
    
    Returns:
        Union[bool, Dict[str, str]]: True if match found, False otherwise, or error message.
    """
    if not os.path.isfile(file_path):
        return {'error': f'File {file_path} does not exist'}
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash in hash_db
    except Exception as e:
        return {'error': f'Malware hash check failed: {str(e)}'}

def find_suspicious_processes() -> List[Dict]:
    """
    38. Suspicious Process Monitor
    Detects suspicious processes (e.g., no executable path).
    
    Returns:
        List[Dict]: List of suspicious processes.
    """
    suspicious = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if not proc.info['exe'] or not os.path.exists(proc.info['exe']):
                    suspicious.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'reason': 'No executable path'
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logging.error(f"Suspicious process monitor failed: {str(e)}")
    return suspicious

def check_file_permissions(directory: str) -> List[Dict]:
    """
    39. Unusual File Permission Detector
    Detects files with unusual permissions (e.g., world-writable).
    
    Args:
        directory (str): The directory to scan.
    
    Returns:
        List[Dict]: List of files with unusual permissions.
    """
    unusual = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                try:
                    mode = os.stat(path).st_mode
                    if mode & 0o777 == 0o777:
                        unusual.append({
                            'path': path,
                            'permissions': oct(mode)[-3:],
                            'issue': 'World writable'
                        })
                except Exception:
                    continue
    except Exception as e:
        logging.error(f"File permission check failed: {str(e)}")
    return unusual

def extract_image_metadata(image_path: str) -> Dict:
    """
    40. Image Metadata Extractor
    Extracts metadata from an image file.
    
    Args:
        image_path (str): The image file path.
    
    Returns:
        Dict: Image metadata or error message.
    """
    if not os.path.isfile(image_path):
        return {'error': f'Image {image_path} does not exist'}
    try:
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f)
            return {str(k): str(v) for k, v in tags.items() 
                   if k not in ('JPEGThumbnail', 'TIFFThumbnail')}
    except Exception as e:
        return {'error': str(e)}

def detect_hardcoded_credentials(file_path: str) -> List[str]:
    """
    41. Hardcoded Credentials Detector
    Detects hardcoded credentials in a file.
    
    Args:
        file_path (str): The file to scan.
    
    Returns:
        List[str]: Detected credential patterns.
    """
    patterns = [
        r'password\s*=\s*[\'"][^\'"]+[\'"]',
        r'api_?key\s*=\s*[\'"][^\'"]+[\'"]',
        r'secret_?key\s*=\s*[\'"][^\'"]+[\'"]',
        r'database_?url\s*=\s*[\'"][^\'"]+[\'"]',
        r'"password"\s*:\s*"[^"]+"',
        r'password\s*:\s*[^\s]+',
        r'PASSWORD\s*=\s*[^\s]+'
    ]
    matches = []
    if not os.path.isfile(file_path):
        return []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                matches.extend(re.findall(pattern, content, re.IGNORECASE))
    except Exception as e:
        logging.error(f"Hardcoded credentials detection failed: {str(e)}")
    return matches

def redact_sensitive_data(text: str) -> str:
    """
    42. Sensitive Data Remover
    Redacts sensitive data (e.g., emails, credit cards, SSNs) from text.
    
    Args:
        text (str): The input text.
    
    Returns:
        str: Redacted text.
    """
    try:
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                     '[REDACTED_EMAIL]', text)
        text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CC]', text)
        text = re.sub(r'\b\d{3}[ -]?\d{2}[ -]?\d{4}\b', '[REDACTED_SSN]', text)
        return text
    except Exception as e:
        logging.error(f"Sensitive data redaction failed: {str(e)}")
        return text

def recommend_file_permissions(file_path: str) -> Dict:
    """
    43. File Permission Advisor
    Recommends file permissions based on file type.
    
    Args:
        file_path (str): The file to check.
    
    Returns:
        Dict: Current and recommended permissions or error message.
    """
    if not os.path.isfile(file_path):
        return {'error': f'File {file_path} does not exist'}
    try:
        current = oct(os.stat(file_path).st_mode)[-3:]
        if file_path.endswith(('.pem', '.key', '.env')):
            recommended = '600'
        elif file_path.endswith(('.py', '.sh', '.php')):
            recommended = '644'
        else:
            recommended = '640'
        return {
            'current': current,
            'recommended': recommended,
            'action_needed': current != recommended
        }
    except Exception as e:
        return {'error': f'Permission check failed: {str(e)}'}

def monitor_file_changes(file_path: str, known_hash: str) -> Dict:
    """
    44. File Tampering Detector
    Detects changes to a file by comparing its SHA-256 hash.
    
    Args:
        file_path (str): The file to monitor.
        known_hash (str): The known hash.
    
    Returns:
        Dict: Change detection results or error message.
    """
    if not os.path.isfile(file_path):
        return {'error': f'File {file_path} does not exist'}
    try:
        with open(file_path, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        return {
            'changed': current_hash != known_hash,
            'current_hash': current_hash,
            'known_hash': known_hash
        }
    except Exception as e:
        return {'error': f'Failed to read file: {str(e)}'}

def encrypt_file(file_path: str, output_path: str, key: bytes) -> Union[bool, Dict[str, str]]:
    """
    45. Secure Text File Encryptor
    Encrypts a file using Fernet.
    
    Args:
        file_path (str): The input file path.
        output_path (str): The output file path.
        key (bytes): The Fernet key.
    
    Returns:
        Union[bool, Dict[str, str]]: True if successful, error message otherwise.
    """
    if not os.path.isfile(file_path):
        return {'error': f'Input file {file_path} does not exist'}
    try:
        Fernet(key)
        fernet = Fernet(key)
        with open(file_path, 'rb') as f:
            encrypted = fernet.encrypt(f.read())
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        return True
    except Exception as e:
        return {'error': f'Encryption failed: {str(e)}'}

def detect_plaintext_passwords(file_path: str) -> List[str]:
    """
    46. Unsecure Password Storage Detector
    Detects plaintext password storage in a file.
    
    Args:
        file_path (str): The file to scan.
    
    Returns:
        List[str]: Detected password patterns.
    """
    patterns = [
        r'password\s*=\s*[\'"][^\'"]+[\'"]',
        r'passwd\s*=\s*[\'"][^\'"]+[\'"]',
        r'pwd\s*=\s*[\'"][^\'"]+[\'"]',
        r'"password"\s*:\s*"[^"]+"',
        r'password\s*:\s*[^\s]+',
        r'PASSWORD\s*=\s*[^\s]+'
    ]
    matches = []
    if not os.path.isfile(file_path):
        return []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                matches.extend(re.findall(pattern, content, re.IGNORECASE))
    except Exception as e:
        logging.error(f"Plaintext password detection failed: {str(e)}")
    return matches

# ========================
# SYSTEM SECURITY (47-54)
# ========================

def simple_auth_system(username: str, password: str, storage_file: str = 'auth.json') -> Dict:
    """
    47. User Authentication System
    Authenticates or registers a user with bcrypt hashing.
    
    Args:
        username (str): The username.
        password (str): The password.
        storage_file (str): Storage file for credentials (default: 'auth.json').
    
    Returns:
        Dict: Authentication or registration status.
    """
    try:
        if os.path.exists(storage_file):
            with open(storage_file, 'r') as f:
                users = json.load(f)
        else:
            users = {}
        
        if username in users:
            if bcrypt.checkpw(password.encode(), users[username].encode()):
                return {'authenticated': True}
            return {'authenticated': False, 'error': 'Invalid password'}
        
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        users[username] = hashed
        with open(storage_file, 'w') as f:
            json.dump(users, f)
        return {'registered': True}
    except Exception as e:
        return {'error': str(e)}

def check_password_breach(password: str) -> Dict:
    """
    48. Password Breach Checker
    Checks if a password has been breached using HIBP API (k-anonymity).
    
    Args:
        password (str): The password to check.
    
    Returns:
        Dict: Breach status or error message.
    """
    try:
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        if response.status_code != 200:
            return {'error': 'Failed to query HIBP API'}
        
        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return {
                    'breached': True,
                    'count': int(count),
                    'message': f'Password found in {count} breaches'
                }
        return {'breached': False, 'message': 'Password not found in breaches'}
    except Exception as e:
        return {'error': f'Failed to check breach: {str(e)}'}

def analyze_logs(log_file: str) -> Dict:
    """
    49. Suspicious Log Analyzer
    Analyzes logs for suspicious patterns.
    
    Args:
        log_file (str): The log file to analyze.
    
    Returns:
        Dict: Analysis results.
    """
    suspicious_patterns = {
        'failed_login': r'Failed login|Authentication failure',
        'brute_force': r'Too many failed attempts',
        'sql_attempt': r'SQL syntax|SQL command',
        'xss_attempt': r'<script>|javascript:'
    }
    results = {k: 0 for k in suspicious_patterns}
    if not os.path.isfile(log_file):
        return {'error': f'Log file {log_file} does not exist'}
    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                for pattern_name, pattern in suspicious_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        results[pattern_name] += 1
    except Exception as e:
        logging.error(f"Log analysis failed: {str(e)}")
    return results

def detect_insecure_patterns(code_path: str) -> Dict:
    """
    50. Insecure Coding Pattern Detector
    Detects insecure coding patterns in a directory.
    
    Args:
        code_path (str): The directory to scan.
    
    Returns:
        Dict: Detected patterns.
    """
    patterns = {
        'eval': r'eval\(',
        'exec': r'exec\(',
        'shell_true': r'shell=True',
        'hardcoded_secrets': r'password\s*=\s*[\'"][^\'"]+[\'"]|api_?key\s*=\s*[\'"][^\'"]+[\'"]',
        'sql_concat': r'SELECT\s+.+\s+\+\s+.+FROM'
    }
    results = {k: [] for k in patterns}
    try:
        for root, _, files in os.walk(code_path):
            for file in files:
                if file.endswith('.py'):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', errors='ignore') as f:
                            content = f.read()
                            for pattern_name, pattern in patterns.items():
                                if re.search(pattern, content, re.IGNORECASE):
                                    results[pattern_name].append(file)
                    except Exception:
                        continue
    except Exception as e:
        logging.error(f"Insecure pattern detection failed: {str(e)}")
    return results

def steganography_encode(image_path: str, message: str, output_path: str) -> Union[bool, Dict[str, str]]:
    """
    51. Steganography Encoder
    Encodes a message into an image using LSB steganography.
    
    Args:
        image_path (str): The input image path.
        message (str): The message to encode.
        output_path (str): The output image path.
    
    Returns:
        Union[bool, Dict[str, str]]: True if successful, error message otherwise.
    """
    if not os.path.isfile(image_path):
        return {'error': f'Image {image_path} does not exist'}
    try:
        img = Image.open(image_path).convert('RGB')
        binary_msg = ''.join(format(ord(c), '08b') for c in message) + '1111111111111110'
        
        if len(binary_msg) > img.width * img.height * 3:
            return {'error': 'Message too large for image'}
        
        pixels = img.load()
        msg_index = 0
        for i in range(img.width):
            for j in range(img.height):
                r, g, b = pixels[i, j]
                if msg_index < len(binary_msg):
                    r = (r & 0xFE) | int(binary_msg[msg_index])
                    msg_index += 1
                if msg_index < len(binary_msg):
                    g = (g & 0xFE) | int(binary_msg[msg_index])
                    msg_index += 1
                if msg_index < len(binary_msg):
                    b = (b & 0xFE) | int(binary_msg[msg_index])
                    msg_index += 1
                pixels[i, j] = (r, g, b)
        
        img.save(output_path)
        return True
    except Exception as e:
        return {'error': f'Steganography encoding failed: {str(e)}'}

def steganography_decode(image_path: str) -> Union[str, Dict[str, str]]:
    """
    51b. Steganography Decoder
    Decodes a message from an image using LSB steganography.
    
    Args:
        image_path (str): The image file path.
    
    Returns:
        Union[str, Dict[str, str]]: The decoded message or error message.
    """
    if not os.path.isfile(image_path):
        return {'error': f'Image {image_path} does not exist'}
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = img.load()
        binary_msg = []
        for i in range(img.width):
            for j in range(img.height):
                r, g, b = pixels[i, j]
                binary_msg.append(str(r & 1))
                binary_msg.append(str(g & 1))
                binary_msg.append(str(b & 1))
        
        binary_str = ''.join(binary_msg)
        end_marker = '1111111111111110'
        if end_marker in binary_str:
            binary_str = binary_str[:binary_str.index(end_marker)]
        
        message = ''
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        return message if message else {'error': 'No message found'}
    except Exception as e:
        return {'error': f'Steganography decoding failed: {str(e)}'}

def check_spam_domain(email: str) -> Union[bool, Dict[str, str]]:
    """
    52. Spam Domain Email Validator
    Checks if an email domain is associated with spam.
    
    Args:
        email (str): The email address to check.
    
    Returns:
        Union[bool, Dict[str, str]]: True if spam domain, False otherwise, or error message.
    """
    try:
        spam_domains = [
            'mail.ru', 'yandex.ru', 'qq.com',
            '163.com', '126.com', 'list.ru'
        ]
        domain = email.split('@')[-1].lower() if '@' in email else ''
        if not domain:
            return {'error': 'Invalid email format'}
        return domain in spam_domains
    except Exception as e:
        return {'error': f'Spam domain check failed: {str(e)}'}

def detect_access_anomalies(log_file: str, threshold: int = 10) -> Dict:
    """
    53. Access Pattern Anomaly Detector
    Detects anomalous access patterns in a log file.
    
    Args:
        log_file (str): The log file to analyze.
        threshold (int): Threshold for anomaly detection (default: 10).
    
    Returns:
        Dict: Anomaly detection results or error message.
    """
    ip_counts = {}
    if not os.path.isfile(log_file):
        return {'error': f'Log file {log_file} does not exist'}
    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    ip = ip_match.group()
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except Exception as e:
        logging.error(f"Access anomaly detection failed: {str(e)}")
    
    anomalies = {ip: count for ip, count in ip_counts.items() if count > threshold}
    return {
        'total_ips': len(ip_counts),
        'anomalous_ips': anomalies,
        'threshold': threshold
    }

def check_outdated_packages() -> List[Dict]:
    """
    54. Software Update Checker
    Checks for outdated pip packages.
    
    Returns:
        List[Dict]: List of outdated packages.
    """
    try:
        result = subprocess.run(['pip', 'list', '--outdated'], 
                              capture_output=True, text=True)
        packages = []
        for line in result.stdout.split('\n')[2:]:
            if line:
                parts = line.split()
                packages.append({
                    'package': parts[0],
                    'current': parts[1],
                    'latest': parts[2]
                })
        return packages
    except Exception as e:
        logging.error(f"Outdated package check failed: {str(e)}")
        return []

# ===========================
# UNIT TESTS
# ===========================

class TestCybersecurityToolkit(unittest.TestCase):
    def test_caesar_cipher(self):
        self.assertEqual(caesar_cipher("Hello", 3, "encrypt"), "Khoor")
        self.assertEqual(caesar_cipher("Khoor", 3, "decrypt"), "Hello")
    
    def test_base64_encode_decode(self):
        encoded = base64_encode_decode("test", "encode")
        self.assertEqual(base64_encode_decode(encoded, "decode"), "test")
    
    def test_sha256_hash(self):
        self.assertEqual(
            sha256_hash("test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
    
    def test_xor_cipher(self):
        encoded = xor_cipher("Hello", 42, "encode")
        self.assertEqual(xor_cipher(encoded, 42, "decode"), "Hello")
    
    def test_password_strength(self):
        result = check_password_strength("password123")
        self.assertIn('score', result)
        self.assertLessEqual(result['score'], 4)

def main():
    """
    Main menu interface for the Cybersecurity Toolkit
    Organizes tools by category and handles user input.
    """
    logging.info("Starting Cybersecurity Toolkit")
    categories = {
        "Cryptography & Encryption": [
            ("1. Caesar Cipher", caesar_cipher),
            ("2. Base64 Encode/Decode", base64_encode_decode),
            ("3. SHA-256 Hash Generator", sha256_hash),
            ("4. Password Strength Checker", check_password_strength),
            ("5. File Integrity Verifier", verify_file_integrity),
            ("6. XOR Cipher", xor_cipher),
            ("7. Substitution Cipher", substitution_cipher),
        ],
        "Password Security": [
            ("8. Hash Password (hashlib)", hash_password),
            ("9. Salted Hash with bcrypt", bcrypt_hash),
            ("10. Random Password Generator", generate_password),
        ],
        "Network Security": [
            ("11. Port Scanner", port_scanner),
            ("12. HTTP Header Extractor", http_header_extractor),
            ("13. IP Type Checker", ip_type_checker),
            ("14. Ping Tool", ping_host),
            ("15. Packet Sniffer", packet_sniffer),
            ("16. URL Extractor", url_extractor),
            ("17. MAC Spoofing Detector", mac_spoofing_detector),
            ("18. Connected Devices Lister", list_connected_devices),
            ("19. DNS Resolver", dns_resolver),
            ("20. SSL Certificate Checker", ssl_certificate_checker),
            ("21. HTTPS Checker", https_checker),
        ],
        "Web Security": [
            ("22. SQL Injection Scanner", sql_injection_scanner),
            ("23. XSS Sanitizer", xss_sanitizer),
            ("24. Metadata Extractor (Web)", extract_web_metadata),
            ("25. Clickjacking Detector", clickjacking_detector),
            ("26. Brute-force Cracker", brute_force_cracker),
            ("27. Missing Security Headers Detector", check_security_headers),
            ("28. Exposed Directory Checker", exposed_directory_checker),
            ("29. Broken Link Crawler", broken_link_crawler),
            ("30. Input Validator", input_validator),
        ],
        "File System Security": [
            ("31. Suspicious File Extensions Detector", detect_suspicious_extensions),
            ("32. Executable Scanner", find_executable_files),
            ("33. String Extractor from Files", extract_strings_from_file),
            ("34. Hash Signature Comparator", compare_hashes),
            ("35. Keylogger Detector", detect_keylogger_patterns),
            ("36. Obfuscated Code Scanner", detect_obfuscated_code),
            ("37. Malware Sample Checker", check_malware_hashes),
            ("38. Suspicious Process Monitor", find_suspicious_processes),
            ("39. Unusual File Permission Detector", check_file_permissions),
            ("40. Image Metadata Extractor", extract_image_metadata),
            ("41. Hardcoded Credentials Detector", detect_hardcoded_credentials),
            ("42. Sensitive Data Remover", redact_sensitive_data),
            ("43. File Permission Advisor", recommend_file_permissions),
            ("44. File Tampering Detector", monitor_file_changes),
            ("45. Secure Text File Encryptor", encrypt_file),
            ("46. Unsecure Password Storage Detector", detect_plaintext_passwords),
        ],
        "System Security": [
            ("47. User Authentication System", simple_auth_system),
            ("48. Password Breach Checker", check_password_breach),
            ("49. Suspicious Log Analyzer", analyze_logs),
            ("50. Insecure Coding Pattern Detector", detect_insecure_patterns),
            ("51. Steganography Encoder", steganography_encode),
            ("51b. Steganography Decoder", steganography_decode),  # Added decoder as separate option
            ("52. Spam Domain Email Validator", check_spam_domain),
            ("53. Access Pattern Anomaly Detector", detect_access_anomalies),
            ("54. Software Update Checker", check_outdated_packages),
        ]
    }

    while True:
        print("\n" + "="*50)
        print("CYBERSECURITY TOOLKIT - ALL 54 TOOLS".center(50))
        print("="*50)
        
        tool_count = 1
        for category, tools in categories.items():
            print(f"\n{category}:")
            for i in range(0, len(tools), 2):
                row = [f"{tools[i+j][0]:<35}" for j in range(2) if i+j < len(tools)]
                print(" ".join(row))
        
        print("\n0. Exit Program")
        print("99. Run quick test (SHA256, Password Gen, Base64, XOR)")
        
        choice = input("\nEnter tool number (0 to exit): ").strip()

        if choice == "0":
            print("Exiting Cybersecurity Toolkit. Goodbye!")
            logging.info("Exiting Cybersecurity Toolkit")
            break
        elif choice == "99":
            print("\nRunning quick tests...")
            print("SHA-256 of 'test':", sha256_hash("test"))
            print("Random password:", generate_password())
            print("Base64 encoded 'hello':", base64_encode_decode("hello", "encode"))
            print("Caesar Cipher 'hello' (shift 3):", caesar_cipher("hello", 3))
            print("XOR Cipher 'hello' (key 42):", xor_cipher("hello", 42, "encode"))
            print("Password strength for 'password123':", check_password_strength("password123")['score'])
            input("\nPress Enter to continue...")
            continue

        try:
            choice = int(choice)
            flat_tools = [tool for cat in categories.values() for tool in cat]
            if not 1 <= choice <= len(flat_tools):
                print("Invalid tool number. Please select a number between 1 and", len(flat_tools))
                input("\nPress Enter to continue...")
                continue
        except ValueError:
            print("Invalid input. Please enter a number.")
            input("\nPress Enter to continue...")
            continue

        selected_func = flat_tools[choice-1][1]
        tool_name = flat_tools[choice-1][0].split(". ")[1]
        
        if selected_func in [port_scanner, sql_injection_scanner, brute_force_cracker, packet_sniffer, list_connected_devices]:
            print("WARNING: This tool should only be used on systems you have permission to test.")
            if input("Continue? (y/n): ").lower() != 'y':
                continue
        
        try:
            print(f"\nRunning {tool_name}...")
            logging.info(f"Running tool: {tool_name}")
            params = []

            # Parameter collection for each function
            if selected_func == caesar_cipher:
                params.append(input("Enter text: ").strip())
                shift = input("Enter shift value (integer): ").strip()
                try:
                    params.append(int(shift))
                except ValueError:
                    print("Error: Shift must be an integer")
                    continue
                mode = input("Encrypt or decrypt? (e/d): ").lower().strip()
                params.append('encrypt' if mode == 'e' else 'decrypt')

            elif selected_func == base64_encode_decode:
                params.append(input("Enter text: ").strip())
                mode = input("Encode or decode? (e/d): ").lower().strip()
                params.append('encode' if mode == 'e' else 'decode')

            elif selected_func == sha256_hash:
                params.append(input("Enter text to hash: ").strip())

            elif selected_func == check_password_strength:
                params.append(input("Enter password to check: ").strip())

            elif selected_func == verify_file_integrity:
                params.append(input("Enter file path: ").strip())
                params.append(input("Enter known SHA-256 hash: ").strip())

            elif selected_func == xor_cipher:
                params.append(input("Enter text: ").strip())
                key = input("Enter XOR key (integer): ").strip()
                try:
                    params.append(int(key))
                except ValueError:
                    print("Error: Key must be an integer")
                    continue
                mode = input("Encode or decode? (e/d): ").lower().strip()
                params.append('encode' if mode == 'e' else 'decode')

            elif selected_func == substitution_cipher:
                params.append(input("Enter text: ").strip())
                use_custom = input("Use custom substitution map? (y/n): ").lower().strip() == 'y'
                if use_custom:
                    custom_map = {}
                    print("Enter substitution map (e.g., 'a:b, c:d') or leave blank for random:")
                    mapping = input().strip()
                    if mapping:
                        try:
                            for pair in mapping.split(','):
                                k, v = pair.strip().split(':')
                                custom_map[k.strip()] = v.strip()
                            params.append(custom_map)
                        except ValueError:
                            print("Error: Invalid map format. Use 'a:b, c:d'.")
                            continue
                    else:
                        params.append(None)
                else:
                    params.append(None)

            elif selected_func == hash_password:
                params.append(input("Enter password to hash: ").strip())
                algo = input("Algorithm (sha256/sha512, default sha256): ").lower().strip() or 'sha256'
                params.append(algo)

            elif selected_func == bcrypt_hash:
                params.append(input("Enter password to hash: ").strip())
                rounds = input("Number of rounds (default 12): ").strip()
                params.append(int(rounds) if rounds and rounds.isdigit() else 12)

            elif selected_func == generate_password:
                length = input("Enter password length (default 16): ").strip()
                params.append(int(length) if length and length.isdigit() else 16)
                special = input("Include special characters? (y/n): ").lower().strip() == 'y'
                params.append(special)

            elif selected_func == port_scanner:
                params.append(input("Enter target IP or hostname: ").strip())
                ports = input("Enter ports to scan (comma separated, e.g., 80,443): ").strip()
                try:
                    params.append([int(p.strip()) for p in ports.split(',') if p.strip()])
                except ValueError:
                    print("Error: Ports must be integers")
                    continue

            elif selected_func == http_header_extractor:
                params.append(input("Enter URL (e.g., https://example.com): ").strip())

            elif selected_func == ip_type_checker:
                params.append(input("Enter IP address: ").strip())

            elif selected_func == ping_host:
                params.append(input("Enter host to ping: ").strip())
                count = input("Number of pings (default 4): ").strip()
                params.append(int(count) if count and count.isdigit() else 4)

            elif selected_func == packet_sniffer:
                count = input("Number of packets to capture (default 10): ").strip()
                params.append(int(count) if count and count.isdigit() else 10)

            elif selected_func == url_extractor:
                params.append(input("Enter URL to extract links from: ").strip())

            elif selected_func == mac_spoofing_detector:
                # No parameters required
                pass

            elif selected_func == list_connected_devices:
                subnet = input("Enter subnet to scan (default 192.168.1.0/24): ").strip() or "192.168.1.0/24"
                params.append(subnet)

            elif selected_func == dns_resolver:
                params.append(input("Enter domain to resolve: ").strip())
                record_type = input("Record type (A/MX/NS/TXT, default A): ").upper().strip() or 'A'
                params.append(record_type)

            elif selected_func == ssl_certificate_checker:
                params.append(input("Enter hostname: ").strip())
                port = input("Enter port (default 443): ").strip()
                params.append(int(port) if port and port.isdigit() else 443)

            elif selected_func == https_checker:
                params.append(input("Enter domain to check (e.g., example.com): ").strip())

            elif selected_func == sql_injection_scanner:
                params.append(input("Enter URL to test: ").strip())
                params.append(input("Enter parameter to test (e.g., id): ").strip())
                method = input("Enter HTTP method (GET/POST, default GET): ").upper().strip() or "GET"
                params.append(method)

            elif selected_func == xss_sanitizer:
                params.append(input("Enter string to sanitize: ").strip())

            elif selected_func == extract_web_metadata:
                params.append(input("Enter URL to extract metadata: ").strip())

            elif selected_func == clickjacking_detector:
                params.append(input("Enter URL to check: ").strip())

            elif selected_func == brute_force_cracker:
                params.append(input("Enter target SHA-256 hash: ").strip())
                params.append(input("Enter wordlist file path: ").strip())
                max_attempts = input("Maximum attempts (default 10000): ").strip()
                params.append(int(max_attempts) if max_attempts and max_attempts.isdigit() else 10000)

            elif selected_func == check_security_headers:
                params.append(input("Enter URL to check headers: ").strip())

            elif selected_func == exposed_directory_checker:
                params.append(input("Enter base URL (e.g., https://example.com): ").strip())

            elif selected_func == broken_link_crawler:
                params.append(input("Enter starting URL to crawl: ").strip())
                max_pages = input("Maximum pages to crawl (default 10): ").strip()
                params.append(int(max_pages) if max_pages and max_pages.isdigit() else 10)
                max_depth = input("Maximum depth (default 3): ").strip()
                params.append(int(max_depth) if max_depth and max_depth.isdigit() else 3)

            elif selected_func == input_validator:
                params.append(input("Enter input string to validate: ").strip())

            elif selected_func == detect_suspicious_extensions:
                params.append(input("Enter directory to scan: ").strip())

            elif selected_func == find_executable_files:
                params.append(input("Enter directory to scan for executables: ").strip())

            elif selected_func == extract_strings_from_file:
                params.append(input("Enter file path to extract strings: ").strip())
                min_len = input("Minimum string length (default 4): ").strip()
                params.append(int(min_len) if min_len and min_len.isdigit() else 4)

            elif selected_func == compare_hashes:
                params.append(input("Enter file path to hash: ").strip())
                hashes = input("Enter known hashes (comma separated): ").strip()
                params.append([h.strip() for h in hashes.split(",") if h.strip()])

            elif selected_func == detect_keylogger_patterns:
                params.append(input("Enter file path to scan for keylogger patterns: ").strip())

            elif selected_func == detect_obfuscated_code:
                params.append(input("Enter file path to scan for obfuscated code: ").strip())

            elif selected_func == check_malware_hashes:
                params.append(input("Enter file path to check: ").strip())
                hashes = input("Enter known malware hashes (comma separated): ").strip()
                params.append([h.strip() for h in hashes.split(",") if h.strip()])

            elif selected_func == find_suspicious_processes:
                # No parameters required
                pass

            elif selected_func == check_file_permissions:
                params.append(input("Enter directory to check permissions: ").strip())

            elif selected_func == extract_image_metadata:
                params.append(input("Enter image file path: ").strip())

            elif selected_func == detect_hardcoded_credentials:
                params.append(input("Enter file path to scan for credentials: ").strip())

            elif selected_func == redact_sensitive_data:
                params.append(input("Enter text to redact: ").strip())

            elif selected_func == recommend_file_permissions:
                params.append(input("Enter file path to check permissions: ").strip())

            elif selected_func == monitor_file_changes:
                params.append(input("Enter file path to monitor: ").strip())
                params.append(input("Enter known SHA-256 hash: ").strip())

            elif selected_func == encrypt_file:
                params.append(input("Enter input file path: ").strip())
                params.append(input("Enter output file path: ").strip())
                key_input = input("Enter Fernet key (leave blank to generate): ").strip()
                if key_input:
                    try:
                        key = key_input.encode()
                        Fernet(key)
                        params.append(key)
                    except Exception:
                        print("Error: Invalid Fernet key")
                        continue
                else:
                    key = Fernet.generate_key()
                    print(f"Generated key: {key.decode()}")
                    params.append(key)

            elif selected_func == detect_plaintext_passwords:
                params.append(input("Enter file path to scan for passwords: ").strip())

            elif selected_func == simple_auth_system:
                params.append(input("Enter username: ").strip())
                params.append(input("Enter password: ").strip())
                storage = input("Enter storage file (default auth.json): ").strip() or 'auth.json'
                params.append(storage)

            elif selected_func == check_password_breach:
                params.append(input("Enter password to check for breaches: ").strip())

            elif selected_func == analyze_logs:
                params.append(input("Enter log file path to analyze: ").strip())

            elif selected_func == detect_insecure_patterns:
                params.append(input("Enter directory to scan for insecure patterns: ").strip())

            elif selected_func == steganography_encode:
                params.append(input("Enter input image path: ").strip())
                params.append(input("Enter message to encode: ").strip())
                params.append(input("Enter output image path: ").strip())

            elif selected_func == steganography_decode:
                params.append(input("Enter image path to decode: ").strip())

            elif selected_func == check_spam_domain:
                params.append(input("Enter email address to check: ").strip())

            elif selected_func == detect_access_anomalies:
                params.append(input("Enter log file path: ").strip())
                threshold = input("Enter threshold for anomalies (default 10): ").strip()
                params.append(int(threshold) if threshold and threshold.isdigit() else 10)

            elif selected_func == check_outdated_packages:
                # No parameters required
                pass

            result = selected_func(*params)
            
            print("\nRESULTS:")
            if isinstance(result, dict) and 'error' in result:
                print(f"Error: {result['error']}")
            else:
                print(result)
            
            logging.info(f"Tool {tool_name} completed with result: {result}")
            input("\nPress Enter to continue...")
        
        except Exception as e:
            print(f"Error running {tool_name}: {str(e)}")
            logging.error(f"Error running {tool_name}: {str(e)}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    run_tests = input("Run unit tests first? (y/n): ").lower().strip() == 'y'
    if run_tests:
        unittest.main(argv=[''], exit=False)
    main()
