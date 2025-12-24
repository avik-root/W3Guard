"""
Feature extraction for URL analysis
"""

import re
import tldextract
import whois
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import ipaddress
import socket
import hashlib
import time

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.extracted_domain = tldextract.extract(url)
        self.features = {}
    
    def extract_all_features(self):
        """Extract all available features"""
        
        # URL Structure Features
        self.features['url_length'] = self.get_url_length()
        self.features['domain_length'] = self.get_domain_length()
        self.features['num_dots'] = self.count_dots()
        self.features['num_hyphens'] = self.count_hyphens()
        self.features['num_underscores'] = self.count_underscores()
        self.features['num_slashes'] = self.count_slashes()
        self.features['num_question_marks'] = self.count_question_marks()
        self.features['num_equals'] = self.count_equals()
        self.features['num_ampersands'] = self.count_ampersands()
        self.features['num_percent'] = self.count_percent()
        
        # Domain Features
        self.features['is_ip_address'] = self.is_ip_address()
        self.features['has_https'] = self.has_https()
        self.features['port_present'] = self.has_port()
        self.features['has_at_symbol'] = self.has_at_symbol()
        self.features['has_redirect'] = self.has_redirect()
        
        # TLD Features
        self.features['suspicious_tld'] = self.is_suspicious_tld()
        
        # Query Features
        self.features['num_params'] = self.count_parameters()
        self.features['param_length'] = self.get_avg_param_length()
        
        # Path Features
        self.features['path_depth'] = self.get_path_depth()
        self.features['file_extension'] = self.get_file_extension()
        
        # Content-based Features (simulated for demo)
        self.features['has_login_form'] = self.check_login_form()
        self.features['has_suspicious_keywords'] = self.check_keywords()
        
        # Reputation Features
        self.features['domain_age'] = self.get_domain_age()
        self.features['has_whois'] = self.check_whois()
        
        return self.features
    
    def get_url_length(self):
        return len(self.url)
    
    def get_domain_length(self):
        return len(self.extracted_domain.domain)
    
    def count_dots(self):
        return self.url.count('.')
    
    def count_hyphens(self):
        return self.url.count('-')
    
    def count_underscores(self):
        return self.url.count('_')
    
    def count_slashes(self):
        return self.url.count('/')
    
    def count_question_marks(self):
        return self.url.count('?')
    
    def count_equals(self):
        return self.url.count('=')
    
    def count_ampersands(self):
        return self.url.count('&')
    
    def count_percent(self):
        return self.url.count('%')
    
    def is_ip_address(self):
        """Check if domain is IP address"""
        domain = self.parsed_url.netloc.split(':')[0]
        try:
            ipaddress.ip_address(domain)
            return 1
        except ValueError:
            return 0
    
    def has_https(self):
        return 1 if self.parsed_url.scheme == 'https' else 0
    
    def has_port(self):
        return 1 if self.parsed_url.port is not None else 0
    
    def has_at_symbol(self):
        return 1 if '@' in self.url else 0
    
    def has_redirect(self):
        # Check for common redirect patterns
        redirect_patterns = ['//redirect', '//go', '//link', 'url=', 'return=']
        pattern = '|'.join(redirect_patterns)
        return 1 if re.search(pattern, self.url, re.IGNORECASE) else 0
    
    def is_suspicious_tld(self):
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        tld = '.' + self.extracted_domain.suffix
        return 1 if tld in suspicious_tlds else 0
    
    def count_parameters(self):
        query = self.parsed_url.query
        if not query:
            return 0
        return len(parse_qs(query))
    
    def get_avg_param_length(self):
        query = self.parsed_url.query
        if not query:
            return 0
        
        params = parse_qs(query)
        total_length = sum(len(str(v)) for v in params.values())
        return total_length / len(params) if params else 0
    
    def get_path_depth(self):
        path = self.parsed_url.path
        if not path or path == '/':
            return 0
        return path.count('/') - 1
    
    def get_file_extension(self):
        path = self.parsed_url.path
        extensions = ['.exe', '.zip', '.rar', '.js', '.php', '.html']
        for ext in extensions:
            if path.lower().endswith(ext):
                return 1
        return 0
    
    def check_login_form(self):
        # Simulate checking for login forms (in real system, would fetch page)
        login_keywords = ['login', 'signin', 'password', 'username', 'account']
        return 1 if any(keyword in self.url.lower() for keyword in login_keywords) else 0
    
    def check_keywords(self):
        suspicious_keywords = [
            'secure', 'verify', 'update', 'bank', 'paypal', 'account',
            'confirm', 'suspend', 'limited', 'urgent', 'important'
        ]
        url_lower = self.url.lower()
        count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
        return min(count, 5) / 5  # Normalize to 0-1
    
    def get_domain_age(self):
        # Simulate domain age check
        # In real system, would use WHOIS
        return 0.5  # Simulated value
    
    def check_whois(self):
        # Simulate WHOIS check
        try:
            # For demo purposes, return simulated value
            # In real system: whois.whois(self.extracted_domain.domain + '.' + self.extracted_domain.suffix)
            return 0.8
        except:
            return 0
    
    def get_lexical_features(self):
        """Additional lexical features"""
        features = {}
        
        # Digit ratio
        digits = sum(c.isdigit() for c in self.url)
        features['digit_ratio'] = digits / len(self.url) if self.url else 0
        
        # Letter ratio
        letters = sum(c.isalpha() for c in self.url)
        features['letter_ratio'] = letters / len(self.url) if self.url else 0
        
        # Symbol ratio
        symbols = sum(not c.isalnum() for c in self.url)
        features['symbol_ratio'] = symbols / len(self.url) if self.url else 0
        
        # Entropy of URL
        features['entropy'] = self.calculate_entropy(self.url)
        
        return features
    
    def calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        entropy = 0
        for char in set(string):
            p_x = string.count(char) / len(string)
            entropy += -p_x * (p_x and (p_x * p_x).log2() / p_x.log2())
        
        return entropy