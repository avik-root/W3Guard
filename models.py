"""
Data models for W3Guard
"""

import json
import os
from datetime import datetime
from flask_login import UserMixin

class JSONHandler:
    """Handler for JSON file operations"""
    
    def __init__(self, filename):
        self.filename = filename
    
    def load_data(self):
        """Load data from JSON file"""
        if not os.path.exists(self.filename):
            return {}
        
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def save_data(self, data):
        """Save data to JSON file"""
        try:
            with open(self.filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except IOError:
            return False

class User(UserMixin):
    """User model"""
    
    def __init__(self, id, email, password, is_admin=False, scan_count=0, 
                 daily_scans=0, last_scan_date=None, credit_points=0):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin
        self.scan_count = scan_count
        self.daily_scans = daily_scans
        self.last_scan_date = last_scan_date
        self.credit_points = credit_points
        self.created_at = datetime.now()
    
    def get_id(self):
        return self.id
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return True
    
    @property
    def is_anonymous(self):
        return False

class Scan:
    """Scan result model"""
    
    def __init__(self, scan_id, user_id, url, result, confidence, details, features):
        self.id = scan_id
        self.user_id = user_id
        self.url = url
        self.result = result
        self.confidence = confidence
        self.details = details
        self.features = features
        self.timestamp = datetime.now()

class AdminSettings:
    """Admin settings model"""
    
    def __init__(self):
        self.maintenance_mode = False
        self.site_name = "W3Guard"
        self.contact_email = "admin@w3guard.edu"
        self.max_scans_per_day = 10
    
    def to_dict(self):
        return self.__dict__
    
    @classmethod
    def from_dict(cls, data):
        settings = cls()
        for key, value in data.items():
            if hasattr(settings, key):
                setattr(settings, key, value)
        return settings

class News:
    """News article model"""
    
    def __init__(self, article_id, title, content, author):
        self.id = article_id
        self.title = title
        self.content = content
        self.author = author
        self.date = datetime.now()
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'author': self.author,
            'date': self.date.isoformat()
        }