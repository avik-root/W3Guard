#!/usr/bin/env python3
"""
W3Guard Admin Configuration Script
Set up admin credentials with real IP logging

Usage:
  python admin_config.py init
  python admin_config.py email your-email@example.com
  python admin_config.py password YourPassword123!
  python admin_config.py show
"""

import json
import sys
import os
import getpass
import re
from flask_bcrypt import Bcrypt
from datetime import datetime

bcrypt = Bcrypt()

ADMIN_FILE = 'data/admin.json'
AUDIT_FILE = 'data/admin_audit.json'

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password complexity"""
    if len(password) < 8:
        print("❌ Password must be at least 8 characters long")
        return False
    if not re.search(r'[A-Z]', password):
        print("❌ Password must contain at least one uppercase letter")
        return False
    if not re.search(r'[a-z]', password):
        print("❌ Password must contain at least one lowercase letter")
        return False
    if not re.search(r'\d', password):
        print("❌ Password must contain at least one digit")
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        print("❌ Password must contain at least one special character")
        return False
    return True

def load_admin_config():
    """Load existing admin config"""
    if os.path.exists(ADMIN_FILE):
        try:
            with open(ADMIN_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None

def save_admin_config(config):
    """Save admin config"""
    os.makedirs('data', exist_ok=True)
    with open(ADMIN_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"✅ Admin config saved to {ADMIN_FILE}")

def log_admin_change(action, email, changes):
    """Log admin configuration changes"""
    os.makedirs('data', exist_ok=True)
    
    audit_data = {}
    if os.path.exists(AUDIT_FILE):
        try:
            with open(AUDIT_FILE, 'r') as f:
                audit_data = json.load(f)
        except:
            audit_data = {}
    
    if 'admin_config_changes' not in audit_data:
        audit_data['admin_config_changes'] = []
    
    audit_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'email': email,
        'changes': changes
    }
    
    audit_data['admin_config_changes'].append(audit_entry)
    # Keep only last 100 entries
    audit_data['admin_config_changes'] = audit_data['admin_config_changes'][-100:]
    
    try:
        with open(AUDIT_FILE, 'w') as f:
            json.dump(audit_data, f, indent=2)
    except:
        pass

def cmd_init():
    """Initialize admin configuration"""
    print("\n" + "="*60)
    print("W3GUARD ADMIN CONFIGURATION - INITIALIZATION")
    print("="*60 + "\n")
    
    admin_config = load_admin_config()
    
    if admin_config:
        print("⚠️  Admin configuration already exists!")
        print(f"   Email: {admin_config.get('email', 'N/A')}")
        response = input("\nDo you want to reset it? (yes/no): ").strip().lower()
        if response != 'yes':
            print("❌ Initialization cancelled")
            return
    
    # Get email
    while True:
        email = input("\nEnter admin email: ").strip()
        if validate_email(email):
            break
        print("❌ Invalid email format")
    
    # Get password
    while True:
        password = getpass.getpass("Enter admin password (min 8 chars, needs uppercase, lowercase, number, special): ")
        if validate_password(password):
            confirm = getpass.getpass("Confirm password: ")
            if password == confirm:
                break
            print("❌ Passwords do not match")
        print("❌ Password does not meet requirements\n")
    
    # Hash password
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Create admin config
    admin_config = {
        'email': email,
        'password_hash': password_hash,
        'credit_points': 1000,
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'login_attempts': 0,
        'locked_until': None
    }
    
    save_admin_config(admin_config)
    log_admin_change('init', email, {'email': email})
    
    print("\n" + "="*60)
    print("✅ ADMIN CONFIGURATION COMPLETE")
    print("="*60)
    print(f"Email: {email}")
    print(f"Password Hash: {password_hash[:50]}...")
    print(f"Credit Points: 1000")
    print("\n⚠️  IMPORTANT: Keep your admin credentials safe!")
    print("="*60 + "\n")

def cmd_email(email):
    """Update admin email"""
    print("\n" + "="*60)
    print("UPDATE ADMIN EMAIL")
    print("="*60 + "\n")
    
    if not validate_email(email):
        print("❌ Invalid email format")
        return
    
    admin_config = load_admin_config()
    if not admin_config:
        print("❌ Admin configuration not found. Run 'python admin_config.py init' first")
        return
    
    old_email = admin_config.get('email')
    admin_config['email'] = email
    save_admin_config(admin_config)
    log_admin_change('update_email', email, {'old_email': old_email, 'new_email': email})
    
    print(f"\n✅ Admin email updated:")
    print(f"   Old: {old_email}")
    print(f"   New: {email}")
    print("="*60 + "\n")

def cmd_password(password=None):
    """Update admin password"""
    print("\n" + "="*60)
    print("UPDATE ADMIN PASSWORD")
    print("="*60 + "\n")
    
    admin_config = load_admin_config()
    if not admin_config:
        print("❌ Admin configuration not found. Run 'python admin_config.py init' first")
        return
    
    # Verify current password
    current_password = getpass.getpass("Enter current password: ")
    if not bcrypt.check_password_hash(admin_config['password_hash'], current_password):
        print("❌ Current password is incorrect")
        return
    
    # Get new password
    while True:
        new_password = getpass.getpass("\nEnter new password (min 8 chars, needs uppercase, lowercase, number, special): ")
        if validate_password(new_password):
            confirm = getpass.getpass("Confirm password: ")
            if new_password == confirm:
                break
            print("❌ Passwords do not match")
        print("❌ Password does not meet requirements\n")
    
    # Hash and save
    password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    admin_config['password_hash'] = password_hash
    save_admin_config(admin_config)
    log_admin_change('update_password', admin_config['email'], {'password_changed': True})
    
    print("\n✅ Admin password updated successfully")
    print("="*60 + "\n")

def cmd_show():
    """Show admin configuration"""
    print("\n" + "="*60)
    print("ADMIN CONFIGURATION")
    print("="*60 + "\n")
    
    admin_config = load_admin_config()
    if not admin_config:
        print("❌ Admin configuration not found")
        print("Run 'python admin_config.py init' to initialize\n")
        return
    
    print(f"Email: {admin_config.get('email', 'N/A')}")
    print(f"Credit Points: {admin_config.get('credit_points', 'N/A')}")
    print(f"Created: {admin_config.get('created_at', 'N/A')}")
    print(f"Last Login: {admin_config.get('last_login', 'Never')}")
    print(f"Login Attempts: {admin_config.get('login_attempts', 0)}")
    print(f"Locked Until: {admin_config.get('locked_until', 'Not locked')}")
    print(f"Password Hash: {admin_config.get('password_hash', 'N/A')[:50]}...")
    print("\n" + "="*60 + "\n")

def cmd_reset_attempts():
    """Reset login attempts"""
    print("\n" + "="*60)
    print("RESET LOGIN ATTEMPTS")
    print("="*60 + "\n")
    
    admin_config = load_admin_config()
    if not admin_config:
        print("❌ Admin configuration not found\n")
        return
    
    admin_config['login_attempts'] = 0
    admin_config['locked_until'] = None
    save_admin_config(admin_config)
    log_admin_change('reset_attempts', admin_config['email'], {'attempts': 0, 'locked_until': None})
    
    print(f"✅ Login attempts reset for {admin_config['email']}")
    print("="*60 + "\n")

def cmd_credits(amount):
    """Set admin credit points"""
    print("\n" + "="*60)
    print("SET ADMIN CREDIT POINTS")
    print("="*60 + "\n")
    
    try:
        credits = int(amount)
        if credits < 0:
            print("❌ Credit points must be non-negative")
            return
    except ValueError:
        print("❌ Invalid credit amount")
        return
    
    admin_config = load_admin_config()
    if not admin_config:
        print("❌ Admin configuration not found\n")
        return
    
    old_credits = admin_config.get('credit_points', 0)
    admin_config['credit_points'] = credits
    save_admin_config(admin_config)
    log_admin_change('update_credits', admin_config['email'], {'old_credits': old_credits, 'new_credits': credits})
    
    print(f"✅ Admin credit points updated:")
    print(f"   Old: {old_credits}")
    print(f"   New: {credits}")
    print("="*60 + "\n")

def print_help():
    """Print help message"""
    print("\n" + "="*60)
    print("W3GUARD ADMIN CONFIGURATION TOOL")
    print("="*60 + "\n")
    print("Usage: python admin_config.py <command> [argument]\n")
    print("Commands:")
    print("  init                      Initialize admin configuration")
    print("  email <email>             Update admin email address")
    print("  password                  Update admin password (interactive)")
    print("  show                      Show admin configuration")
    print("  reset-attempts            Reset failed login attempts")
    print("  credits <amount>          Set admin credit points")
    print("  help                      Show this help message\n")
    print("Examples:")
    print("  python admin_config.py init")
    print("  python admin_config.py email admin@w3guard.edu")
    print("  python admin_config.py password")
    print("  python admin_config.py credits 1000\n")
    print("="*60 + "\n")

def main():
    if len(sys.argv) < 2:
        print_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == 'init':
        cmd_init()
    elif command == 'email' and len(sys.argv) > 2:
        cmd_email(sys.argv[2])
    elif command == 'password':
        cmd_password()
    elif command == 'show':
        cmd_show()
    elif command == 'reset-attempts':
        cmd_reset_attempts()
    elif command == 'credits' and len(sys.argv) > 2:
        cmd_credits(sys.argv[2])
    elif command == 'help':
        print_help()
    else:
        print(f"❌ Unknown command: {command}")
        print_help()

if __name__ == '__main__':
    main()
