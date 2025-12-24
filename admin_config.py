"""
W3Guard Admin Configuration Manager - Interactive Setup
Manages admin credentials in data/admin.json file with validation
"""

import json
import os
import secrets
import re
import sys
from flask_bcrypt import Bcrypt
from datetime import datetime
from getpass import getpass

class AdminConfigManager:
    """Manage admin configuration and credentials with validation"""
    
    def __init__(self, admin_file='data/admin.json'):
        self.admin_file = admin_file
        self.bcrypt = Bcrypt()
        self.password_regex = {
            'min_length': 8,
            'uppercase': r'[A-Z]',
            'lowercase': r'[a-z]',
            'digit': r'\d',
            'special': r'[!@#$%^&*(),.?":{}|<>]'
        }
    
    def load_admin_config(self):
        """Load admin configuration from file"""
        if os.path.exists(self.admin_file):
            try:
                with open(self.admin_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return self._create_default_admin_config()
        return self._create_default_admin_config()
    
    def save_admin_config(self, config):
        """Save admin configuration to file"""
        os.makedirs('data', exist_ok=True)
        try:
            with open(self.admin_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except IOError as e:
            print(f"❌ Error saving admin config: {e}")
            return False
    
    def _create_default_admin_config(self):
        """Create default admin configuration"""
        return {
            'email': 'admin@w3guard.edu',
            'password_hash': None,
            'created_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'is_admin': True,
            'credit_points': 1000
        }
    
    def generate_secure_password(self):
        """Generate a secure random password"""
        return secrets.token_urlsafe(16)
    
    def hash_password(self, password):
        """Hash a password using bcrypt"""
        return self.bcrypt.generate_password_hash(password).decode('utf-8')
    
    def verify_password(self, password_hash, password):
        """Verify a password against its hash"""
        return self.bcrypt.check_password_hash(password_hash, password)
    
    def validate_password(self, password):
        """
        Validate password strength
        Requirements:
        - At least 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 digit
        - At least 1 special character
        
        Returns: (is_valid, error_messages)
        """
        errors = []
        
        # Check minimum length
        if len(password) < self.password_regex['min_length']:
            errors.append(f"❌ Password must be at least {self.password_regex['min_length']} characters long")
        
        # Check for uppercase letter
        if not re.search(self.password_regex['uppercase'], password):
            errors.append("❌ Password must contain at least one uppercase letter (A-Z)")
        
        # Check for lowercase letter
        if not re.search(self.password_regex['lowercase'], password):
            errors.append("❌ Password must contain at least one lowercase letter (a-z)")
        
        # Check for digit
        if not re.search(self.password_regex['digit'], password):
            errors.append("❌ Password must contain at least one digit (0-9)")
        
        # Check for special character
        if not re.search(self.password_regex['special'], password):
            errors.append("❌ Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
        
        return len(errors) == 0, errors
    
    def validate_email(self, email):
        """
        Validate email format
        Returns: (is_valid, error_message)
        """
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not email or len(email) == 0:
            return False, "❌ Email cannot be empty"
        
        if len(email) > 120:
            return False, "❌ Email is too long (max 120 characters)"
        
        if not re.match(email_regex, email):
            return False, "❌ Invalid email format. Please enter a valid email address"
        
        return True, ""
    
    def interactive_setup(self):
        """Interactive setup for admin configuration"""
        print(f"\n{'='*70}")
        print(f"{'W3GUARD - ADMIN CONFIGURATION SETUP':^70}")
        print(f"{'='*70}\n")
        
        # Get admin email
        print("📧 STEP 1: ADMIN EMAIL")
        print("-" * 70)
        while True:
            email = input("Enter admin email address: ").strip()
            is_valid, error = self.validate_email(email)
            
            if is_valid:
                print(f"✅ Email validated: {email}\n")
                break
            else:
                print(error)
                print("Please try again.\n")
        
        # Get admin password
        print("🔐 STEP 2: ADMIN PASSWORD")
        print("-" * 70)
        print("Password Requirements:")
        print("  • Minimum 8 characters")
        print("  • At least 1 uppercase letter (A-Z)")
        print("  • At least 1 lowercase letter (a-z)")
        print("  • At least 1 digit (0-9)")
        print("  • At least 1 special character (!@#$%^&*(),.?\":{}|<>)")
        print()
        
        while True:
            password = getpass("Enter admin password: ")
            
            if not password:
                print("❌ Password cannot be empty\n")
                continue
            
            is_valid, errors = self.validate_password(password)
            
            if not is_valid:
                print("❌ Password is too weak:")
                for error in errors:
                    print(f"   {error}")
                print()
                continue
            
            # Confirm password
            confirm_password = getpass("Confirm admin password: ")
            
            if password != confirm_password:
                print("❌ Passwords do not match. Please try again.\n")
                continue
            
            print(f"✅ Password validated successfully\n")
            break
        
        # Create admin configuration
        password_hash = self.hash_password(password)
        config = {
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'is_admin': True,
            'credit_points': 1000
        }
        
        # Save configuration
        success = self.save_admin_config(config)
        
        if success:
            print(f"{'='*70}")
            print(f"{'✅ ADMIN CONFIGURATION CREATED SUCCESSFULLY':^70}")
            print(f"{'='*70}")
            print(f"\n📧 Admin Email:        {email}")
            print(f"🔐 Password:           ••••••••••• (securely hashed)")
            print(f"⏰ Created:            {config['created_at']}")
            print(f"💳 Credit Points:      {config['credit_points']}")
            print(f"📁 Config File:        {self.admin_file}")
            print(f"\n{'='*70}")
            print(f"{'NEXT STEPS':^70}")
            print(f"{'='*70}")
            print(f"\n1. Update your app.py to use app_updated.py:")
            print(f"   cp app_updated.py app.py")
            print(f"\n2. Start the W3Guard application:")
            print(f"   python app.py")
            print(f"\n3. Login with your admin credentials:")
            print(f"   Email: {email}")
            print(f"   Password: (the password you just entered)")
            print(f"\n4. After first login, go to Settings to change password")
            print(f"\n{'='*70}\n")
            
            return config, password
        else:
            print(f"\n❌ Failed to save admin configuration")
            return None, None
    
    def set_admin_email(self, new_email):
        """Update admin email"""
        is_valid, error = self.validate_email(new_email)
        
        if not is_valid:
            print(error)
            return False
        
        config = self.load_admin_config()
        old_email = config.get('email')
        config['email'] = new_email
        config['last_updated'] = datetime.now().isoformat()
        
        success = self.save_admin_config(config)
        if success:
            print(f"✅ Admin email updated: {old_email} → {new_email}")
            return True
        else:
            print("❌ Failed to update admin email")
            return False
    
    def set_admin_password(self, new_password=None):
        """Update admin password with validation"""
        
        if new_password is None:
            # Interactive password input
            print(f"\n{'='*70}")
            print(f"{'UPDATE ADMIN PASSWORD':^70}")
            print(f"{'='*70}\n")
            print("Password Requirements:")
            print("  • Minimum 8 characters")
            print("  • At least 1 uppercase letter (A-Z)")
            print("  • At least 1 lowercase letter (a-z)")
            print("  • At least 1 digit (0-9)")
            print("  • At least 1 special character (!@#$%^&*(),.?\":{}|<>)")
            print()
            
            while True:
                new_password = getpass("Enter new password: ")
                
                if not new_password:
                    print("❌ Password cannot be empty\n")
                    continue
                
                is_valid, errors = self.validate_password(new_password)
                
                if not is_valid:
                    print("❌ Password is too weak:")
                    for error in errors:
                        print(f"   {error}")
                    print()
                    continue
                
                confirm_password = getpass("Confirm new password: ")
                
                if new_password != confirm_password:
                    print("❌ Passwords do not match. Please try again.\n")
                    continue
                
                break
        else:
            # Validate provided password
            is_valid, errors = self.validate_password(new_password)
            
            if not is_valid:
                print("❌ Password is too weak:")
                for error in errors:
                    print(f"   {error}")
                return False
        
        config = self.load_admin_config()
        password_hash = self.hash_password(new_password)
        config['password_hash'] = password_hash
        config['last_updated'] = datetime.now().isoformat()
        
        success = self.save_admin_config(config)
        if success:
            print(f"✅ Admin password updated successfully")
            print(f"⏰ Last updated: {config['last_updated']}\n")
            return True
        else:
            print("❌ Failed to update admin password")
            return False
    
    def get_admin_email(self):
        """Get admin email"""
        config = self.load_admin_config()
        return config.get('email', 'admin@w3guard.edu')
    
    def get_admin_password_hash(self):
        """Get admin password hash"""
        config = self.load_admin_config()
        return config.get('password_hash')
    
    def display_admin_info(self):
        """Display current admin information"""
        config = self.load_admin_config()
        print(f"\n{'='*70}")
        print(f"{'CURRENT ADMIN CONFIGURATION':^70}")
        print(f"{'='*70}")
        print(f"📧 Email:              {config.get('email')}")
        print(f"👤 Is Admin:           {config.get('is_admin')}")
        print(f"💳 Credit Points:      {config.get('credit_points')}")
        print(f"✅ Password Hash:      {'SET' if config.get('password_hash') else 'NOT SET'}")
        print(f"📅 Created At:         {config.get('created_at')}")
        print(f"🔄 Last Updated:       {config.get('last_updated')}")
        print(f"{'='*70}\n")


def display_menu():
    """Display interactive menu"""
    print(f"\n{'='*70}")
    print(f"{'W3GUARD ADMIN CONFIGURATION MANAGER':^70}")
    print(f"{'='*70}")
    print("\n1. 🆕 Interactive Setup (First Time)")
    print("2. 📧 Update Admin Email")
    print("3. 🔐 Update Admin Password")
    print("4. ℹ️  View Admin Information")
    print("5. 🎲 Generate New Secure Password (display only)")
    print("6. ❌ Exit")
    print(f"\n{'='*70}\n")
    
    return input("Select an option (1-6): ").strip()


def main():
    """Interactive CLI interface for admin configuration"""
    manager = AdminConfigManager()
    
    # Check if admin.json already exists
    admin_exists = os.path.exists(manager.admin_file)
    
    if len(sys.argv) > 1:
        # Command-line mode
        command = sys.argv[1].lower()
        
        if command == 'init':
            if admin_exists:
                print(f"\n⚠️  Admin configuration already exists at {manager.admin_file}")
                response = input("Do you want to reconfigure? (yes/no): ").strip().lower()
                if response != 'yes':
                    print("Cancelled.\n")
                    return
            manager.interactive_setup()
        
        elif command == 'email' and len(sys.argv) >= 3:
            new_email = sys.argv[2]
            manager.set_admin_email(new_email)
        
        elif command == 'password' and len(sys.argv) >= 3:
            new_password = sys.argv[2]
            manager.set_admin_password(new_password)
        
        elif command == 'info':
            manager.display_admin_info()
        
        elif command == 'generate':
            password = manager.generate_secure_password()
            print(f"\n{'='*70}")
            print(f"Generated Secure Password: {password}")
            print(f"{'='*70}")
            print("\nTo set this password, run:")
            print(f"python admin_config.py password {password}\n")
        
        else:
            print(f"\n❌ Unknown command: {command}")
            print("\nUsage:")
            print("  python admin_config.py init              - Interactive setup")
            print("  python admin_config.py email <email>     - Update email")
            print("  python admin_config.py password <pwd>    - Update password")
            print("  python admin_config.py info              - View configuration")
            print("  python admin_config.py generate          - Generate password\n")
    
    else:
        # Interactive menu mode
        while True:
            choice = display_menu()
            
            if choice == '1':
                if admin_exists:
                    print(f"\n⚠️  Admin configuration already exists at {manager.admin_file}")
                    response = input("Do you want to reconfigure? (yes/no): ").strip().lower()
                    if response != 'yes':
                        print("Cancelled.\n")
                        continue
                manager.interactive_setup()
            
            elif choice == '2':
                email = input("\nEnter new admin email: ").strip()
                manager.set_admin_email(email)
            
            elif choice == '3':
                manager.set_admin_password()
            
            elif choice == '4':
                manager.display_admin_info()
            
            elif choice == '5':
                password = manager.generate_secure_password()
                print(f"\n{'='*70}")
                print(f"Generated Secure Password:")
                print(f"{password}")
                print(f"{'='*70}\n")
            
            elif choice == '6':
                print("\n👋 Goodbye!\n")
                break
            
            else:
                print("❌ Invalid option. Please select 1-6.\n")


if __name__ == '__main__':
    main()
