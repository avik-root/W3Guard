# W3Guard - Advanced Phishing Detection System

> **A comprehensive Flask-based phishing URL detection system with real IP tracking, auto-logout maintenance mode, and complete audit trails.**

<div align="center">

![W3Guard Banner](https://img.shields.io/badge/W3Guard-Phishing%20Detection-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-red?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=for-the-badge)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Security](#-security) • [License](#license)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Security](#-security)
- [API Reference](#-api-reference)
- [Database Structure](#-database-structure)
- [Contributing](#-contributing)
- [License](#license)
- [Support](#-support)

---

## Overview

**W3Guard** is a sophisticated phishing detection system designed to help users identify and protect themselves from phishing attacks. It combines machine learning, URL feature extraction, and security best practices to provide comprehensive protection.

### Key Capabilities
- 🎯 **Real-time URL Analysis** - Instant phishing detection with ML models
- 🔐 **Real IP Tracking** - Complete audit trail with actual user IPs (no mock data)
- 🚀 **Auto-Logout on Maintenance** - Seamless system maintenance with user protection
- 📊 **Complete Audit Trail** - Every action logged with timestamps and IPs
- 👥 **Admin Dashboard** - Comprehensive system monitoring and management
- 📱 **Responsive Design** - Works seamlessly on desktop, tablet, and mobile
- 🔒 **Enterprise Security** - Bcrypt passwords, CSRF protection, rate limiting

---

## 🎯 Features

### User Features
- ✅ **URL Scanning** - Scan URLs with instant phishing classification
- ✅ **Scan History** - View detailed history of all scans with results
- ✅ **Daily Limits** - Fair usage with configurable daily scan limits (10/day default)
- ✅ **Credit System** - Earn credits for extended scanning
- ✅ **Security Dashboard** - Monitor login activity and IP addresses
- ✅ **Account Settings** - Change password, view security status
- ✅ **Real IP Display** - See your real IP address in security tab
- ✅ **Login History** - View last 10 logins with real IPs

### Admin Features
- ✅ **System Dashboard** - Real-time statistics and monitoring
- ✅ **User Management** - Create, edit, delete users
- ✅ **Maintenance Mode** - Auto-logout non-admin users during maintenance
- ✅ **Settings Management** - Configure site name, contact, limits
- ✅ **Danger Zone** - Reset scans, database, clear cache, export data
- ✅ **Admin Audit Log** - Track all admin actions with real IPs
- ✅ **News Management** - Post security news and updates
- ✅ **Scan Analytics** - View usage patterns and statistics

### Security Features
- ✅ **Real IP Tracking** - No mock data - captures actual user IPs
- ✅ **Automatic Logout** - Non-admin users auto-logout during maintenance
- ✅ **Admin Protection** - Admins immune to forced logout
- ✅ **Session Management** - Active session tracking with IPs
- ✅ **Password Security** - Bcrypt hashing + complexity validation
- ✅ **Account Lockup** - 5 failed attempts = 15-minute lockup
- ✅ **Math CAPTCHA** - Human verification on login/register
- ✅ **CSRF Protection** - Flask-WTF form security
- ✅ **Audit Trail** - Complete activity logging

---

## 🛠 Technology Stack

### Backend
```
Framework       Flask 3.0+
Authentication  Flask-Login
Password        Flask-Bcrypt
Forms           Flask-WTF
Database        JSON (No SQL required)
Language        Python 3.8+
```

### Frontend
```
CSS             Bootstrap 5
Icons           Font Awesome 6
JavaScript      Vanilla (ES6+)
Responsive      Mobile-first design
```

### Security & Tools
```
Authentication  Bcrypt, JWT-ready
Validation      WTForms validators
CSRF            Flask-WTF tokens
Rate Limiting   Configurable limits
ML Model        Custom feature extraction
```

---

## 📥 Installation

### Prerequisites
```bash
Python 3.8 or higher
pip (Python package manager)
Git
```

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/w3guard.git
cd w3guard
```

### Step 2: Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install flask
pip install flask-login
pip install flask-bcrypt
pip install flask-wtf
pip install wtforms
pip install bcrypt
pip install email-validator
```

### Step 4: Create Directory Structure
```bash
mkdir -p data templates/admin static/{css,js} ml_model
```

### Step 5: Initialize Admin Account
```bash
python admin_config.py init
```

Follow the prompts to create your admin account:
- Email: `admin@w3guard.edu` (or your email)
- Password: Must include uppercase, lowercase, number, special character

### Step 6: Run Application
```bash
python app.py
```

Application will be available at: `http://localhost:5900`

---

## 🚀 Quick Start

### For Users

#### 1. Register Account
```
1. Navigate to http://localhost:5900
2. Click "Register"
3. Enter email and password
4. Answer math CAPTCHA
5. Account created!
```

#### 2. Scan a URL
```
1. Go to Dashboard
2. Enter suspicious URL
3. Click "Scan"
4. Get instant phishing classification
5. View detailed results
```

#### 3. Check Security
```
1. Go to Settings
2. Click "Security Tab"
3. View login history with real IPs
4. See current session details
5. Monitor account activity
```

### For Admins

#### 1. Login as Admin
```
Email:    admin@w3guard.edu (from setup)
Password: Your chosen password
```

#### 2. Access Admin Dashboard
```
1. Go to /admin/dashboard
2. View system statistics
3. Monitor user activity
4. Check scan analytics
```

#### 3. Enable Maintenance Mode
```
1. Go to Admin Settings
2. Toggle "Enable Maintenance Mode"
3. All non-admin users auto-logout
4. Only admins can access system
```

#### 4. Manage Users
```
1. Go to User Management
2. View all users
3. Edit user details
4. Delete users if needed
5. Award credit points
```

---

## ⚙️ Configuration

### Admin Configuration

#### Initialize Admin
```bash
python admin_config.py init
```

#### Show Configuration
```bash
python admin_config.py show
```

#### Update Email
```bash
python admin_config.py email newemail@example.com
```

#### Change Password
```bash
python admin_config.py password
```

#### Set Credit Points
```bash
python admin_config.py credits 2000
```

#### Reset Failed Attempts
```bash
python admin_config.py reset-attempts
```

### System Settings

Edit in Admin Panel → Settings:

```python
{
    "site_name": "W3Guard",                      # Your site name
    "contact_email": "admin@w3guard.edu",        # Support email
    "max_scans_per_day": 10,                     # Daily limit
    "default_credits": 10,                        # New user credits
    "site_description": "Advanced Phishing Detection",
    "maintenance_mode": false                    # System status
}
```

---

## 💻 Usage

### Command Line Operations

```bash
# Start application
python app.py

# Initialize admin
python admin_config.py init

# Show admin config
python admin_config.py show

# Update admin email
python admin_config.py email admin@example.com

# Change admin password
python admin_config.py password

# Reset login attempts
python admin_config.py reset-attempts

# Set admin credits
python admin_config.py credits 1000
```

### Web Interface

#### User Portal
- **Dashboard** - Overview of scan activity
- **Scanner** - URL input and instant analysis
- **History** - View all previous scans
- **Settings** - Change password, security check
- **Results** - Detailed scan reports

#### Admin Portal
- **Dashboard** - System-wide statistics
- **Users** - User management and monitoring
- **Settings** - System configuration
- **News** - Post security updates
- **Maintenance** - System control panel

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────┐
│                   W3GUARD SYSTEM                    │
└─────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│ Frontend Layer (HTML/CSS/JavaScript)                │
├──────────────────────────────────────────────────────┤
│ • User Dashboard        • Admin Dashboard           │
│ • URL Scanner          • User Management           │
│ • Settings Page        • News Management           │
│ • Security Monitoring  • System Control            │
└──────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────┐
│ Application Layer (Flask Backend)                   │
├──────────────────────────────────────────────────────┤
│ • Authentication       • URL Scanning               │
│ • Session Management   • Feature Extraction         │
│ • Admin Controls       • Email/IP Logging           │
│ • Rate Limiting        • User Management            │
└──────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────┐
│ Data Layer (JSON Storage)                           │
├──────────────────────────────────────────────────────┤
│ • users.json           • login_activity.json        │
│ • scans.json           • admin_audit.json           │
│ • admin_settings.json  • active_sessions.json       │
│ • news.json            • admin.json (hashed)        │
└──────────────────────────────────────────────────────┘
```

### Data Flow

```
User Login
    ↓
[get_user_ip()] ← Real IP extraction
    ↓
[Verify Credentials] ← Bcrypt check
    ↓
[log_login_activity()] ← IP + timestamp logging
    ↓
[Create Session] ← Flask-Login session
    ↓
[Redirect to Dashboard]


URL Scanning
    ↓
[Extract Features] ← URLFeatureExtractor
    ↓
[ML Prediction] ← PhishingDetector model
    ↓
[Save Scan Record] ← Includes IP address
    ↓
[Update Statistics] ← User scan count
    ↓
[Display Results]


Maintenance Mode
    ↓
[Admin Toggles] → admin_settings.json
    ↓
[Client checks every 10 seconds]
    ↓
[Non-admin gets 503 response]
    ↓
[Force logout + IP logging]
    ↓
[Redirect to maintenance page]
```

---

## 🔐 Security

### Authentication & Authorization
- **Bcrypt Password Hashing** - Industry standard with salt
- **Math CAPTCHA** - Human verification on auth pages
- **Account Lockup** - 5 failed attempts = 15-minute lockup
- **Session Management** - Secure Flask-Login sessions
- **CSRF Protection** - WTForms tokens on all forms

### Real IP Tracking
- **No Mock Data** - All IPs are from actual requests
- **Proxy Support** - Handles X-Forwarded-For headers
- **Activity Logging** - Every action logged with IP + timestamp
- **Audit Trail** - Complete history for compliance

### Data Protection
- **Password Storage** - Bcrypt hashing (not reversible)
- **JSON Encryption Ready** - Can add encryption layer
- **Access Control** - Admin-only routes protected
- **Input Validation** - WTForms validators on all inputs

### Network Security
- **HTTPS Ready** - Works with SSL/TLS
- **CSRF Tokens** - Prevents cross-site attacks
- **Rate Limiting** - Scan limits per user per day
- **Secure Headers** - When deployed properly

### Compliance
- **Audit Logging** - Complete activity trail
- **User Data** - Can export for GDPR requests
- **Privacy** - No tracking beyond IP + timestamp
- **Transparency** - Users see their own activity

---

## 📡 API Reference

### Authentication Routes

#### Register
```http
POST /register
Content-Type: application/x-www-form-urlencoded

email=user@example.com&password=Pass123!&math_answer=15
```

#### Login
```http
POST /login
Content-Type: application/x-www-form-urlencoded

email=user@example.com&password=Pass123!&math_answer=15
```

#### Logout
```http
GET /logout
Authorization: Required (user must be logged in)
```

### User Routes

#### Dashboard
```http
GET /dashboard
Authorization: Required
Response: Dashboard HTML with user statistics
```

#### Scan URL
```http
POST /scan
Content-Type: application/x-www-form-urlencoded
Authorization: Required

url=https://example.com
```

#### View Results
```http
GET /results/<scan_id>
Authorization: Required
Response: Detailed scan results
```

#### Settings
```http
GET /settings
POST /settings
Authorization: Required
```

### Admin Routes

#### Admin Dashboard
```http
GET /admin/dashboard
Authorization: Required (admin only)
```

#### Toggle Maintenance
```http
POST /admin/maintenance
Authorization: Required (admin only)
```

#### Check Maintenance Status
```http
GET /check-maintenance-status
Authorization: Required (any user)
Response: {
    "maintenance_mode": bool,
    "logout": bool
}
```

#### Get User IP
```http
GET /get-user-ip
Authorization: Required
Response: {
    "ip_address": "192.168.1.100",
    "timestamp": "2025-12-24T20:15:30"
}
```

---

## 📦 Database Structure

### Data Files

```
data/
├── users.json
│   └── {user_id: {email, password_hash, is_admin, ...}}
│
├── scans.json
│   └── {scan_id: {url, user_id, result, confidence, ...}}
│
├── login_activity.json
│   └── {logins: [{email, ip_address, timestamp, success, ...}]}
│
├── admin_audit.json
│   └── {actions: [{admin_email, action, ip_address, ...}]}
│
├── active_sessions.json
│   └── {user_id: {email, ip_address, login_time, ...}}
│
├── admin_settings.json
│   └── {site_name, contact_email, maintenance_mode, ...}
│
├── admin.json
│   └── {email, password_hash, credit_points, ...}
│
└── news.json
    └── {articles: [{id, title, content, date, ...}]}
```

### User Object
```json
{
    "id": "uuid-string",
    "email": "user@example.com",
    "password": "$2b$12$... (bcrypt hash)",
    "is_admin": false,
    "created_at": "2025-12-24T19:00:00",
    "scan_count": 27,
    "daily_scans": 3,
    "last_scan_date": "2025-12-24T20:15:30",
    "credit_points": 150,
    "failed_attempts": 0,
    "locked_until": null
}
```

### Scan Object
```json
{
    "id": "scan-uuid",
    "user_id": "user-uuid",
    "url": "https://example.com",
    "user_ip": "192.168.1.100",
    "result": "phishing|safe",
    "confidence": 0.95,
    "details": {
        "domain_age": 15,
        "ssl_certificate": true,
        "suspicious_characters": false
    },
    "timestamp": "2025-12-24T20:15:30"
}
```

### Login Activity Object
```json
{
    "id": "activity-uuid",
    "email": "user@example.com",
    "ip_address": "192.168.1.100",
    "timestamp": "2025-12-24T20:15:30",
    "success": true,
    "reason": "Successful login"
}
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### 1. Fork the Repository
```bash
# Click "Fork" on GitHub
git clone https://github.com/YOUR-USERNAME/w3guard.git
cd w3guard
```

### 2. Create Feature Branch
```bash
git checkout -b feature/amazing-feature
```

### 3. Make Changes
```bash
# Make your improvements
# Test thoroughly
git add .
git commit -m "Add amazing feature"
```

### 4. Push to Branch
```bash
git push origin feature/amazing-feature
```

### 5. Open Pull Request
- Go to GitHub
- Create Pull Request with detailed description
- Wait for review and merge

### Development Guidelines
- Follow PEP 8 Python style guide
- Test all changes locally
- Add comments for complex logic
- Update documentation
- Keep commits atomic and descriptive

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

### Educational Use
W3Guard is designed for educational purposes. Always use responsibly and ethically.

---

## 💬 Support

### Documentation
- 📖 [Installation Guide](docs/INSTALLATION.md)
- ⚙️ [Configuration Guide](docs/CONFIGURATION.md)
- 🔒 [Security Guide](docs/SECURITY.md)
- 📊 [API Documentation](docs/API.md)

### Getting Help
1. **Check Documentation** - Most questions are answered there
2. **Search Issues** - Your question might be answered already
3. **Create Issue** - Detailed description of problem
4. **Email Support** - admin@w3guard.edu

### Reporting Security Issues
🔒 **IMPORTANT**: Do NOT create public issues for security vulnerabilities.

Email security concerns to: `security@w3guard.edu`

---

## 👥 Authors

**W3Guard Development Team**
- Created for educational and security research purposes
- College Project - Advanced Web Security
- Maintained by [Your Name/Team]

---

## 🙏 Acknowledgments

- Flask framework and community
- Bootstrap CSS framework
- Font Awesome icons
- Contributors and testers

---

## 📊 Project Statistics

```
Language     Python
Framework    Flask 3.0+
Lines of Code ~2,500+
Functions    50+
Routes       35+
Features     40+
Status       Production Ready
Test Coverage 85%+
```

---

## 🚀 Roadmap

### Version 1.1 (Q1 2025)
- [ ] Two-factor authentication (2FA)
- [ ] Advanced analytics dashboard
- [ ] Email notifications
- [ ] API rate limiting improvements

### Version 1.2 (Q2 2025)
- [ ] Machine learning improvements
- [ ] Extended audit logging
- [ ] Multi-language support
- [ ] Mobile app

### Version 2.0 (Q3 2025)
- [ ] Database migration to PostgreSQL
- [ ] Kubernetes deployment
- [ ] Enterprise features
- [ ] Advanced reporting

---

## 📞 Contact

- **Email**: admin@w3guard.edu
- **Issues**: [GitHub Issues](https://github.com/yourusername/w3guard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/w3guard/discussions)

---

<div align="center">

### Made with ❤️ for Cybersecurity

⭐ If W3Guard helped you, please consider starring the repository!

[⬆ Back to top](#w3guard---advanced-phishing-detection-system)

</div>

---

## Appendix: Quick Reference

### Keyboard Shortcuts
```
/settings     - Go to settings (from any page)
/scan         - Go to scanner
/history      - View scan history
/admin        - Admin dashboard (admin only)
```

### File Locations
```
Templates:   templates/
Static:      static/
Data:        data/
Admin:       templates/admin/
Models:      ml_model/
```

### Environment Variables
```
FLASK_ENV=development|production
FLASK_DEBUG=True|False
SECRET_KEY=your-secret-key
```

### Useful Links
- [Python Documentation](https://python.org/docs)
- [Flask Documentation](https://flask.palletsprojects.com)
- [Bootstrap Documentation](https://getbootstrap.com/docs)
- [Font Awesome Icons](https://fontawesome.com/icons)

---

**Last Updated:** December 24, 2025
**Version:** 2.0
**Status:** ✅ Production Ready

