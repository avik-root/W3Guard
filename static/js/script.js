// W3Guard - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Password strength indicator
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        input.addEventListener('input', function() {
            const password = this.value;
            const strength = checkPasswordStrength(password);
            updatePasswordStrengthIndicator(this, strength);
        });
    });

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Auto-refresh captcha
    const refreshCaptchaBtn = document.getElementById('refresh-captcha');
    if (refreshCaptchaBtn) {
        refreshCaptchaBtn.addEventListener('click', function() {
            refreshCaptcha();
        });
    }

    // Real-time URL validation for scan form
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.addEventListener('blur', function() {
            validateURL(this);
        });
    }

    // Admin chart initialization
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }

    // Auto-hide alerts
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

function checkPasswordStrength(password) {
    let strength = 0;
    
    // Length check
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    
    // Character variety checks
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    return Math.min(strength, 5); // Max 5
}

function updatePasswordStrengthIndicator(input, strength) {
    let indicator = input.parentElement.querySelector('.password-strength');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.className = 'password-strength mt-2';
        input.parentElement.appendChild(indicator);
    }
    
    const colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60'];
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    
    let html = '<div class="progress" style="height: 5px;">';
    html += `<div class="progress-bar" role="progressbar" style="width: ${strength * 20}%; background-color: ${colors[strength - 1] || '#e74c3c'};"></div>`;
    html += '</div>';
    html += `<small class="text-muted">${labels[strength - 1] || 'Very Weak'}</small>`;
    
    indicator.innerHTML = html;
}

async function refreshCaptcha() {
    try {
        const response = await fetch('/generate_captcha');
        const data = await response.json();
        
        const captchaImage = document.querySelector('.captcha-image');
        const captchaText = document.querySelector('.captcha-text');
        
        if (captchaImage) {
            captchaImage.src = data.image;
        }
        if (captchaText) {
            captchaText.textContent = data.captcha_text;
        }
    } catch (error) {
        console.error('Error refreshing captcha:', error);
    }
}

function validateURL(input) {
    const url = input.value.trim();
    const feedback = document.getElementById('url-feedback');
    
    if (!url) return;
    
    // Basic URL validation
    const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w\.-]*)*\/?$/;
    
    if (!urlPattern.test(url)) {
        input.classList.add('is-invalid');
        if (feedback) {
            feedback.textContent = 'Please enter a valid URL';
            feedback.style.display = 'block';
        }
        return false;
    }
    
    input.classList.remove('is-invalid');
    if (feedback) {
        feedback.style.display = 'none';
    }
    return true;
}

function initializeCharts() {
    // Sample chart for admin dashboard
    const ctx = document.getElementById('scanChart');
    if (ctx) {
        const scanChart = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Safe Scans',
                    data: [65, 59, 80, 81, 56, 55, 40],
                    borderColor: '#27ae60',
                    backgroundColor: 'rgba(39, 174, 96, 0.1)',
                    tension: 0.1
                }, {
                    label: 'Phishing Scans',
                    data: [28, 48, 40, 19, 86, 27, 90],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    }
                }
            }
        });
    }
}

// AJAX functions for admin
async function toggleMaintenance() {
    try {
        const response = await fetch('/admin/maintenance', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const data = await response.json();
        const btn = document.getElementById('maintenance-btn');
        
        if (btn) {
            if (data.maintenance_mode) {
                btn.innerHTML = '<i class="fas fa-toggle-on"></i> Maintenance ON';
                btn.classList.remove('btn-secondary');
                btn.classList.add('btn-warning');
            } else {
                btn.innerHTML = '<i class="fas fa-toggle-off"></i> Maintenance OFF';
                btn.classList.remove('btn-warning');
                btn.classList.add('btn-secondary');
            }
        }
        
        showAlert('Maintenance mode updated', 'success');
    } catch (error) {
        console.error('Error:', error);
        showAlert('Failed to update maintenance mode', 'danger');
    }
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? All their scan data will be lost.')) {
        return;
    }
    
    try {
        const response = await fetch(`/admin/user/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ action: 'delete' })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            document.getElementById(`user-${userId}`).remove();
            showAlert('User deleted successfully', 'success');
        } else {
            showAlert(data.error || 'Failed to delete user', 'danger');
        }
    } catch (error) {
        console.error('Error:', error);
        showAlert('Failed to delete user', 'danger');
    }
}

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Scan progress animation
function showScanProgress() {
    const progressDiv = document.createElement('div');
    progressDiv.className = 'scan-progress';
    progressDiv.innerHTML = `
        <div class="text-center">
            <div class="spinner mb-3"></div>
            <p>Analyzing URL for phishing indicators...</p>
            <div class="progress">
                <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
            </div>
        </div>
    `;
    
    document.querySelector('.scan-form').appendChild(progressDiv);
}
// Math question functions
function refreshMathQuestion() {
    fetch('/new_math_question')
        .then(response => response.json())
        .then(data => {
            const mathQuestion = document.getElementById('math-question');
            const mathAnswer = document.getElementById('math-answer');
            
            if (mathQuestion) {
                mathQuestion.textContent = data.question;
            }
            if (mathAnswer) {
                mathAnswer.value = '';
                mathAnswer.focus();
            }
        })
        .catch(error => {
            console.error('Error refreshing math question:', error);
            alert('Failed to refresh math question. Please try again.');
        });
}

// Initialize math question refresh buttons
document.addEventListener('DOMContentLoaded', function() {
    const refreshMathBtns = document.querySelectorAll('#refresh-math');
    refreshMathBtns.forEach(btn => {
        btn.addEventListener('click', refreshMathQuestion);
    });
});
// Reset Scans - Single checkbox
document.getElementById('confirmResetScans').addEventListener('change', function() {
    document.getElementById('resetScansBtn').disabled = !this.checked;
});

// Reset Database - Requires BOTH checkboxes
document.getElementById('confirmResetDB1').addEventListener('change', updateResetDatabaseButton);
document.getElementById('confirmResetDB2').addEventListener('change', updateResetDatabaseButton);

function updateResetDatabaseButton() {
    const check1 = document.getElementById('confirmResetDB1').checked;
    const check2 = document.getElementById('confirmResetDB2').checked;
    document.getElementById('resetDatabaseBtn').disabled = !(check1 && check2);
}
