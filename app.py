#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import string
import random
import re
import hashlib
import secrets
import time
import json
import bcrypt
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'farhan-modz-super-secret-key-2024-secure')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# CORS - Allow all for simplicity
CORS(app)

# In-memory storage (works on Vercel)
users = {}
keys = {}
api_connections = {}
key_counter = 1
api_counter = 1

# Initialize default users
def init_default_users():
    global users
    if not users:
        # Default admin
        admin_password = bcrypt.hashpw('Admin@2024'.encode('utf-8'), bcrypt.gensalt())
        users['admin'] = {
            'id': 1,
            'username': 'admin',
            'email': 'admin@modz.com',
            'password': admin_password.decode('utf-8'),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'is_admin': True,
            'is_owner': True,
            'is_banned': False
        }
        
        # Default farhan user
        farhan_password = bcrypt.hashpw('Farhan@2024'.encode('utf-8'), bcrypt.gensalt())
        users['farhan'] = {
            'id': 2,
            'username': 'farhan',
            'email': 'farhan@modz.com',
            'password': farhan_password.decode('utf-8'),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'is_admin': True,
            'is_owner': True,
            'is_banned': False
        }

# Initialize on first request
init_default_users()

# Utility functions
def get_utc_now():
    return datetime.now(timezone.utc).isoformat()

def get_user(username):
    return users.get(username)

def get_user_by_email(email):
    for user in users.values():
        if user['email'] == email:
            return user
    return None

def get_user_by_id(user_id):
    for user in users.values():
        if user['id'] == user_id:
            return user
    return None

def validate_username(username):
    if not username:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_email(email):
    if not email:
        return False
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def validate_password(password):
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_custom_format(pattern):
    if not pattern:
        return False
    allowed_chars = set('XXx9Hh?*' + string.ascii_letters + string.digits + '-_')
    return all(c in allowed_chars for c in pattern) and len(pattern) > 0

def generate_key(format_type='default'):
    chars = string.ascii_uppercase + string.digits
    if format_type == 'default':
        return ''.join(secrets.choice(chars) for _ in range(32))
    elif format_type == 'hex':
        return ''.join(secrets.choice('0123456789ABCDEF') for _ in range(32))
    elif format_type == 'mixed':
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    elif format_type == 'numbers':
        return ''.join(secrets.choice(string.digits) for _ in range(32))
    elif format_type == 'lowercase':
        return ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(32))
    elif format_type == 'uppercase':
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    else:
        return ''.join(secrets.choice(chars) for _ in range(32))

def generate_custom_key(pattern):
    result = []
    chars_upper = string.ascii_uppercase
    chars_lower = string.ascii_lowercase
    chars_digits = string.digits
    chars_hex = '0123456789ABCDEF'
    
    for char in pattern:
        if char == 'X':
            result.append(secrets.choice(chars_upper))
        elif char == 'x':
            result.append(secrets.choice(chars_lower))
        elif char == '9':
            result.append(secrets.choice(chars_digits))
        elif char == 'H':
            result.append(secrets.choice(chars_hex))
        elif char == 'h':
            result.append(secrets.choice(chars_hex.lower()))
        elif char == '?':
            result.append(secrets.choice(chars_upper + chars_digits))
        elif char == '*':
            result.append(secrets.choice(chars_upper + chars_lower + chars_digits))
        else:
            result.append(char)
    return ''.join(result)

def generate_unique_key(format_type='default', custom_pattern=None, max_attempts=20):
    for _ in range(max_attempts):
        if custom_pattern:
            key = generate_custom_key(custom_pattern)
        else:
            key = generate_key(format_type)
        
        if key not in keys:
            return key
    
    # Fallback
    timestamp = int(time.time() * 1000)
    return f"KEY-{timestamp}-{secrets.token_hex(8)}"

def generate_api_key():
    chars = string.ascii_letters + string.digits
    api_key = 'fm_' + ''.join(secrets.choice(chars) for _ in range(32))
    
    for conn in api_connections.values():
        if conn['api_key'] == api_key:
            return generate_api_key()
    return api_key

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Templates (same as before, but compressed for Vercel)
INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Farhan Modz Online Key Generator</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; font-family: 'Courier New', monospace; color: #00ffcc; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 30px; border-bottom: 2px solid #00ffcc; margin-bottom: 30px; }
        .header h1 { font-size: 2.5rem; color: #00ffcc; text-shadow: 0 0 20px rgba(0,255,204,0.3); }
        .header p { color: #666; margin-top: 10px; }
        .card { background: #111; border: 1px solid #00ffcc; border-radius: 10px; padding: 25px; margin-bottom: 20px; }
        .card-title { color: #00ffcc; font-size: 1.2rem; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        input, select { width: 100%; padding: 12px; background: #0a0a0a; border: 1px solid #00ffcc; border-radius: 5px; color: #00ffcc; font-family: monospace; font-size: 1rem; margin-bottom: 10px; }
        input:focus, select:focus { outline: none; box-shadow: 0 0 20px rgba(0,255,204,0.2); }
        .btn { padding: 12px 25px; background: #00ffcc; color: #000; border: none; border-radius: 5px; font-size: 1rem; font-weight: bold; cursor: pointer; transition: all 0.3s; font-family: monospace; margin: 5px; }
        .btn:hover { background: #00ccaa; transform: scale(1.02); }
        .btn-danger { background: #ff0066; color: #fff; }
        .btn-danger:hover { background: #cc0055; }
        .btn-warning { background: #ffaa00; color: #000; }
        .btn-warning:hover { background: #cc8800; }
        .btn-success { background: #00cc66; color: #000; }
        .btn-success:hover { background: #009955; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
        .key-display { background: #0a0a0a; padding: 15px; border-radius: 5px; border: 1px solid #00ffcc; margin: 10px 0; word-break: break-all; }
        .key-display span { color: #ff0066; }
        .table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .table th, .table td { padding: 10px; border: 1px solid #333; text-align: left; }
        .table th { background: #1a1a1a; color: #00ffcc; }
        .table td { color: #00ffcc; }
        .status-active { color: #00cc66; }
        .status-expired { color: #ff0066; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.95); z-index: 1000; justify-content: center; align-items: center; }
        .modal-content { background: #0a0a0a; border: 1px solid #00ffcc; border-radius: 10px; padding: 30px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; border-bottom: 1px solid #00ffcc; padding-bottom: 10px; margin-bottom: 15px; }
        .modal-header h3 { color: #00ffcc; }
        .close { color: #ff0066; font-size: 24px; cursor: pointer; }
        .nav { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #333; margin-bottom: 20px; }
        .nav a { color: #00ffcc; text-decoration: none; margin: 0 10px; }
        .nav a:hover { color: #ff0066; }
        .user-info { color: #666; font-size: 0.9rem; }
        .telegram-link { color: #0088cc; text-decoration: none; }
        .telegram-link:hover { text-decoration: underline; }
        .api-status { color: #00cc66; font-weight: bold; }
        @media (max-width: 768px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } .header h1 { font-size: 1.8rem; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Farhan Modz Online Key Generator</h1>
            <p>Generate and manage your license keys</p>
            <p style="font-size:0.8rem; color:#666; margin-top:5px;">
                Made By: @FarhanModzBack | 
                <a href="https://t.me/+VTaPNYle6eViNmQx" target="_blank" class="telegram-link">Join Telegram Channel</a> |
                <a href="https://t.me/Farhan_Modz" target="_blank" class="telegram-link">Join Developers Team</a>
            </p>
        </div>
        
        {% if not session.user_id %}
        <div class="card">
            <div class="card-title">Welcome</div>
            <p style="color:#666; margin-bottom:15px;">Please login or sign up to access the key generator</p>
            <div class="grid-2">
                <a href="{{ url_for('login') }}" class="btn" style="text-align:center; text-decoration:none;">Login</a>
                <a href="{{ url_for('signup') }}" class="btn btn-success" style="text-align:center; text-decoration:none;">Sign Up</a>
            </div>
        </div>
        {% else %}
        
        <div class="nav">
            <div>
                <span class="user-info">User: {{ session.username }}</span>
                {% if session.is_admin %}
                <span style="color:#ff0066; margin-left:10px;">[Admin]</span>
                {% endif %}
                {% if session.is_owner %}
                <span style="color:#ffaa00; margin-left:10px;">[Owner]</span>
                {% endif %}
            </div>
            <div>
                <a href="{{ url_for('logout') }}" class="btn btn-danger" style="font-size:0.8rem; padding:8px 15px; text-decoration:none;">Logout</a>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">Online Key Generator</div>
            <div class="grid-3">
                <div>
                    <label>Devices Number</label>
                    <input type="number" id="devicesInput" value="1" min="1" max="1000">
                </div>
                <div>
                    <label>Expire Date</label>
                    <input type="datetime-local" id="expireInput">
                </div>
                <div>
                    <label>Key Format</label>
                    <select id="keyFormat">
                        <option value="default">Default (32 chars)</option>
                        <option value="hex">Hex (0-9A-F)</option>
                        <option value="mixed">Mixed Case + Numbers</option>
                        <option value="numbers">Only Numbers</option>
                        <option value="lowercase">Lowercase + Numbers</option>
                        <option value="uppercase">Uppercase + Numbers</option>
                        <option value="custom">Custom Format</option>
                    </select>
                </div>
            </div>
            <div class="grid-2" style="margin-top:10px;">
                <div>
                    <label>Custom Format (optional)</label>
                    <input type="text" id="customFormat" placeholder="Enter custom format (e.g., KEY-XXXX-XXXX)" disabled>
                </div>
            </div>
            <button class="btn btn-success" onclick="generateKey()">Generate Key</button>
        </div>
        
        <div class="card">
            <div class="card-title">Your Keys</div>
            <div id="keysList"><p style="color:#666;">Loading keys...</p></div>
        </div>
        
        <div class="card">
            <div class="card-title">API Connection</div>
            <div id="apiStatus" class="api-status">API Status: Online - Enjoy!</div>
            <p style="color:#666; margin-bottom:10px;">Use this API key in your panel: <span style="color:#ff0066;">/api/connect</span></p>
            <div id="apiKeyDisplay"><p style="color:#666;">Loading API key...</p></div>
            <button class="btn btn-warning" onclick="generateApiKey()">Generate API Key</button>
        </div>
        
        <div class="card">
            <div class="card-title">Stats</div>
            <div id="statsDisplay"><p style="color:#666;">Loading stats...</p></div>
        </div>
        
        <div class="card" style="border-color:#ff0066;">
            <div class="card-title" style="color:#ff0066;">Information</div>
            <p style="color:#666; font-size:0.9rem;">
                <strong>Farhan Modz Online Key Generator</strong><br>
                - Generate license keys for your applications<br>
                - Each key works for specified number of devices<br>
                - Keys expire automatically after set date<br>
                - API access available for developers<br>
                - All keys are securely stored<br><br>
                <strong>Made By:</strong> @FarhanModzBack<br>
                <strong>Telegram Channel:</strong> <a href="https://t.me/+VTaPNYle6eViNmQx" target="_blank" class="telegram-link">Join Channel</a><br>
                <strong>Developers Team:</strong> <a href="https://t.me/Farhan_Modz" target="_blank" class="telegram-link">Join Team</a>
            </p>
        </div>
        {% endif %}
    </div>
    
    <div id="modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Key Details</h3>
                <span class="close" onclick="closeModal()">x</span>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const formatSelect = document.getElementById('keyFormat');
            const customField = document.getElementById('customFormat');
            if (formatSelect) {
                formatSelect.addEventListener('change', function() {
                    if (this.value === 'custom') {
                        customField.disabled = false;
                        customField.placeholder = 'Enter custom format (e.g., KEY-XXXX-XXXX)';
                    } else {
                        customField.disabled = true;
                        customField.value = '';
                        customField.placeholder = 'Enter custom format (e.g., KEY-XXXX-XXXX)';
                    }
                });
            }
        });
        
        fetch('/api/connect')
            .then(res => res.json())
            .then(data => {
                if (data.status) {
                    const el = document.getElementById('apiStatus');
                    if (el) el.textContent = 'API Status: ' + data.status;
                }
            })
            .catch(() => {});
        
        {% if session.user_id %}
        loadKeys();
        loadApiKey();
        loadStats();
        {% endif %}
        
        function loadKeys() {
            fetch('/api/keys')
                .then(res => res.json())
                .then(data => {
                    const container = document.getElementById('keysList');
                    if (data.keys && data.keys.length > 0) {
                        let html = '<table class="table"><tr><th>Key</th><th>Devices</th><th>Expires</th><th>Status</th><th>Actions</th></tr>';
                        data.keys.forEach(k => {
                            const status = k.is_active && new Date(k.expires) > new Date() ? 'Active' : 'Expired';
                            const statusClass = status === 'Active' ? 'status-active' : 'status-expired';
                            html += `<tr>
                                <td><span style="font-size:0.8rem;">${k.key}</span></td>
                                <td>${k.devices}</td>
                                <td>${k.expires}</td>
                                <td class="${statusClass}">${status}</td>
                                <td>
                                    <button class="btn btn-warning" style="font-size:0.7rem; padding:5px 10px;" onclick="editKey('${k.key}')">Edit</button>
                                    <button class="btn btn-danger" style="font-size:0.7rem; padding:5px 10px;" onclick="deleteKey('${k.key}')">Delete</button>
                                </td>
                            </tr>`;
                        });
                        html += '</table>';
                        container.innerHTML = html;
                    } else {
                        container.innerHTML = '<p style="color:#666;">No keys found. Generate your first key!</p>';
                    }
                })
                .catch(() => {
                    document.getElementById('keysList').innerHTML = '<p style="color:#ff0066;">Error loading keys</p>';
                });
        }
        
        function generateKey() {
            const devices = document.getElementById('devicesInput').value;
            const expire = document.getElementById('expireInput').value;
            const format = document.getElementById('keyFormat').value;
            const customFormat = document.getElementById('customFormat').value;
            
            if (!expire) { 
                alert('Please select an expire date'); 
                return; 
            }
            
            const expireDate = new Date(expire);
            if (expireDate <= new Date()) {
                alert('Expire date must be in the future');
                return;
            }
            
            const data = {
                devices: parseInt(devices) || 1,
                expires: expire,
                format: format
            };
            
            if (format === 'custom' && customFormat) {
                data.custom_format = customFormat;
            }
            
            fetch('/api/key/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) { 
                    alert('Key generated successfully!'); 
                    loadKeys(); 
                    loadStats();
                } else { 
                    alert('Error: ' + (data.error || 'Unknown error')); 
                }
            })
            .catch(() => alert('Error generating key'));
        }
        
        function deleteKey(key) {
            if (!confirm('Delete key: ' + key + '?')) return;
            fetch('/api/key/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: key })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) { 
                    alert('Key deleted!'); 
                    loadKeys();
                    loadStats();
                } else { 
                    alert('Error: ' + (data.error || 'Unknown error')); 
                }
            })
            .catch(() => alert('Error deleting key'));
        }
        
        function editKey(key) {
            const modal = document.getElementById('modal');
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            modalTitle.textContent = 'Edit Key: ' + key;
            modalBody.innerHTML = `
                <label>Devices</label>
                <input type="number" id="editDevices" value="1" min="1" max="1000">
                <label>Expire Date</label>
                <input type="datetime-local" id="editExpire">
                <br><br>
                <button class="btn btn-success" onclick="updateKey('${key}')">Update Key</button>
                <button class="btn btn-danger" onclick="closeModal()">Cancel</button>
            `;
            modal.style.display = 'flex';
        }
        
        function updateKey(key) {
            const devices = document.getElementById('editDevices').value;
            const expire = document.getElementById('editExpire').value;
            
            if (!expire) { 
                alert('Please select an expire date'); 
                return; 
            }
            
            const expireDate = new Date(expire);
            if (expireDate <= new Date()) {
                alert('Expire date must be in the future');
                return;
            }
            
            fetch('/api/key/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    key: key, 
                    devices: parseInt(devices) || 1, 
                    expires: expire 
                })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) { 
                    alert('Key updated!'); 
                    closeModal(); 
                    loadKeys();
                    loadStats();
                } else { 
                    alert('Error: ' + (data.error || 'Unknown error')); 
                }
            })
            .catch(() => alert('Error updating key'));
        }
        
        function loadApiKey() {
            fetch('/api/connect')
                .then(res => res.json())
                .then(data => {
                    const container = document.getElementById('apiKeyDisplay');
                    if (data.api_key) {
                        container.innerHTML = `
                            <div class="key-display">
                                <span>API Key:</span> ${data.api_key}
                            </div>
                            <p style="color:#666; font-size:0.8rem;">Use this key in your panel header: X-API-Key</p>
                        `;
                    } else {
                        container.innerHTML = '<p style="color:#666;">No API key found. Generate one!</p>';
                    }
                })
                .catch(() => {
                    document.getElementById('apiKeyDisplay').innerHTML = '<p style="color:#ff0066;">Error loading API key</p>';
                });
        }
        
        function generateApiKey() {
            fetch('/api/connect/generate', { 
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) { 
                    alert('API Key generated successfully!'); 
                    loadApiKey(); 
                } else { 
                    alert('Error: ' + (data.error || 'Unknown error')); 
                }
            })
            .catch(() => alert('Error generating API key'));
        }
        
        function loadStats() {
            fetch('/api/stats')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('statsDisplay').innerHTML = `
                        <div class="grid-3">
                            <div style="background:#0a0a0a;padding:15px;border-radius:5px;border:1px solid #00ffcc;">
                                <h3 style="color:#00ffcc;">${data.total_keys || 0}</h3>
                                <p style="color:#666;">Total Keys</p>
                            </div>
                            <div style="background:#0a0a0a;padding:15px;border-radius:5px;border:1px solid #00ffcc;">
                                <h3 style="color:#00cc66;">${data.active_keys || 0}</h3>
                                <p style="color:#666;">Active Keys</p>
                            </div>
                            <div style="background:#0a0a0a;padding:15px;border-radius:5px;border:1px solid #00ffcc;">
                                <h3 style="color:#ff0066;">${data.expired_keys || 0}</h3>
                                <p style="color:#666;">Expired Keys</p>
                            </div>
                        </div>
                    `;
                })
                .catch(() => {
                    document.getElementById('statsDisplay').innerHTML = '<p style="color:#ff0066;">Error loading stats</p>';
                });
        }
        
        function closeModal() {
            document.getElementById('modal').style.display = 'none';
        }
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') { closeModal(); }
        });
        
        window.onclick = function(event) {
            const modal = document.getElementById('modal');
            if (event.target == modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Farhan Modz</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; font-family: 'Courier New', monospace; color: #00ffcc; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .login-box { background: #111; border: 1px solid #00ffcc; border-radius: 10px; padding: 40px; max-width: 400px; width: 90%; }
        .login-box h1 { text-align: center; margin-bottom: 30px; font-size: 1.8rem; }
        .login-box input { width: 100%; padding: 12px; background: #0a0a0a; border: 1px solid #00ffcc; border-radius: 5px; color: #00ffcc; font-family: monospace; font-size: 1rem; margin-bottom: 15px; }
        .login-box input:focus { outline: none; box-shadow: 0 0 20px rgba(0,255,204,0.2); }
        .btn { width: 100%; padding: 12px; background: #00ffcc; color: #000; border: none; border-radius: 5px; font-size: 1rem; font-weight: bold; cursor: pointer; transition: all 0.3s; font-family: monospace; }
        .btn:hover { background: #00ccaa; transform: scale(1.02); }
        .link { color: #666; text-align: center; margin-top: 15px; }
        .link a { color: #00ffcc; text-decoration: none; }
        .link a:hover { color: #ff0066; }
        .error { color: #ff0066; text-align: center; margin-bottom: 15px; padding: 10px; border: 1px solid #ff0066; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Farhan Modz</h1>
        <h3 style="text-align:center; color:#666; margin-bottom:20px;">Login</h3>
        {% with messages = get_flashed_messages() %}
        {% if messages %}
        <div class="error">{{ messages[0] }}</div>
        {% endif %}
        {% endwith %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="link">Don't have an account? <a href="{{ url_for('signup') }}">Sign Up</a></div>
        <div class="link" style="margin-top:5px;"><a href="{{ url_for('index') }}">Back to Home</a></div>
    </div>
</body>
</html>
'''

SIGNUP_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - Farhan Modz</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; font-family: 'Courier New', monospace; color: #00ffcc; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .signup-box { background: #111; border: 1px solid #00ffcc; border-radius: 10px; padding: 40px; max-width: 400px; width: 90%; }
        .signup-box h1 { text-align: center; margin-bottom: 30px; font-size: 1.8rem; }
        .signup-box input { width: 100%; padding: 12px; background: #0a0a0a; border: 1px solid #00ffcc; border-radius: 5px; color: #00ffcc; font-family: monospace; font-size: 1rem; margin-bottom: 15px; }
        .signup-box input:focus { outline: none; box-shadow: 0 0 20px rgba(0,255,204,0.2); }
        .btn { width: 100%; padding: 12px; background: #00ffcc; color: #000; border: none; border-radius: 5px; font-size: 1rem; font-weight: bold; cursor: pointer; transition: all 0.3s; font-family: monospace; }
        .btn:hover { background: #00ccaa; transform: scale(1.02); }
        .link { color: #666; text-align: center; margin-top: 15px; }
        .link a { color: #00ffcc; text-decoration: none; }
        .link a:hover { color: #ff0066; }
        .error { color: #ff0066; text-align: center; margin-bottom: 15px; padding: 10px; border: 1px solid #ff0066; border-radius: 5px; }
        .agreement { margin: 15px 0; font-size: 0.8rem; color: #666; border: 1px solid #333; padding: 10px; border-radius: 5px; }
        .agreement input { width: auto; margin-right: 10px; }
        .password-requirements { font-size: 0.7rem; color: #666; margin-top: -5px; margin-bottom: 10px; }
        .password-requirements ul { list-style: none; padding-left: 10px; }
        .password-requirements li:before { content: "• "; }
        .password-requirements .valid { color: #00cc66; }
        .password-requirements .invalid { color: #ff0066; }
    </style>
</head>
<body>
    <div class="signup-box">
        <h1>Farhan Modz</h1>
        <h3 style="text-align:center; color:#666; margin-bottom:20px;">Sign Up</h3>
        {% with messages = get_flashed_messages() %}
        {% if messages %}
        <div class="error">{{ messages[0] }}</div>
        {% endif %}
        {% endwith %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username (3-20 chars, alphanumeric)" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password (min 8 chars)" required id="password">
            <div class="password-requirements">
                <ul>
                    <li id="req-length" class="invalid">At least 8 characters</li>
                    <li id="req-upper" class="invalid">At least one uppercase letter</li>
                    <li id="req-lower" class="invalid">At least one lowercase letter</li>
                    <li id="req-number" class="invalid">At least one number</li>
                </ul>
            </div>
            <div class="agreement">
                <input type="checkbox" id="agree" name="agree" required>
                <label for="agree">I agree to the Farhan Modz terms and conditions</label>
            </div>
            <button type="submit" class="btn">Sign Up</button>
        </form>
        <div class="link">Already have an account? <a href="{{ url_for('login') }}">Login</a></div>
        <div class="link" style="margin-top:5px;"><a href="{{ url_for('index') }}">Back to Home</a></div>
    </div>
    
    <script>
        document.getElementById('password').addEventListener('input', function() {
            const pwd = this.value;
            const reqs = [
                { id: 'req-length', valid: pwd.length >= 8 },
                { id: 'req-upper', valid: /[A-Z]/.test(pwd) },
                { id: 'req-lower', valid: /[a-z]/.test(pwd) },
                { id: 'req-number', valid: /[0-9]/.test(pwd) }
            ];
            reqs.forEach(req => {
                const element = document.getElementById(req.id);
                if (req.valid) {
                    element.className = 'valid';
                } else {
                    element.className = 'invalid';
                }
            });
        });
    </script>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password required')
            return render_template_string(LOGIN_TEMPLATE)
        
        user = get_user(username)
        
        if user:
            try:
                if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                    if user.get('is_banned', False):
                        flash('Account is banned')
                        return render_template_string(LOGIN_TEMPLATE)
                    
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['is_admin'] = bool(user.get('is_admin', False))
                    session['is_owner'] = bool(user.get('is_owner', False))
                    
                    return redirect(url_for('index'))
            except Exception as e:
                print(f"Login error: {e}")
        
        flash('Invalid username or password')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('user_id'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        agree = request.form.get('agree')
        
        if not username or not email or not password:
            flash('All fields are required')
            return render_template_string(SIGNUP_TEMPLATE)
        
        if not agree:
            flash('You must agree to the terms and conditions')
            return render_template_string(SIGNUP_TEMPLATE)
        
        if not validate_username(username):
            flash('Username must be 3-20 characters and contain only letters, numbers, and underscores')
            return render_template_string(SIGNUP_TEMPLATE)
        
        if not validate_email(email):
            flash('Invalid email address')
            return render_template_string(SIGNUP_TEMPLATE)
        
        valid, message = validate_password(password)
        if not valid:
            flash(message)
            return render_template_string(SIGNUP_TEMPLATE)
        
        if get_user(username):
            flash('Username already taken')
            return render_template_string(SIGNUP_TEMPLATE)
        
        if get_user_by_email(email):
            flash('Email already registered')
            return render_template_string(SIGNUP_TEMPLATE)
        
        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            global key_counter
            key_counter += 1
            user = {
                'id': key_counter,
                'username': username,
                'email': email,
                'password': hashed_password.decode('utf-8'),
                'created_at': get_utc_now(),
                'is_admin': False,
                'is_owner': False,
                'is_banned': False
            }
            users[username] = user
            
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = False
            session['is_owner'] = False
            
            flash('Account created successfully!')
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Signup error: {e}")
            flash('An error occurred during signup. Please try again.')
    
    return render_template_string(SIGNUP_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# API Routes
@app.route('/api/connect', methods=['GET'])
def api_connect():
    user_id = session.get('user_id')
    if user_id:
        for conn in api_connections.values():
            if conn['user_id'] == user_id and conn['is_active']:
                return jsonify({
                    'status': 'Online - Enjoy!',
                    'api_key': conn['api_key']
                })
        return jsonify({'status': 'Online - Enjoy!', 'api_key': None})
    return jsonify({'status': 'Online - Enjoy!', 'message': 'Login to get your API key'})

@app.route('/api/connect/generate', methods=['POST'])
@login_required
def generate_api_connection():
    user_id = session.get('user_id')
    
    # Deactivate old API keys
    for conn in api_connections.values():
        if conn['user_id'] == user_id:
            conn['is_active'] = False
    
    global api_counter
    api_counter += 1
    api_key = generate_api_key()
    
    conn = {
        'id': api_counter,
        'user_id': user_id,
        'api_key': api_key,
        'created_at': get_utc_now(),
        'is_active': True
    }
    api_connections[api_key] = conn
    
    return jsonify({'success': True, 'api_key': api_key})

@app.route('/api/key/generate', methods=['POST'])
@login_required
def generate_key_api():
    user_id = session.get('user_id')
    
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    devices = data.get('devices', 1)
    expires_str = data.get('expires')
    key_format = data.get('format', 'default')
    custom_format = data.get('custom_format', '')
    
    if not expires_str:
        return jsonify({'error': 'Expire date required'}), 400
    
    try:
        expires = datetime.strptime(expires_str, '%Y-%m-%dT%H:%M')
        expires = expires.replace(tzinfo=timezone.utc)
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DDTHH:MM'}), 400
    
    if expires < datetime.now(timezone.utc):
        return jsonify({'error': 'Expire date must be in the future'}), 400
    
    try:
        devices = int(devices)
        if devices < 1 or devices > 1000:
            return jsonify({'error': 'Devices must be between 1 and 1000'}), 400
    except:
        return jsonify({'error': 'Invalid devices count'}), 400
    
    if key_format == 'custom':
        if not custom_format:
            return jsonify({'error': 'Custom format pattern required'}), 400
        if not validate_custom_format(custom_format):
            return jsonify({'error': 'Invalid custom format pattern'}), 400
    
    try:
        if key_format == 'custom':
            key_string = generate_unique_key(custom_pattern=custom_format)
        else:
            key_string = generate_unique_key(format_type=key_format)
    except Exception as e:
        print(f"Key generation error: {e}")
        key_string = f"FM-{secrets.token_hex(16)}"
    
    global key_counter
    key_counter += 1
    key = {
        'id': key_counter,
        'key': key_string,
        'devices': devices,
        'expires': expires.isoformat(),
        'created_at': get_utc_now(),
        'user_id': user_id,
        'is_active': True
    }
    keys[key_string] = key
    
    return jsonify({
        'success': True,
        'key': {
            'key': key_string,
            'devices': devices,
            'expires': expires.isoformat()
        }
    })

@app.route('/api/key/delete', methods=['POST'])
@login_required
def delete_key_api():
    user_id = session.get('user_id')
    
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    key_string = data.get('key')
    if not key_string:
        return jsonify({'error': 'Key required'}), 400
    
    key = keys.get(key_string)
    if not key or key['user_id'] != user_id:
        return jsonify({'error': 'Key not found'}), 404
    
    del keys[key_string]
    return jsonify({'success': True})

@app.route('/api/key/update', methods=['POST'])
@login_required
def update_key_api():
    user_id = session.get('user_id')
    
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    key_string = data.get('key')
    devices = data.get('devices')
    expires_str = data.get('expires')
    
    if not key_string:
        return jsonify({'error': 'Key required'}), 400
    
    key = keys.get(key_string)
    if not key or key['user_id'] != user_id:
        return jsonify({'error': 'Key not found'}), 404
    
    if devices is not None:
        try:
            devices = int(devices)
            if devices < 1 or devices > 1000:
                return jsonify({'error': 'Devices must be between 1 and 1000'}), 400
            key['devices'] = devices
        except:
            return jsonify({'error': 'Invalid devices count'}), 400
    
    if expires_str:
        try:
            expires = datetime.strptime(expires_str, '%Y-%m-%dT%H:%M')
            expires = expires.replace(tzinfo=timezone.utc)
            if expires < datetime.now(timezone.utc):
                return jsonify({'error': 'Expire date must be in the future'}), 400
            key['expires'] = expires.isoformat()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
    
    return jsonify({'success': True})

@app.route('/api/keys', methods=['GET'])
@login_required
def get_keys():
    user_id = session.get('user_id')
    
    user_keys = [k for k in keys.values() if k['user_id'] == user_id]
    user_keys.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({
        'keys': [{
            'key': k['key'],
            'devices': k['devices'],
            'expires': k['expires'],
            'is_active': k['is_active'],
            'created_at': k['created_at']
        } for k in user_keys]
    })

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    user_id = session.get('user_id')
    now = datetime.now(timezone.utc).isoformat()
    
    user_keys = [k for k in keys.values() if k['user_id'] == user_id]
    total_keys = len(user_keys)
    
    active_keys = 0
    expired_keys = 0
    
    for k in user_keys:
        if k['is_active'] and k['expires'] > now:
            active_keys += 1
        else:
            expired_keys += 1
            if k['is_active']:
                k['is_active'] = False
    
    return jsonify({
        'total_keys': total_keys,
        'active_keys': active_keys,
        'expired_keys': expired_keys
    })

@app.route('/api/validate', methods=['POST'])
def validate_key():
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    key_string = data.get('key')
    if not key_string:
        return jsonify({'error': 'Key required'}), 400
    
    key = keys.get(key_string)
    if not key:
        return jsonify({'valid': False, 'error': 'Key not found'}), 404
    
    if not key['is_active']:
        return jsonify({'valid': False, 'error': 'Key is inactive'}), 403
    
    expires = datetime.fromisoformat(key['expires'])
    if expires < datetime.now(timezone.utc):
        key['is_active'] = False
        return jsonify({'valid': False, 'error': 'Key expired'}), 403
    
    return jsonify({
        'valid': True,
        'devices': key['devices'],
        'expires': key['expires']
    })

# Admin routes
@app.route('/api/admin/users', methods=['GET'])
@login_required
def admin_get_users():
    if not session.get('is_admin', False) and not session.get('is_owner', False):
        return jsonify({'error': 'Admin access required'}), 403
    
    users_list = list(users.values())
    return jsonify({'users': users_list})

@app.route('/api/admin/user/<int:user_id>/ban', methods=['POST'])
@login_required
def admin_ban_user(user_id):
    if not session.get('is_admin', False) and not session.get('is_owner', False):
        return jsonify({'error': 'Admin access required'}), 403
    
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot ban yourself'}), 400
    
    for user in users.values():
        if user['id'] == user_id:
            user['is_banned'] = True
            return jsonify({'success': True, 'message': 'User banned successfully'})
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/admin/user/<int:user_id>/unban', methods=['POST'])
@login_required
def admin_unban_user(user_id):
    if not session.get('is_admin', False) and not session.get('is_owner', False):
        return jsonify({'error': 'Admin access required'}), 403
    
    for user in users.values():
        if user['id'] == user_id:
            user['is_banned'] = False
            return jsonify({'success': True, 'message': 'User unbanned successfully'})
    
    return jsonify({'error': 'User not found'}), 404

# Error handlers
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>404 - Not Found</title>
    <style>body{background:#0a0a0a;color:#00ffcc;font-family:'Courier New',monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;}
    a{color:#ff0066;text-decoration:none;}a:hover{color:#00ffcc;}
    </style>
    </head>
    <body>
    <div><h1>404 - Page Not Found</h1><p>The page you're looking for doesn't exist.</p><p><a href="/">Go Home</a></p></div>
    </body>
    </html>
    ''', 404

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>500 - Server Error</title>
    <style>body{background:#0a0a0a;color:#ff0066;font-family:'Courier New',monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;}
    a{color:#00ffcc;text-decoration:none;}a:hover{color:#ff0066;}
    </style>
    </head>
    <body>
    <div><h1>500 - Server Error</h1><p>Something went wrong. Please try again later.</p><p><a href="/">Go Home</a></p></div>
    </body>
    </html>
    ''', 500

# Vercel handler
def handler(request, context):
    return app(request, context)

# For local development
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)