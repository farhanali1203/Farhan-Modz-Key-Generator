from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import hashlib
import secrets
import time
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

# Store generated keys (in-memory - resets on each serverless function call)
key_store = {}

# ==================== HTML TEMPLATE ====================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>🔑 Key Generator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', system-ui, sans-serif;
        }
        body {
            min-height: 100vh;
            background: linear-gradient(145deg, #0b0e18 0%, #1a1f2f 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }
        .container {
            max-width: 750px;
            width: 100%;
            background: rgba(22, 28, 46, 0.85);
            backdrop-filter: blur(12px);
            border-radius: 2.5rem;
            padding: 2.5rem 2rem;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.04);
        }
        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: #f0f3ff;
            text-align: center;
            margin-bottom: 0.5rem;
        }
        .sub {
            color: #94a3b8;
            text-align: center;
            margin-bottom: 2rem;
            font-size: 0.95rem;
        }
        .card {
            background: rgba(15, 20, 35, 0.6);
            border-radius: 1.8rem;
            padding: 1.8rem;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }
        .input-group {
            display: flex;
            flex-wrap: wrap;
            gap: 0.8rem;
            margin-bottom: 1.8rem;
        }
        .input-group input {
            flex: 2 1 200px;
            padding: 0.9rem 1.4rem;
            border-radius: 60px;
            border: 1px solid #2d3a52;
            background: #0f1422;
            color: #f1f5f9;
            font-size: 1rem;
            outline: none;
            transition: 0.25s;
        }
        .input-group input:focus {
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.25);
        }
        .btn {
            padding: 0.9rem 2rem;
            border: none;
            border-radius: 60px;
            font-weight: 600;
            font-size: 1rem;
            background: linear-gradient(135deg, #7c3aed, #6d28d9);
            color: #fff;
            cursor: pointer;
            transition: 0.2s;
            box-shadow: 0 6px 18px rgba(124, 58, 237, 0.3);
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            flex: 1 0 auto;
            justify-content: center;
        }
        .btn:hover {
            transform: scale(1.02);
            box-shadow: 0 8px 25px rgba(124, 58, 237, 0.5);
        }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        .btn-outline {
            background: transparent;
            box-shadow: none;
            border: 1px solid #4b556b;
            color: #e2e8f0;
            flex: 0.5;
        }
        .btn-outline:hover {
            background: #1e293b;
            border-color: #8b5cf6;
        }
        .key-display {
            background: #0b0f1a;
            border-radius: 1.5rem;
            padding: 1.8rem;
            margin: 1.5rem 0;
            border: 1px solid #2a3650;
            text-align: center;
            min-height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: 0.8rem;
        }
        .key-display .placeholder {
            color: #475569;
            font-size: 1.1rem;
        }
        .key-display .key-text {
            font-family: monospace;
            font-size: 1.8rem;
            font-weight: 600;
            color: #c4b5fd;
            letter-spacing: 2px;
            word-break: break-all;
            animation: fadeIn 0.5s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }
        .key-display .loading {
            color: #a5b4fc;
            font-size: 1.1rem;
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 0.6; }
            50% { opacity: 1; }
        }
        .key-actions {
            display: flex;
            gap: 0.8rem;
            justify-content: center;
            flex-wrap: wrap;
            margin-top: 0.5rem;
        }
        .copy-btn {
            background: #1e293b;
            border: none;
            color: #cbd5e1;
            padding: 0.6rem 1.8rem;
            border-radius: 40px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s;
            border: 1px solid #334155;
        }
        .copy-btn:hover {
            background: #2d3a52;
            color: #fff;
        }
        .copy-btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }
        .meta {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            font-size: 0.85rem;
            color: #94a3b8;
            padding-top: 0.8rem;
            border-top: 1px solid #1e293b;
            gap: 0.5rem;
        }
        .meta strong {
            color: #e2e8f0;
        }
        .status-badge {
            padding: 0.3rem 1rem;
            border-radius: 30px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .status-badge.generating {
            background: rgba(251, 191, 36, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(251, 191, 36, 0.2);
        }
        .status-badge.ready {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .status-badge.waiting {
            background: rgba(148, 163, 184, 0.1);
            color: #94a3b8;
            border: 1px solid rgba(148, 163, 184, 0.1);
        }
        .footer {
            margin-top: 2rem;
            text-align: center;
            color: #475569;
            font-size: 0.75rem;
        }
        .api-info {
            background: #0d1220;
            border-radius: 1rem;
            padding: 1rem;
            margin-top: 1rem;
            border: 1px solid #29344b;
        }
        .api-info code {
            color: #a5b4fc;
            font-family: monospace;
            font-size: 0.85rem;
        }
        @media (max-width: 550px) {
            .container { padding: 1.5rem; }
            h1 { font-size: 1.8rem; }
            .key-display .key-text { font-size: 1.2rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 Key Generator</h1>
        <div class="sub">Python Flask API · Generate secure keys</div>

        <div class="card">
            <div class="input-group">
                <input type="text" id="usernameInput" placeholder="Enter your username" value="User" />
                <button class="btn" id="generateBtn">✨ Generate Key</button>
                <button class="btn btn-outline" id="resetBtn">↺ Reset</button>
            </div>

            <div class="key-display" id="keyDisplay">
                <span class="placeholder" id="placeholderText">Click "Generate Key" to create your key</span>
                <span class="key-text" id="keyText" style="display: none;"></span>
                <span class="loading" id="loadingText" style="display: none;">⏳ Generating key... Please wait 5 seconds</span>
            </div>

            <div class="key-actions">
                <button class="copy-btn" id="copyBtn" disabled>📋 Copy Key</button>
                <span class="status-badge waiting" id="statusBadge">⏳ Waiting</span>
            </div>

            <div class="meta">
                <span>👤 <strong id="displayUser">User</strong></span>
                <span>🕒 <span id="timestamp">—</span></span>
                <span>🔢 <span id="keyLength">0</span> chars</span>
            </div>

            <div class="api-info">
                <code>POST /api/generate-key</code> · 
                <code>POST /api/validate-key</code> · 
                <code>GET /api/keys</code>
            </div>
        </div>

        <div class="footer">Key Generator v2.0 · Python Flask API</div>
    </div>

    <script>
        const usernameInput = document.getElementById('usernameInput');
        const generateBtn = document.getElementById('generateBtn');
        const resetBtn = document.getElementById('resetBtn');
        const placeholderText = document.getElementById('placeholderText');
        const keyText = document.getElementById('keyText');
        const loadingText = document.getElementById('loadingText');
        const copyBtn = document.getElementById('copyBtn');
        const statusBadge = document.getElementById('statusBadge');
        const displayUser = document.getElementById('displayUser');
        const timestampEl = document.getElementById('timestamp');
        const keyLengthEl = document.getElementById('keyLength');

        let currentKey = '';
        let isGenerating = false;
        let generationTimeout = null;

        const API_URL = window.location.origin;

        async function generateKeyAPI(username) {
            try {
                const response = await fetch(`${API_URL}/api/generate-key`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username: username })
                });
                
                const data = await response.json();
                return data;
            } catch (error) {
                console.error('API Error:', error);
                return null;
            }
        }

        function displayKey(key, username, generatedAt, expiresAt) {
            currentKey = key;
            
            placeholderText.style.display = 'none';
            loadingText.style.display = 'none';
            keyText.style.display = 'block';
            keyText.textContent = key;

            displayUser.textContent = username;
            const now = new Date(generatedAt);
            timestampEl.textContent = now.toLocaleString('en-US', { hour12: false });
            keyLengthEl.textContent = key.replace(/-/g, '').length;

            copyBtn.disabled = false;
            copyBtn.textContent = '📋 Copy Key';

            statusBadge.className = 'status-badge ready';
            statusBadge.textContent = '✅ Key Ready';

            isGenerating = false;
            generateBtn.disabled = false;
            generateBtn.textContent = '✨ Generate Key';
        }

        function showLoading(username) {
            isGenerating = true;
            generateBtn.disabled = true;
            generateBtn.textContent = '⏳ Generating...';

            placeholderText.style.display = 'none';
            keyText.style.display = 'none';
            loadingText.style.display = 'block';
            loadingText.textContent = '⏳ Generating key... Please wait 5 seconds';

            copyBtn.disabled = true;
            copyBtn.textContent = '⏳ Wait...';

            statusBadge.className = 'status-badge generating';
            statusBadge.textContent = '⏳ Generating...';

            displayUser.textContent = username;
        }

        async function handleGenerate() {
            if (isGenerating) return;

            const username = usernameInput.value.trim() || 'User';
            
            if (generationTimeout) {
                clearTimeout(generationTimeout);
                generationTimeout = null;
            }

            showLoading(username);

            generationTimeout = setTimeout(async () => {
                const result = await generateKeyAPI(username);
                
                if (result && result.status === 'success') {
                    displayKey(
                        result.key,
                        result.username,
                        result.generated_at,
                        result.expires_at
                    );
                } else {
                    alert('Error generating key. Please try again.');
                    handleReset();
                }
                generationTimeout = null;
            }, 5000);
        }

        function handleReset() {
            if (generationTimeout) {
                clearTimeout(generationTimeout);
                generationTimeout = null;
            }

            usernameInput.value = 'User';
            currentKey = '';
            isGenerating = false;

            placeholderText.style.display = 'block';
            placeholderText.textContent = 'Click "Generate Key" to create your key';
            keyText.style.display = 'none';
            loadingText.style.display = 'none';

            copyBtn.disabled = true;
            copyBtn.textContent = '📋 Copy Key';

            statusBadge.className = 'status-badge waiting';
            statusBadge.textContent = '⏳ Waiting';

            displayUser.textContent = 'User';
            timestampEl.textContent = '—';
            keyLengthEl.textContent = '0';

            generateBtn.disabled = false;
            generateBtn.textContent = '✨ Generate Key';
        }

        function copyKey() {
            if (!currentKey || copyBtn.disabled) return;

            navigator.clipboard.writeText(currentKey).then(() => {
                const originalText = copyBtn.textContent;
                copyBtn.textContent = '✅ Copied!';
                setTimeout(() => {
                    copyBtn.textContent = originalText;
                }, 2000);
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = currentKey;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                const originalText = copyBtn.textContent;
                copyBtn.textContent = '✅ Copied!';
                setTimeout(() => {
                    copyBtn.textContent = originalText;
                }, 2000);
            });
        }

        generateBtn.addEventListener('click', handleGenerate);
        resetBtn.addEventListener('click', handleReset);
        copyBtn.addEventListener('click', copyKey);

        usernameInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleGenerate();
            }
        });

        handleReset();
        console.log('🔑 Key Generator with Python Flask API');
    </script>
</body>
</html>
'''

# ==================== KEY GENERATOR FUNCTIONS ====================

def generate_secure_key(username):
    """Generate a secure 16-character key with hyphens"""
    clean_user = username.strip() if username else "User"
    
    seed = f"{clean_user}{time.time()}{secrets.token_hex(16)}"
    
    hash_obj = hashlib.sha256(seed.encode())
    hash_hex = hash_obj.hexdigest()
    
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    key_parts = []
    
    for i in range(0, 16, 4):
        segment = ''
        for j in range(4):
            idx = int(hash_hex[(i + j) * 2:(i + j) * 2 + 2], 16) % len(chars)
            segment += chars[idx]
        key_parts.append(segment)
    
    return '-'.join(key_parts)

def validate_key(key, username):
    """Validate if a key exists and matches the username"""
    if key not in key_store:
        return False, "Key not found"
    
    stored_data = key_store[key]
    
    if stored_data['username'] != username:
        return False, "Username doesn't match this key"
    
    expires_at = datetime.fromisoformat(stored_data['expires_at'])
    if datetime.now() > expires_at:
        return False, "Key has expired (1 hour validity)"
    
    return True, "Key is valid"

def cleanup_expired_keys():
    """Remove expired keys from memory"""
    now = datetime.now()
    expired_keys = []
    
    for key, data in key_store.items():
        expires_at = datetime.fromisoformat(data['expires_at'])
        if now > expires_at:
            expired_keys.append(key)
    
    for key in expired_keys:
        del key_store[key]
    
    return len(expired_keys)

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/generate-key', methods=['POST'])
def generate_key_api():
    """API endpoint to generate a new key"""
    try:
        data = request.get_json()
        username = data.get('username', 'User').strip()
        
        if not username:
            username = 'User'
        
        key = generate_secure_key(username)
        
        now = datetime.now()
        expires_at = now + timedelta(hours=1)
        
        key_store[key] = {
            'username': username,
            'generated_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'created_at': time.time()
        }
        
        cleanup_expired_keys()
        
        return jsonify({
            'status': 'success',
            'key': key,
            'username': username,
            'generated_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'valid_for': 3600,
            'message': 'Key generated successfully (valid for 1 hour)'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/validate-key', methods=['POST'])
def validate_key_api():
    """API endpoint to validate a key"""
    try:
        data = request.get_json()
        key = data.get('key', '').strip()
        username = data.get('username', '').strip()
        
        if not key or not username:
            return jsonify({
                'status': 'error',
                'message': 'Key and username are required'
            }), 400
        
        is_valid, message = validate_key(key, username)
        
        return jsonify({
            'status': 'success' if is_valid else 'error',
            'valid': is_valid,
            'message': message,
            'key': key,
            'username': username
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/keys', methods=['GET'])
def list_keys():
    """List all stored keys"""
    keys_list = []
    for key, data in key_store.items():
        keys_list.append({
            'key': key,
            'username': data['username'],
            'generated_at': data['generated_at'],
            'expires_at': data['expires_at']
        })
    
    return jsonify({
        'status': 'success',
        'count': len(keys_list),
        'keys': keys_list
    }), 200

@app.route('/api/delete-key/<key>', methods=['DELETE'])
def delete_key(key):
    """Delete a specific key"""
    if key in key_store:
        del key_store[key]
        return jsonify({
            'status': 'success',
            'message': 'Key deleted successfully'
        }), 200
    else:
        return jsonify({
            'status': 'error',
            'message': 'Key not found'
        }), 404

# ==================== VERCEL HANDLER ====================

# This is the handler Vercel will use
def handler(request, context):
    """Vercel serverless function handler"""
    return app

# For local development
if __name__ == '__main__':
    print("\n" + "="*50)
    print("🔑 KEY GENERATOR API - Python Flask")
    print("="*50)
    print("📍 Server running at: http://localhost:5000")
    print("📡 API Endpoints:")
    print("   POST /api/generate-key  - Generate a new key")
    print("   POST /api/validate-key  - Validate a key")
    print("   GET  /api/keys          - List all keys")
    print("   DELETE /api/delete-key/<key> - Delete a key")
    print("="*50)
    print("✅ Open your browser and go to: http://localhost:5000")
    print("="*50 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)