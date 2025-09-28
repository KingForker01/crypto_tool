from flask import Flask, request, jsonify, render_template_string
import base64
import hashlib
import secrets
import json
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Enable CORS for debugging
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# HTML template with enhanced debugging
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Animated Crypto Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            padding: 20px;
            color: white;
            overflow-x: hidden;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
        }

        .title {
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 30px;
            text-shadow: 0 4px 15px rgba(0,0,0,0.3);
            animation: titleGlow 3s ease-in-out infinite alternate;
        }

        @keyframes titleGlow {
            from { text-shadow: 0 4px 15px rgba(0,0,0,0.3), 0 0 20px rgba(255,255,255,0.1); }
            to { text-shadow: 0 4px 15px rgba(0,0,0,0.5), 0 0 30px rgba(255,255,255,0.3); }
        }

        .input-section {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            animation: slideUp 0.8s ease-out forwards;
        }

        @keyframes slideUp {
            from {
                transform: translateY(20px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }

        .input-group {
            margin-bottom: 20px;
        }

        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: rgba(255,255,255,0.9);
        }

        .input-group input, .input-group textarea {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            background: rgba(255,255,255,0.1);
            color: white;
            font-size: 14px;
            backdrop-filter: blur(5px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: all 0.3s ease;
        }

        .input-group input:focus, .input-group textarea:focus {
            outline: none;
            background: rgba(255,255,255,0.15);
            border-color: rgba(255,255,255,0.4);
            box-shadow: 0 0 20px rgba(255,255,255,0.1);
            transform: scale(1.02);
        }

        .input-group input::placeholder, .input-group textarea::placeholder {
            color: rgba(255,255,255,0.6);
        }

        .controls {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            justify-content: center;
        }

        .btn {
            padding: 15px 30px;
            border: none;
            border-radius: 25px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            color: white;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }

        .btn:hover {
            transform: translateY(-3px) scale(1.05);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .crypto-operations {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .crypto-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transform: translateY(0);
            opacity: 1;
            transition: all 0.3s ease;
        }

        .crypto-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 45px rgba(0,0,0,0.2);
            border-color: rgba(255,255,255,0.3);
        }

        .crypto-card h3 {
            font-size: 1.4em;
            margin-bottom: 15px;
            color: #4ecdc4;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .progress-container {
            width: 100%;
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            margin: 15px 0;
            overflow: hidden;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #4ecdc4, #44a08d);
            border-radius: 10px;
            width: 0%;
            transition: width 0.3s ease;
        }

        .result {
            margin-top: 15px;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.4;
            border-left: 4px solid #4ecdc4;
            word-break: break-all;
            min-height: 50px;
        }

        .status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            margin: 10px 0;
        }

        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #666;
            transition: all 0.3s ease;
        }

        .status-indicator.running {
            background: #ff9800;
            animation: pulse 1.5s infinite;
        }

        .status-indicator.success {
            background: #4caf50;
        }

        .status-indicator.error {
            background: #f44336;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.2); }
        }

        .file-input-wrapper {
            position: relative;
            border: 2px dashed rgba(255,255,255,0.3);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            cursor: pointer;
            background: rgba(255,255,255,0.05);
        }

        #fileInput {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }

        .input-mode-selector {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
        }

        .input-mode-selector label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            padding: 8px 16px;
            border-radius: 20px;
        }

        .error-message {
            color: #ff6b6b;
            background: rgba(255, 107, 107, 0.1);
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }

        .download-btn {
            background: linear-gradient(45deg, #3498db, #2980b9);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 15px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 10px;
            transition: all 0.3s ease;
        }

        .download-btn:hover {
            background: linear-gradient(45deg, #2980b9, #21618c);
            transform: translateY(-2px);
        }

        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="title">🔐 Animated Cryptographic Tool</h1>
        
        <div class="input-section">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                <div class="input-group">
                    <label for="plaintext">Text Input:</label>
                    <textarea id="plaintext" rows="4" placeholder="Enter your message to encrypt...">The quick brown fox jumps over the lazy dog</textarea>
                </div>
                
                <div class="input-group">
                    <label for="fileInput">File Input:</label>
                    <div class="file-input-wrapper">
                        <input type="file" id="fileInput" accept="*/*" onchange="handleFileInput(this)">
                        <div id="fileInfo">Choose any file</div>
                    </div>
                </div>
            </div>
            
            <div class="input-mode-selector">
                <label>
                    <input type="radio" name="inputMode" value="text" checked onchange="switchInputMode()">
                    <span>Text Mode</span>
                </label>
                <label>
                    <input type="radio" name="inputMode" value="file" onchange="switchInputMode()">
                    <span>File Mode</span>
                </label>
            </div>
            
            <div class="controls">
                <button class="btn" onclick="runAllOperations()">🚀 Run All Operations</button>
                <button class="btn" onclick="runAESGCM()">🔒 AES-GCM</button>
                <button class="btn" onclick="runRSA()">🗝️ RSA OAEP</button>
                <button class="btn" onclick="runECDH()">🤝 ECDH</button>
                <button class="btn" onclick="runHashing()">🔢 SHA-256</button>
                <button class="btn" onclick="downloadAllResults()" style="background: linear-gradient(45deg, #2ecc71, #27ae60);">📥 Download All</button>
                <button class="btn" onclick="clearResults()" style="background: linear-gradient(45deg, #ff4757, #ff3742);">🗑️ Clear</button>
            </div>
        </div>
        
        <div class="crypto-operations">
            <div class="crypto-card" id="aes-card">
                <h3>🔒 AES-GCM (256-bit)</h3>
                <div class="status">
                    <div class="status-indicator" id="aes-status"></div>
                    <span id="aes-status-text">Ready</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar" id="aes-progress"></div>
                </div>
                <div class="result" id="aes-result">Click AES-GCM button to encrypt</div>
            </div>
            
            <div class="crypto-card" id="rsa-card">
                <h3>🗝️ RSA OAEP (2048-bit)</h3>
                <div class="status">
                    <div class="status-indicator" id="rsa-status"></div>
                    <span id="rsa-status-text">Ready</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar" id="rsa-progress"></div>
                </div>
                <div class="result" id="rsa-result">Click RSA button to encrypt (max 190 bytes)</div>
            </div>
            
            <div class="crypto-card" id="ecdh-card">
                <h3>🤝 ECDH (P-256)</h3>
                <div class="status">
                    <div class="status-indicator" id="ecdh-status"></div>
                    <span id="ecdh-status-text">Ready</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar" id="ecdh-progress"></div>
                </div>
                <div class="result" id="ecdh-result">Click ECDH button to perform key exchange</div>
            </div>
            
            <div class="crypto-card" id="hash-card">
                <h3>🔢 SHA-256 Hashing</h3>
                <div class="status">
                    <div class="status-indicator" id="hash-status"></div>
                    <span id="hash-status-text">Ready</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar" id="hash-progress"></div>
                </div>
                <div class="result" id="hash-result">Click Hash button to generate SHA-256</div>
            </div>
        </div>

        <!-- Debug panel - remove or uncomment to hide -->
        <!--
        <div class="debug-info" id="debug-info">
            <strong>Debug Log:</strong><br>
            Application loaded successfully...<br>
        </div>
        -->
    </div>

    <script>
        // Global storage for results
        let cryptoResults = {
            aes: null,
            rsa: null,
            ecdh: null,
            hash: null
        };

        // Download functionality
        function downloadFile(content, filename, contentType = 'text/plain') {
            const blob = new Blob([content], { type: contentType });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
            logDebug(`Downloaded: ${filename}`);
        }

        function downloadCryptoResult(operation) {
            const result = cryptoResults[operation];
            if (!result || !result.success) {
                alert(`No ${operation.toUpperCase()} result available to download`);
                return;
            }

            let content = '';
            let filename = '';

            switch (operation) {
                case 'aes':
                    content = `AES-GCM Encryption Results
=============================
Original File: ${result.originalName}
Original Size: ${result.originalSize} bytes
Encrypted Size: ${result.encryptedSize} bytes
Initialization Vector (IV): ${result.iv}
Encryption Time: ${result.encryptTime}ms
Algorithm: AES-GCM 256-bit

Encrypted Data (Base64):
${result.encrypted}

Generated on: ${new Date().toISOString()}
`;
                    filename = `aes_encrypted_${new Date().getTime()}.txt`;
                    break;

                case 'rsa':
                    content = `RSA-OAEP Encryption Results
===========================
Original File: ${result.originalName}
Original Size: ${result.originalSize} bytes
Encrypted Size: ${result.encryptedSize} bytes
Key Generation Time: ${result.keygenTime}ms
Algorithm: RSA-OAEP 2048-bit

Encrypted Data (Base64):
${result.encrypted}

Generated on: ${new Date().toISOString()}
`;
                    filename = `rsa_encrypted_${new Date().getTime()}.txt`;
                    break;

                case 'ecdh':
                    content = `ECDH Key Exchange Results
=========================
Key Agreement: ${result.keyAgreement ? 'Successful' : 'Failed'}
Shared Key Length: ${result.sharedKeyLength} bytes
Curve: P-256 (SECP256R1)
Algorithm: ECDH

Shared Key (Hex):
${result.sharedKey}

Generated on: ${new Date().toISOString()}
`;
                    filename = `ecdh_shared_key_${new Date().getTime()}.txt`;
                    break;

                case 'hash':
                    content = `SHA-256 Hash Results
====================
Original File: ${result.originalName}
Original Size: ${result.originalSize} bytes
Hash Time: ${result.hashTime}ms
Algorithm: SHA-256

Hash:
${result.hash}

Generated on: ${new Date().toISOString()}
`;
                    filename = `sha256_hash_${new Date().getTime()}.txt`;
                    break;
            }

            downloadFile(content, filename);
        }

        function downloadAllResults() {
            const hasResults = Object.values(cryptoResults).some(result => result && result.success);
            
            if (!hasResults) {
                alert('No results available to download. Please run some crypto operations first.');
                return;
            }

            let allContent = `CRYPTOGRAPHIC OPERATIONS REPORT
===============================================
Generated on: ${new Date().toISOString()}
Input Mode: ${currentInputMode}
`;

            if (currentInputMode === 'text') {
                allContent += `Input Text: "${document.getElementById('plaintext').value.substring(0, 100)}${document.getElementById('plaintext').value.length > 100 ? '...' : ''}"\n`;
            } else if (selectedFile) {
                allContent += `Input File: ${selectedFile.name} (${selectedFile.size} bytes)\n`;
            }

            allContent += `\n`;

            // Add each result
            if (cryptoResults.aes && cryptoResults.aes.success) {
                allContent += `
1. AES-GCM ENCRYPTION
=====================
Original Size: ${cryptoResults.aes.originalSize} bytes
Encrypted Size: ${cryptoResults.aes.encryptedSize} bytes
IV: ${cryptoResults.aes.iv}
Time: ${cryptoResults.aes.encryptTime}ms
Encrypted Data: ${cryptoResults.aes.encrypted.substring(0, 100)}...

`;
            }

            if (cryptoResults.rsa && cryptoResults.rsa.success) {
                allContent += `
2. RSA-OAEP ENCRYPTION
======================
Original Size: ${cryptoResults.rsa.originalSize} bytes
Encrypted Size: ${cryptoResults.rsa.encryptedSize} bytes
Key Generation: ${cryptoResults.rsa.keygenTime}ms
Encrypted Data: ${cryptoResults.rsa.encrypted.substring(0, 100)}...

`;
            }

            if (cryptoResults.ecdh && cryptoResults.ecdh.success) {
                allContent += `
3. ECDH KEY EXCHANGE
====================
Key Agreement: ${cryptoResults.ecdh.keyAgreement ? 'Success' : 'Failed'}
Shared Key Length: ${cryptoResults.ecdh.sharedKeyLength} bytes
Shared Key: ${cryptoResults.ecdh.sharedKey}

`;
            }

            if (cryptoResults.hash && cryptoResults.hash.success) {
                allContent += `
4. SHA-256 HASH
===============
Original Size: ${cryptoResults.hash.originalSize} bytes
Time: ${cryptoResults.hash.hashTime}ms
Hash: ${cryptoResults.hash.hash}

`;
            }

            allContent += `
===============================================
Report generated by Animated Cryptographic Tool
`;

            const filename = `crypto_report_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
            downloadFile(allContent, filename);
        }

        // Debug function - remove or comment out to disable logging
        function logDebug(message) {
            // Uncomment the lines below to re-enable debug panel
            /*
            const debugDiv = document.getElementById('debug-info');
            if (debugDiv) {
                const timestamp = new Date().toLocaleTimeString();
                debugDiv.innerHTML += `[${timestamp}] ${message}<br>`;
                debugDiv.scrollTop = debugDiv.scrollHeight;
            }
            */
            console.log(`[${new Date().toLocaleTimeString()}] ${message}`);
        }

        function handleFileInput(input) {
            const file = input.files[0];
            if (file) {
                selectedFile = file;
                document.getElementById('fileInfo').innerHTML = `Selected: ${file.name} (${file.size} bytes)`;
                document.querySelector('input[value="file"]').checked = true;
                switchInputMode();
                logDebug(`File selected: ${file.name} (${file.size} bytes)`);
            }
        }

        function switchInputMode() {
            const mode = document.querySelector('input[name="inputMode"]:checked').value;
            currentInputMode = mode;
            logDebug(`Switched to ${mode} mode`);
        }

        async function getInputData() {
            if (currentInputMode === 'text') {
                const text = document.getElementById('plaintext').value;
                if (!text.trim()) {
                    throw new Error('Please enter some text');
                }
                return {
                    data: text,
                    name: 'text_input.txt',
                    size: new Blob([text]).size,
                    type: 'text'
                };
            } else {
                if (!selectedFile) {
                    throw new Error('Please select a file first');
                }
                const reader = new FileReader();
                return new Promise((resolve, reject) => {
                    reader.onload = function(e) {
                        resolve({
                            data: e.target.result,
                            name: selectedFile.name,
                            size: selectedFile.size,
                            type: 'file'
                        });
                    };
                    reader.onerror = reject;
                    reader.readAsDataURL(selectedFile);
                });
            }
        }

        async function updateProgress(progressId, statusId, statusTextId, duration) {
            const progressBar = document.getElementById(progressId);
            const statusIndicator = document.getElementById(statusId);
            const statusText = document.getElementById(statusTextId);
            
            statusIndicator.className = 'status-indicator running';
            statusText.textContent = 'Processing...';
            
            progressBar.style.width = '0%';
            
            return new Promise(resolve => {
                let progress = 0;
                const interval = setInterval(() => {
                    progress += 4;
                    progressBar.style.width = progress + '%';
                    
                    if (progress >= 100) {
                        clearInterval(interval);
                        resolve();
                    }
                }, duration / 25);
            });
        }

        function setOperationComplete(statusId, statusTextId, success = true) {
            const statusIndicator = document.getElementById(statusId);
            const statusText = document.getElementById(statusTextId);
            
            if (success) {
                statusIndicator.className = 'status-indicator success';
                statusText.textContent = 'Completed';
            } else {
                statusIndicator.className = 'status-indicator error';
                statusText.textContent = 'Error';
            }
        }

        async function callPythonAPI(endpoint, data) {
            try {
                logDebug(`Calling API endpoint: /api/${endpoint}`);
                const response = await fetch(`/api/${endpoint}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                logDebug(`API ${endpoint} completed: ${result.success ? 'SUCCESS' : 'FAILED'}`);
                return result;
            } catch (error) {
                logDebug(`API ${endpoint} failed: ${error.message}`);
                throw error;
            }
        }

        async function runAESGCM() {
            const resultDiv = document.getElementById('aes-result');
            try {
                logDebug('Starting AES-GCM encryption...');
                const inputData = await getInputData();
                const progressPromise = updateProgress('aes-progress', 'aes-status', 'aes-status-text', 1500);
                
                const result = await callPythonAPI('aes', inputData);
                
                await progressPromise;
                
                if (result.success) {
                    cryptoResults.aes = result; // Store result for download
                    setOperationComplete('aes-status', 'aes-status-text', true);
                    resultDiv.innerHTML = `
                        <div class="result-header">
                            <strong>✓ AES-GCM Results:</strong>
                            <button class="download-btn" onclick="downloadCryptoResult('aes')">📥 Download</button>
                        </div>
                        File: ${result.originalName} (${result.originalSize} bytes)<br>
                        Encrypted Size: ${result.encryptedSize} bytes<br>
                        IV: ${result.iv.substring(0, 16)}...<br>
                        Time: ${result.encryptTime}ms<br>
                        <span style="color: #4caf50;">Status: ✓ Encryption Successful</span>
                    `;
                } else {
                    setOperationComplete('aes-status', 'aes-status-text', false);
                    resultDiv.innerHTML = `<div class="error-message"><strong>AES-GCM Error:</strong> ${result.error}</div>`;
                }
            } catch (error) {
                setOperationComplete('aes-status', 'aes-status-text', false);
                resultDiv.innerHTML = `<div class="error-message"><strong>AES-GCM Error:</strong> ${error.message}</div>`;
                logDebug(`AES-GCM Error: ${error.message}`);
            }
        }

        async function runRSA() {
            const resultDiv = document.getElementById('rsa-result');
            try {
                logDebug('Starting RSA-OAEP encryption...');
                const inputData = await getInputData();
                const progressPromise = updateProgress('rsa-progress', 'rsa-status', 'rsa-status-text', 2000);
                
                const result = await callPythonAPI('rsa', inputData);
                
                await progressPromise;
                
                if (result.success) {
                    cryptoResults.rsa = result; // Store result for download
                    setOperationComplete('rsa-status', 'rsa-status-text', true);
                    resultDiv.innerHTML = `
                        <div class="result-header">
                            <strong>✓ RSA OAEP Results:</strong>
                            <button class="download-btn" onclick="downloadCryptoResult('rsa')">📥 Download</button>
                        </div>
                        File: ${result.originalName} (${result.originalSize} bytes)<br>
                        Encrypted Size: ${result.encryptedSize} bytes<br>
                        Key Generation: ${result.keygenTime}ms<br>
                        Key Size: 2048 bits<br>
                        <span style="color: #4caf50;">Status: ✓ Encryption Successful</span>
                    `;
                } else {
                    setOperationComplete('rsa-status', 'rsa-status-text', false);
                    resultDiv.innerHTML = `<div class="error-message"><strong>RSA Error:</strong> ${result.error}</div>`;
                }
            } catch (error) {
                setOperationComplete('rsa-status', 'rsa-status-text', false);
                resultDiv.innerHTML = `<div class="error-message"><strong>RSA Error:</strong> ${error.message}</div>`;
                logDebug(`RSA Error: ${error.message}`);
            }
        }

        async function runECDH() {
            const resultDiv = document.getElementById('ecdh-result');
            try {
                logDebug('Starting ECDH key exchange...');
                const inputData = await getInputData();
                const progressPromise = updateProgress('ecdh-progress', 'ecdh-status', 'ecdh-status-text', 1800);
                
                const result = await callPythonAPI('ecdh', inputData);
                
                await progressPromise;
                
                if (result.success) {
                    cryptoResults.ecdh = result; // Store result for download
                    setOperationComplete('ecdh-status', 'ecdh-status-text', true);
                    resultDiv.innerHTML = `
                        <div class="result-header">
                            <strong>✓ ECDH Key Exchange Results:</strong>
                            <button class="download-btn" onclick="downloadCryptoResult('ecdh')">📥 Download</button>
                        </div>
                        Key Agreement: ${result.keyAgreement ? '✓ Success' : '✗ Failed'}<br>
                        Shared Key Length: ${result.sharedKeyLength} bytes<br>
                        Curve: P-256 (SECP256R1)<br>
                        Shared Key: ${result.sharedKey.substring(0, 32)}...<br>
                        <span style="color: #4caf50;">Status: ✓ Key Exchange Successful</span>
                    `;
                } else {
                    setOperationComplete('ecdh-status', 'ecdh-status-text', false);
                    resultDiv.innerHTML = `<div class="error-message"><strong>ECDH Error:</strong> ${result.error}</div>`;
                }
            } catch (error) {
                setOperationComplete('ecdh-status', 'ecdh-status-text', false);
                resultDiv.innerHTML = `<div class="error-message"><strong>ECDH Error:</strong> ${error.message}</div>`;
                logDebug(`ECDH Error: ${error.message}`);
            }
        }

        async function runHashing() {
            const resultDiv = document.getElementById('hash-result');
            try {
                logDebug('Starting SHA-256 hashing...');
                const inputData = await getInputData();
                const progressPromise = updateProgress('hash-progress', 'hash-status', 'hash-status-text', 1200);
                
                const result = await callPythonAPI('hash', inputData);
                
                await progressPromise;
                
                if (result.success) {
                    cryptoResults.hash = result; // Store result for download
                    setOperationComplete('hash-status', 'hash-status-text', true);
                    resultDiv.innerHTML = `
                        <div class="result-header">
                            <strong>✓ SHA-256 Hash Results:</strong>
                            <button class="download-btn" onclick="downloadCryptoResult('hash')">📥 Download</button>
                        </div>
                        File: ${result.originalName} (${result.originalSize} bytes)<br>
                        Algorithm: SHA-256<br>
                        Hash: ${result.hash}<br>
                        Time: ${result.hashTime}ms<br>
                        <span style="color: #4caf50;">Status: ✓ Hash Generated Successfully</span>
                    `;
                } else {
                    setOperationComplete('hash-status', 'hash-status-text', false);
                    resultDiv.innerHTML = `<div class="error-message"><strong>Hash Error:</strong> ${result.error}</div>`;
                }
            } catch (error) {
                setOperationComplete('hash-status', 'hash-status-text', false);
                resultDiv.innerHTML = `<div class="error-message"><strong>Hash Error:</strong> ${error.message}</div>`;
                logDebug(`Hash Error: ${error.message}`);
            }
        }

        function clearResults() {
            // Clear stored results
            cryptoResults = {
                aes: null,
                rsa: null,
                ecdh: null,
                hash: null
            };
            
            // Clear all result divs
            document.querySelectorAll('.result').forEach((result, index) => {
                const operations = ['AES-GCM', 'RSA', 'ECDH', 'SHA-256'];
                const messages = [
                    'Click AES-GCM button to encrypt',
                    'Click RSA button to encrypt (max 190 bytes)', 
                    'Click ECDH button to perform key exchange',
                    'Click Hash button to generate SHA-256'
                ];
                result.innerHTML = messages[index];
            });
            
            // Reset progress bars
            document.querySelectorAll('.progress-bar').forEach(bar => {
                bar.style.width = '0%';
            });
            
            // Reset status indicators
            document.querySelectorAll('.status-indicator').forEach(indicator => {
                indicator.className = 'status-indicator';
            });
            
            // Reset status text
            document.querySelectorAll('.status span').forEach(text => {
                text.textContent = 'Ready';
            });
            
            logDebug('All results cleared');
        }

        async function runAllOperations() {
            logDebug('Starting all cryptographic operations...');
            clearResults();
            
            // Disable buttons during processing
            document.querySelectorAll('.btn').forEach(btn => btn.disabled = true);
            
            try {
                // Run operations sequentially with delays
                await new Promise(resolve => {
                    setTimeout(async () => {
                        await runAESGCM();
                        resolve();
                    }, 200);
                });
                
                await new Promise(resolve => {
                    setTimeout(async () => {
                        await runRSA();
                        resolve();
                    }, 800);
                });
                
                await new Promise(resolve => {
                    setTimeout(async () => {
                        await runECDH();
                        resolve();
                    }, 1400);
                });
                
                await new Promise(resolve => {
                    setTimeout(async () => {
                        await runHashing();
                        resolve();
                    }, 2000);
                });
                
                logDebug('All operations completed successfully!');
            } catch (error) {
                logDebug(`Error in batch operations: ${error.message}`);
            } finally {
                // Re-enable buttons
                document.querySelectorAll('.btn').forEach(btn => btn.disabled = false);
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            switchInputMode();
            logDebug('Crypto tool initialized and ready');
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/aes', methods=['POST'])
def aes_encrypt():
    try:
        data = request.json
        print(f"[AES] API called with data type: {data.get('type', 'unknown')}, size: {data.get('size', 'unknown')}")
        
        input_text = data['data']
        
        # Convert input to bytes
        if data['type'] == 'text':
            input_bytes = input_text.encode('utf-8')
        else:
            # Handle base64 encoded file data
            if ',' in input_text:
                input_bytes = base64.b64decode(input_text.split(',')[1])
            else:
                input_bytes = base64.b64decode(input_text)
        
        # AES-GCM encryption
        key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(12)   # 96-bit IV for GCM
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        start_time = time.time()
        encrypted_data = encryptor.update(input_bytes) + encryptor.finalize()
        encrypt_time = (time.time() - start_time) * 1000  # Convert to ms
        
        result = {
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        print(f"[AES] Encryption successful: {len(input_bytes)} -> {len(encrypted_data)} bytes")
        return jsonify(result)
        
    except Exception as e:
        print(f"[AES] Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/rsa', methods=['POST'])
def rsa_encrypt():
    try:
        data = request.json
        print(f"[RSA] API called with data type: {data.get('type', 'unknown')}, size: {data.get('size', 'unknown')}")
        
        input_text = data['data']
        
        # Convert input to bytes
        if data['type'] == 'text':
            input_bytes = input_text.encode('utf-8')
        else:
            if ',' in input_text:
                input_bytes = base64.b64decode(input_text.split(',')[1])
            else:
                input_bytes = base64.b64decode(input_text)
        
        # Check size limitation
        if len(input_bytes) > 190:
            raise Exception(f"RSA-2048 can only encrypt up to 190 bytes. Your input is {len(input_bytes)} bytes.")
        
        # Generate RSA key pair
        keygen_start = time.time()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        keygen_time = (time.time() - keygen_start) * 1000
        
        # Encrypt
        encrypted_data = public_key.encrypt(
            input_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        result = {
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data),
            'keygenTime': f"{keygen_time:.0f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        print(f"[RSA] Encryption successful: {len(input_bytes)} -> {len(encrypted_data)} bytes")
        return jsonify(result)
        
    except Exception as e:
        print(f"[RSA] Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ecdh', methods=['POST'])
def ecdh_exchange():
    try:
        data = request.json
        print(f"[ECDH] API called with data type: {data.get('type', 'unknown')}")
        
        # Generate ECDH key pairs for Alice and Bob
        alice_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        alice_public_key = alice_private_key.public_key()
        
        bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bob_public_key = bob_private_key.public_key()
        
        # Perform key exchange
        alice_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
        bob_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)
        
        # Verify keys are the same
        keys_equal = alice_shared_key == bob_shared_key
        
        result = {
            'success': True,
            'keyAgreement': keys_equal,
            'sharedKeyLength': len(alice_shared_key),
            'sharedKey': alice_shared_key.hex()
        }
        
        print(f"[ECDH] Key exchange successful: {len(alice_shared_key)} byte shared key")
        return jsonify(result)
        
    except Exception as e:
        print(f"[ECDH] Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hash', methods=['POST'])
def hash_data():
    try:
        data = request.json
        print(f"[HASH] API called with data type: {data.get('type', 'unknown')}, size: {data.get('size', 'unknown')}")
        
        input_text = data['data']
        
        # Convert input to bytes
        if data['type'] == 'text':
            input_bytes = input_text.encode('utf-8')
        else:
            if ',' in input_text:
                input_bytes = base64.b64decode(input_text.split(',')[1])
            else:
                input_bytes = base64.b64decode(input_text)
        
        # Hash the data
        start_time = time.time()
        hash_digest = hashlib.sha256(input_bytes).hexdigest()
        hash_time = (time.time() - start_time) * 1000
        
        result = {
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'hash': hash_digest,
            'hashTime': f"{hash_time:.2f}"
        }
        
        print(f"[HASH] Hash successful: {len(input_bytes)} bytes -> SHA-256")
        return jsonify(result)
        
    except Exception as e:
        print(f"[HASH] Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# Add a test endpoint to verify server is working
@app.route('/api/test', methods=['GET'])
def test_api():
    return jsonify({
        'success': True,
        'message': 'API is working',
        'timestamp': time.time(),
        'endpoints': ['aes', 'rsa', 'ecdh', 'hash']
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🔐 CRYPTOGRAPHIC TOOL SERVER - DEBUG VERSION")
    print("=" * 60)
    print("Features enabled:")
    print("  ✓ AES-GCM 256-bit encryption")
    print("  ✓ RSA-OAEP 2048-bit encryption")
    print("  ✓ ECDH P-256 key exchange")
    print("  ✓ SHA-256 hashing")
    print("  ✓ Debug logging enabled")
    print("=" * 60)
    print("Server starting...")
    print("Open your browser and go to: http://localhost:5000")
    print("Test API endpoint: http://localhost:5000/api/test")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000) 