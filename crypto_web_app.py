from flask import Flask, request, jsonify, render_template_string
import base64
import hashlib
import secrets
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Crypto Tool</title>
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               font-family: 'Segoe UI', sans-serif; min-height: 100vh; padding: 20px; color: white; }
        .container { max-width: 1200px; margin: 0 auto; }
        .title { text-align: center; font-size: 2.5em; margin-bottom: 30px; }
        .input-section { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); 
                        border-radius: 20px; padding: 30px; margin-bottom: 30px; }
        .input-group { margin-bottom: 20px; }
        .input-group label { display: block; margin-bottom: 8px; font-weight: 600; }
        .input-group textarea { width: 100%; padding: 15px; border: none; border-radius: 10px; 
                               background: rgba(255,255,255,0.1); color: white; }
        .btn { padding: 15px 30px; border: none; border-radius: 25px; font-size: 16px; 
               cursor: pointer; margin: 5px; background: linear-gradient(45deg, #ff6b6b, #4ecdc4); 
               color: white; transition: transform 0.3s; }
        .btn:hover { transform: translateY(-2px); }
        .crypto-ops { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                     gap: 20px; margin-top: 30px; }
        .crypto-card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); 
                      border-radius: 20px; padding: 25px; }
        .result { margin-top: 15px; padding: 15px; background: rgba(0,0,0,0.2); 
                 border-radius: 10px; font-family: monospace; font-size: 12px; 
                 word-break: break-all; min-height: 100px; }
        .file-input-wrapper { position: relative; border: 2px dashed rgba(255,255,255,0.3);
                             border-radius: 15px; padding: 20px; text-align: center; cursor: pointer;
                             background: rgba(255,255,255,0.05); transition: all 0.3s ease; }
        .file-input-wrapper:hover { border-color: rgba(255,255,255,0.5); background: rgba(255,255,255,0.1); }
        #fileInput { position: absolute; top: 0; left: 0; width: 100%; height: 100%; 
                    opacity: 0; cursor: pointer; z-index: 2; }
        #fileInfo { pointer-events: none; position: relative; z-index: 1; font-size: 14px; 
                   padding: 10px; }
        .input-mode-selector { display: flex; justify-content: center; gap: 30px; 
                              margin-bottom: 20px; padding: 15px; background: rgba(255,255,255,0.05);
                              border-radius: 15px; }
        .input-mode-selector label { display: flex; align-items: center; gap: 8px; 
                                    cursor: pointer; padding: 8px 16px; border-radius: 20px; }
        .download-btn { background: linear-gradient(45deg, #3498db, #2980b9); color: white;
                       border: none; padding: 10px 15px; border-radius: 15px; cursor: pointer;
                       font-size: 12px; margin: 10px 0; transition: all 0.3s ease; }
        .download-btn:hover { background: linear-gradient(45deg, #2980b9, #21618c); 
                             transform: translateY(-2px); }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="title">🔐 Crypto Tool</h1>
        
        <div class="input-section">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                <div class="input-group">
                    <label for="plaintext">Text Input:</label>
                    <textarea id="plaintext" rows="4" placeholder="Enter message...">Hello World!</textarea>
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
            
            <div style="text-align: center;">
                <button class="btn" onclick="runAES()">🔒 AES</button>
                <button class="btn" onclick="runRSA()">🗝️ RSA</button>
                <button class="btn" onclick="runECDH()">🤝 ECDH</button>
                <button class="btn" onclick="runHash()">🔢 Hash</button>
                <button class="btn" onclick="runAll()">🚀 Run All</button>
                <button class="btn" onclick="downloadResults()" style="background: linear-gradient(45deg, #2ecc71, #27ae60);">📥 Download</button>
            </div>
        </div>
        
        <div class="crypto-ops">
            <div class="crypto-card">
                <h3>🔒 AES-GCM</h3>
                <div class="result" id="aes-result">Click AES to encrypt</div>
                <button class="download-btn" id="aes-download" onclick="downloadIndividual('aes')" style="display:none;">📥 Download AES</button>
            </div>
            
            <div class="crypto-card">
                <h3>🗝️ RSA OAEP</h3>
                <div class="result" id="rsa-result">Click RSA to encrypt</div>
                <button class="download-btn" id="rsa-download" onclick="downloadIndividual('rsa')" style="display:none;">📥 Download RSA</button>
            </div>
            
            <div class="crypto-card">
                <h3>🤝 ECDH</h3>
                <div class="result" id="ecdh-result">Click ECDH for key exchange</div>
                <button class="download-btn" id="ecdh-download" onclick="downloadIndividual('ecdh')" style="display:none;">📥 Download ECDH</button>
            </div>
            
            <div class="crypto-card">
                <h3>🔢 SHA-256</h3>
                <div class="result" id="hash-result">Click Hash to generate</div>
                <button class="download-btn" id="hash-download" onclick="downloadIndividual('hash')" style="display:none;">📥 Download Hash</button>
            </div>
        </div>
    </div>

    <script>
        let selectedFile = null;
        let currentInputMode = 'text';
        let cryptoResults = {};

        function handleFileInput(input) {
            const file = input.files[0];
            if (file) {
                selectedFile = file;
                document.getElementById('fileInfo').innerHTML = `Selected: ${file.name} (${file.size} bytes)`;
                document.querySelector('input[value="file"]').checked = true;
                switchInputMode();
            }
        }

        function switchInputMode() {
            currentInputMode = document.querySelector('input[name="inputMode"]:checked').value;
        }

        async function getInputData() {
            if (currentInputMode === 'text') {
                const text = document.getElementById('plaintext').value;
                if (!text.trim()) throw new Error('Please enter some text');
                return {
                    data: text,
                    name: 'text_input.txt',
                    size: new Blob([text]).size,
                    type: 'text'
                };
            } else {
                if (!selectedFile) throw new Error('Please select a file first');
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
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

        async function callAPI(endpoint, data) {
            try {
                const response = await fetch(`/api/${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                return await response.json();
            } catch (error) {
                return { success: false, error: error.message };
            }
        }

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
        }

        function downloadResults() {
            const hasResults = Object.values(cryptoResults).some(result => result && result.success);
            if (!hasResults) {
                alert('No results available. Please run crypto operations first.');
                return;
            }

            let content = `CRYPTOGRAPHIC OPERATIONS REPORT\n`;
            content += `Generated: ${new Date().toISOString()}\n`;
            content += `Input Mode: ${currentInputMode}\n\n`;

            if (cryptoResults.aes && cryptoResults.aes.success) {
                content += `AES-GCM ENCRYPTION:\n`;
                content += `File: ${cryptoResults.aes.originalName}\n`;
                content += `Size: ${cryptoResults.aes.originalSize} -> ${cryptoResults.aes.encryptedSize} bytes\n`;
                content += `IV: ${cryptoResults.aes.iv}\n`;
                content += `Time: ${cryptoResults.aes.encryptTime}ms\n`;
                content += `Data: ${cryptoResults.aes.encrypted.substring(0, 100)}...\n\n`;
            }

            if (cryptoResults.rsa && cryptoResults.rsa.success) {
                content += `RSA-OAEP ENCRYPTION:\n`;
                content += `File: ${cryptoResults.rsa.originalName}\n`;
                content += `Size: ${cryptoResults.rsa.originalSize} -> ${cryptoResults.rsa.encryptedSize} bytes\n`;
                content += `Keygen: ${cryptoResults.rsa.keygenTime}ms\n`;
                content += `Data: ${cryptoResults.rsa.encrypted.substring(0, 100)}...\n\n`;
            }

            if (cryptoResults.ecdh && cryptoResults.ecdh.success) {
                content += `ECDH KEY EXCHANGE:\n`;
                content += `Agreement: ${cryptoResults.ecdh.keyAgreement}\n`;
                content += `Key Length: ${cryptoResults.ecdh.sharedKeyLength} bytes\n`;
                content += `Shared Key: ${cryptoResults.ecdh.sharedKey}\n\n`;
            }

            if (cryptoResults.hash && cryptoResults.hash.success) {
                content += `SHA-256 HASH:\n`;
                content += `File: ${cryptoResults.hash.originalName}\n`;
                content += `Size: ${cryptoResults.hash.originalSize} bytes\n`;
                content += `Time: ${cryptoResults.hash.hashTime}ms\n`;
                content += `Hash: ${cryptoResults.hash.hash}\n\n`;
            }

            const filename = `crypto_results_${new Date().getTime()}.txt`;
            downloadFile(content, filename);
        }

        async function runAES() {
            try {
                const inputData = await getInputData();
                const result = await callAPI('aes', inputData);
                cryptoResults.aes = result;
                
                if (result.success) {
                    document.getElementById('aes-result').innerHTML = 
                        `✓ Encrypted<br>Size: ${result.originalSize} → ${result.encryptedSize} bytes<br>` +
                        `IV: ${result.iv.substring(0, 16)}...<br>Time: ${result.encryptTime}ms<br>` +
                        `<details><summary>Encrypted Data</summary><div style="max-height:100px;overflow-y:auto;font-size:10px;word-break:break-all;">${result.encrypted}</div></details>`;
                    document.getElementById('aes-download').style.display = 'block';
                } else {
                    document.getElementById('aes-result').innerHTML = `✗ Error: ${result.error}`;
                    document.getElementById('aes-download').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('aes-result').innerHTML = `✗ Error: ${error.message}`;
                document.getElementById('aes-download').style.display = 'none';
            }
        }

        async function runRSA() {
            try {
                const inputData = await getInputData();
                const result = await callAPI('rsa', inputData);
                cryptoResults.rsa = result;
                
                if (result.success) {
                    document.getElementById('rsa-result').innerHTML = 
                        `✓ Encrypted<br>Size: ${result.originalSize} → ${result.encryptedSize} bytes<br>` +
                        `Keygen: ${result.keygenTime}ms<br>` +
                        `<details><summary>Encrypted Data</summary><div style="max-height:100px;overflow-y:auto;font-size:10px;word-break:break-all;">${result.encrypted}</div></details>`;
                    document.getElementById('rsa-download').style.display = 'block';
                } else {
                    document.getElementById('rsa-result').innerHTML = `✗ Error: ${result.error}`;
                    document.getElementById('rsa-download').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('rsa-result').innerHTML = `✗ Error: ${error.message}`;
                document.getElementById('rsa-download').style.display = 'none';
            }
        }

        async function runECDH() {
            try {
                const inputData = await getInputData();
                const result = await callAPI('ecdh', inputData);
                cryptoResults.ecdh = result;
                
                if (result.success) {
                    document.getElementById('ecdh-result').innerHTML = 
                        `✓ Key Exchange<br>Agreement: ${result.keyAgreement}<br>` +
                        `Key Length: ${result.sharedKeyLength} bytes<br>` +
                        `<details><summary>Shared Key</summary><div style="max-height:100px;overflow-y:auto;font-size:10px;word-break:break-all;">${result.sharedKey}</div></details>`;
                    document.getElementById('ecdh-download').style.display = 'block';
                } else {
                    document.getElementById('ecdh-result').innerHTML = `✗ Error: ${result.error}`;
                    document.getElementById('ecdh-download').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('ecdh-result').innerHTML = `✗ Error: ${error.message}`;
                document.getElementById('ecdh-download').style.display = 'none';
            }
        }

        async function runHash() {
            try {
                const inputData = await getInputData();
                const result = await callAPI('hash', inputData);
                cryptoResults.hash = result;
                
                if (result.success) {
                    document.getElementById('hash-result').innerHTML = 
                        `✓ Hash Generated<br>Size: ${result.originalSize} bytes<br>` +
                        `Time: ${result.hashTime}ms<br>` +
                        `<details><summary>SHA-256 Hash</summary><div style="max-height:100px;overflow-y:auto;font-size:10px;word-break:break-all;">${result.hash}</div></details>`;
                    document.getElementById('hash-download').style.display = 'block';
                } else {
                    document.getElementById('hash-result').innerHTML = `✗ Error: ${result.error}`;
                    document.getElementById('hash-download').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('hash-result').innerHTML = `✗ Error: ${error.message}`;
                document.getElementById('hash-download').style.display = 'none';
            }
        }

        async function runAll() {
            try {
                await runAES();
                await runRSA();
                await runECDH();
                await runHash();
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            switchInputMode();
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
        input_bytes = data['data'].encode('utf-8')
        
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        start_time = time.time()
        encrypted_data = encryptor.update(input_bytes) + encryptor.finalize()
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/rsa', methods=['POST'])
def rsa_encrypt():
    try:
        data = request.json
        input_bytes = data['data'].encode('utf-8')
        
        if len(input_bytes) > 190:
            raise Exception(f"RSA max 190 bytes. Input: {len(input_bytes)} bytes")
        
        keygen_start = time.time()
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()
        keygen_time = (time.time() - keygen_start) * 1000
        
        encrypted_data = public_key.encrypt(input_bytes, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))
        
        return jsonify({
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data),
            'keygenTime': f"{keygen_time:.0f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ecdh', methods=['POST'])
def ecdh_exchange():
    try:
        alice_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bob_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        alice_shared = alice_private.exchange(ec.ECDH(), bob_private.public_key())
        bob_shared = bob_private.exchange(ec.ECDH(), alice_private.public_key())
        
        return jsonify({
            'success': True,
            'keyAgreement': alice_shared == bob_shared,
            'sharedKeyLength': len(alice_shared),
            'sharedKey': alice_shared.hex()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hash', methods=['POST'])
def hash_data():
    try:
        data = request.json
        input_bytes = data['data'].encode('utf-8')
        
        start_time = time.time()
        hash_digest = hashlib.sha256(input_bytes).hexdigest()
        hash_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'hash': hash_digest,
            'hashTime': f"{hash_time:.2f}"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("🔐 Crypto Tool Server Starting...")
    print("Open: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)