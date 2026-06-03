from flask import Flask, request, jsonify, send_file
import base64
import secrets
import time
import io
import json
import os
import re
import numpy as np
from cryptography.hazmat.backends import default_backend
from algorithms import aes, symmetric, classical, ecc
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# Utility function for cross-platform filename sanitization
def sanitize_filename(filename):
    """
    Sanitize filename for cross-platform compatibility (Windows/Mac/Linux).
    Removes path separators and invalid characters.
    """
    if not filename:
        return 'file'
    
    filename = os.path.basename(filename.replace('\\', '/'))
    filename = re.sub(r'[<>:"|?*\\/\x00-\x1f]', '_', filename)
    
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200-len(ext)] + ext
    
    if not filename or filename.strip('.') == '':
        return 'file'
    
    return filename

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# ==================== SIMULATION FUNCTIONS ====================

def simulate_aes_gcm(plaintext_bytes, key, iv):
    """Simulate AES-GCM encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Convert plaintext to bytes',
        'data': {
            'plaintext_hex': plaintext_bytes.hex(),
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key & IV Setup',
        'description': 'Generate 256-bit key and 96-bit IV (nonce)',
        'data': {
            'key_hex': key.hex(), 'key_bits': len(key) * 8,
            'iv_hex': iv.hex(), 'iv_bits': len(iv) * 8
        }
    })
    
    block_count = (len(plaintext_bytes) + 15) // 16
    steps.append({
        'step': 3, 'name': 'Block Division',
        'description': 'Divide plaintext into 16-byte AES blocks',
        'data': {
            'block_size': 16, 'total_blocks': block_count,
            'last_block_size': len(plaintext_bytes) % 16 or 16
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Cipher Initialization',
        'description': 'Initialize AES-256-GCM cipher with key and IV',
        'data': {
            'algorithm': 'AES-256-GCM', 'mode': 'Galois/Counter Mode',
            'authenticated': 'True'
        }
    })
    
    start_time = time.time()
    encrypted_data, tag = aes.encrypt_gcm(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Encryption Process',
        'description': 'Encrypt data and generate authentication tag',
        'data': {
            'ciphertext_hex': encrypted_data.hex(),
            'ciphertext_length': len(encrypted_data),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 6, 'name': 'Authentication Tag',
        'description': 'Generate 128-bit authentication tag for integrity',
        'data': {
            'tag_hex': tag.hex(), 'tag_bits': len(tag) * 8,
            'purpose': 'Ensures data integrity and authenticity'
        }
    })
    
    return {
        'steps': steps, 'encrypt_time': float(encrypt_time),
        'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'), 
        'iv': iv.hex(), 'tag': tag.hex(), 'key': key.hex(),
        'algorithm': 'AES', 'originalSize': len(plaintext_bytes), 'encryptedSize': len(encrypted_data)
    }


def simulate_rsa(plaintext_bytes):
    """Simulate RSA-OAEP encryption step by step"""
    steps = []
    
    MAX_RSA_SIZE = 190
    
    steps.append({
        'step': 1, 'name': 'Input Validation',
        'description': 'Verify plaintext size for RSA-2048',
        'data': {
            'plaintext_length': len(plaintext_bytes), 
            'max_allowed': MAX_RSA_SIZE,
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else ''),
            'size_check': 'Valid' if len(plaintext_bytes) <= MAX_RSA_SIZE else 'Too large'
        }
    })
    
    if len(plaintext_bytes) > MAX_RSA_SIZE:
        steps.append({
            'step': 2, 'name': 'Error - Data Too Large',
            'description': f'RSA cannot encrypt data larger than {MAX_RSA_SIZE} bytes',
            'data': {
                'error': f'Input size {len(plaintext_bytes)} bytes exceeds maximum {MAX_RSA_SIZE} bytes',
                'recommendation': 'Use symmetric encryption (AES) for large files'
            }
        })
        return {'steps': steps, 'error': f'RSA can encrypt max {MAX_RSA_SIZE} bytes, got {len(plaintext_bytes)}'}
    
    keygen_start = time.time()
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    public_key = private_key.public_key()
    keygen_time = (time.time() - keygen_start) * 1000
    
    steps.append({
        'step': 2, 'name': 'RSA Key Pair Generation',
        'description': 'Generate 2048-bit RSA public/private key pair',
        'data': {
            'key_size': '2048 bits', 'public_exponent': '65537',
            'generation_time_ms': f"{keygen_time:.2f}", 'key_type': 'RSA-2048'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'OAEP Padding Setup',
        'description': 'Configure Optimal Asymmetric Encryption Padding',
        'data': {
            'padding_scheme': 'OAEP', 'hash_algorithm': 'SHA-256',
            'mgf': 'MGF1 with SHA-256', 'label': 'None'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Apply OAEP Padding',
        'description': 'Add randomized padding to plaintext',
        'data': {
            'original_size': len(plaintext_bytes), 'padded_size': 256,
            'padding_overhead': 256 - len(plaintext_bytes),
            'randomized': 'Yes (secure padding)'
        }
    })
    
    encrypt_start = time.time()
    encrypted_data = public_key.encrypt(plaintext_bytes, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))
    encrypt_time = (time.time() - encrypt_start) * 1000
    
    steps.append({
        'step': 5, 'name': 'RSA Encryption',
        'description': 'Encrypt padded data using public key',
        'data': {
            'encryption_time_ms': f"{encrypt_time:.2f}",
            'ciphertext_length': len(encrypted_data),
            'ciphertext_preview': encrypted_data[:32].hex() + '...'
        }
    })
    
    decrypt_start = time.time()
    decrypted_data = private_key.decrypt(encrypted_data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))
    decrypt_time = (time.time() - decrypt_start) * 1000
    
    steps.append({
        'step': 6, 'name': 'Decryption Verification',
        'description': 'Decrypt with private key to verify',
        'data': {
            'decryption_time_ms': f"{decrypt_time:.2f}",
            'verification': 'Success' if decrypted_data == plaintext_bytes else 'Failed',
            'decrypted_length': len(decrypted_data)
        }
    })
    
    return {
        'steps': steps, 'keygen_time': float(keygen_time),
        'encrypt_time': float(encrypt_time), 
        'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
        'private_key': private_key.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8'),
        'algorithm': 'RSA', 'originalSize': len(plaintext_bytes), 'encryptedSize': len(encrypted_data)
    }


def simulate_des(plaintext_bytes, key, iv):
    """Simulate DES encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for DES encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key Setup',
        'description': 'DES uses 56-bit effective key (8 bytes)',
        'data': {
            'key_hex': key.hex(),
            'key_size': '64 bits (56 effective)',
            'iv_hex': iv.hex()
        }
    })
    
    steps.append({
        'step': 3, 'name': 'PKCS7 Padding',
        'description': 'Add padding to make length multiple of 8',
        'data': {
            'block_size': 8,
            'padding_needed': 8 - (len(plaintext_bytes) % 8) if len(plaintext_bytes) % 8 != 0 else 8
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_des(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'DES Encryption',
        'description': 'Apply 16 rounds of Feistel network',
        'data': {
            'rounds': '16',
            'ciphertext_length': len(ciphertext),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Output',
        'description': 'Encrypted ciphertext ready',
        'data': {
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else '')
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_3des(plaintext_bytes, key, iv):
    """Simulate 3DES encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for 3DES encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Triple Key Setup',
        'description': '3DES uses three 56-bit keys (24 bytes total)',
        'data': {
            'key_hex': key.hex(),
            'key_size': '192 bits (168 effective)',
            'iv_hex': iv.hex(),
            'keys': '3 independent keys'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'PKCS7 Padding',
        'description': 'Add padding to make length multiple of 8',
        'data': {
            'block_size': 8,
            'padding_needed': 8 - (len(plaintext_bytes) % 8) if len(plaintext_bytes) % 8 != 0 else 8
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Triple Encryption',
        'description': 'Encrypt -> Decrypt -> Encrypt (EDE mode)',
        'data': {
            'operation': 'Encrypt with K1, Decrypt with K2, Encrypt with K3',
            'mode': 'EDE (Encrypt-Decrypt-Encrypt)'
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_3des(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Output',
        'description': 'Triple-encrypted ciphertext ready',
        'data': {
            'ciphertext_length': len(ciphertext),
            'time_ms': f"{encrypt_time:.4f}",
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else '')
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_blowfish(plaintext_bytes, key, iv):
    """Simulate Blowfish encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for Blowfish encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key Setup',
        'description': 'Blowfish supports variable key length (4-56 bytes)',
        'data': {
            'key_hex': key.hex(),
            'key_size_bytes': len(key),
            'key_size_bits': len(key) * 8,
            'iv_hex': iv.hex()
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Subkey Generation',
        'description': 'Generate P-array and S-boxes from key',
        'data': {
            'p_array_size': '18 x 32-bit',
            's_boxes': '4 S-boxes, 256 entries each',
            'total_subkeys': '1042'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'PKCS7 Padding',
        'description': 'Add padding to make length multiple of 8',
        'data': {
            'block_size': 8,
            'padding_needed': 8 - (len(plaintext_bytes) % 8) if len(plaintext_bytes) % 8 != 0 else 8
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_blowfish(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Feistel Encryption',
        'description': 'Apply 16 rounds of Feistel network',
        'data': {
            'rounds': '16',
            'ciphertext_length': len(ciphertext),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 6, 'name': 'Output',
        'description': 'Blowfish encrypted ciphertext ready',
        'data': {
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else '')
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_chacha20(plaintext_bytes, key, nonce):
    """Simulate ChaCha20 encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for ChaCha20 stream cipher',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key & Nonce Setup',
        'description': 'ChaCha20 uses 256-bit key and 128-bit nonce',
        'data': {
            'key_hex': key.hex(),
            'key_bits': len(key) * 8,
            'nonce_hex': nonce.hex(),
            'nonce_bits': len(nonce) * 8
        }
    })
    
    steps.append({
        'step': 3, 'name': 'State Initialization',
        'description': 'Initialize 512-bit ChaCha20 state',
        'data': {
            'state_blocks': '16 x 32-bit words',
            'magic_const': 'expand 32-byte k magic',
            'counter_val': '0'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Quarter Round Function',
        'description': 'ChaCha20 uses quarter-round mixing function',
        'data': {
            'operations': 'ADD, XOR, ROTATE',
            'total_rounds': '20 (10 column + 10 diagonal)',
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_chacha20(plaintext_bytes, key, nonce)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Keystream Generation',
        'description': 'Generate keystream and XOR with plaintext',
        'data': {
            'cipher_type': 'Stream cipher',
            'operation': 'XOR plaintext with keystream',
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 6, 'name': 'Output',
        'description': 'ChaCha20 encrypted ciphertext ready',
        'data': {
            'ciphertext_length': len(ciphertext),
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else ''),
            'note': 'No padding needed (stream cipher)'
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_playfair(plaintext_str, key_str):
    """Simulate Playfair cipher step by step"""
    steps = []
    
    cipher = classical.PlayfairCipher(key_str)
    
    steps.append({
        'step': 1, 'name': 'Key Matrix Generation',
        'description': 'Create 5x5 Playfair matrix from keyword',
        'data': {
            'keyword': key_str.upper(),
            'matrix': [' '.join(row) for row in cipher.matrix],
            'note': 'J is combined with I'
        }
    })
    
    prepared = cipher._prepare_text(plaintext_str)
    steps.append({
        'step': 2, 'name': 'Text Preparation',
        'description': 'Prepare plaintext into digraphs',
        'data': {
            'original': plaintext_str,
            'prepared': ' '.join([prepared[i:i+2] for i in range(0, len(prepared), 2)]),
            'note': 'X inserted between duplicate letters'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Digraph Rules',
        'description': 'Apply Playfair encryption rules',
        'data': {
            'rule_1': 'Same row: shift right',
            'rule_2': 'Same column: shift down',
            'rule_3': 'Rectangle: swap columns'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'Encryption Complete',
        'description': 'Each digraph encrypted using matrix',
        'data': {
            'ciphertext': ' '.join([ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext, 'key': key_str, 'algorithm': 'Playfair'}


def simulate_hill(plaintext_str, key_matrix):
    """Simulate Hill cipher step by step"""
    steps = []
    
    cipher = classical.HillCipher(key_matrix)
    
    steps.append({
        'step': 1, 'name': 'Key Matrix Setup',
        'description': 'Initialize 2x2 Hill cipher key matrix',
        'data': {
            'matrix': str(key_matrix),
            'determinant': str(int(np.linalg.det(np.array(key_matrix))) % 26),
            'coprime_check': 'Valid (coprime with 26)'
        }
    })
    
    numbers = cipher._text_to_numbers(plaintext_str)
    steps.append({
        'step': 2, 'name': 'Text to Numbers',
        'description': 'Convert letters to numbers (A=0, B=1, ...)',
        'data': {
            'plaintext': plaintext_str.upper(),
            'numbers': str(numbers)
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Matrix Multiplication',
        'description': 'Multiply key matrix with plaintext vectors',
        'data': {
            'operation': 'C = K × P (mod 26)',
            'vector_size': '2x1',
            'modulus': '26'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'Encryption Complete',
        'description': 'Numbers converted back to letters',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext, 'keyMatrix': key_matrix, 'algorithm': 'Hill'}


def simulate_vigenere(plaintext_str, key_str):
    """Simulate Vigenère cipher step by step"""
    steps = []
    
    cipher = classical.VigenereCipher(key_str)
    
    steps.append({
        'step': 1, 'name': 'Keyword Setup',
        'description': 'Prepare encryption keyword',
        'data': {
            'keyword': cipher.key,
            'key_length': len(cipher.key)
        }
    })
    
    shifts = [ord(c) - ord('A') for c in cipher.key[:5]]
    steps.append({
        'step': 2, 'name': 'Calculate Shifts',
        'description': 'Each keyword letter determines shift amount',
        'data': {
            'first_5_letters': cipher.key[:5],
            'first_5_shifts': str(shifts),
            'note': 'Shift repeats for entire plaintext'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Caesar Shift Application',
        'description': 'Apply Caesar cipher with varying shifts',
        'data': {
            'method': 'C[i] = (P[i] + K[i mod keylen]) mod 26',
            'polyalphabetic': 'Yes'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'Encryption Complete',
        'description': 'All characters shifted according to keyword',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext, 'key': key_str, 'algorithm': 'Vigenere'}


def simulate_railfence(plaintext_str, rails1, rails2):
    """Simulate Double Rail Fence cipher step by step"""
    steps = []
    
    cipher = classical.DoubleRailFenceCipher(rails1, rails2)
    
    steps.append({
        'step': 1, 'name': 'Configuration',
        'description': 'Set up double rail fence parameters',
        'data': {
            'first_pass_rails': rails1,
            'second_pass_rails': rails2,
            'plaintext_length': len(plaintext_str)
        }
    })
    
    steps.append({
        'step': 2, 'name': 'First Rail Fence Pass',
        'description': f'Write plaintext in zigzag pattern across {rails1} rails',
        'data': {
            'rails': rails1,
            'pattern': 'Zigzag down and up'
        }
    })
    
    temp = cipher._rail_fence_encrypt(plaintext_str.replace(' ', ''), rails1)
    
    steps.append({
        'step': 3, 'name': 'First Pass Complete',
        'description': 'Read rails left-to-right, top-to-bottom',
        'data': {
            'intermediate': temp[:50] + ('...' if len(temp) > 50 else '')
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Second Rail Fence Pass',
        'description': f'Apply rail fence again with {rails2} rails',
        'data': {
            'rails': rails2,
            'pattern': 'Zigzag down and up on intermediate text'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Encryption Complete',
        'description': 'Double transposition complete',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext, 'rails1': rails1, 'rails2': rails2, 'algorithm': 'Double Rail Fence'}


def simulate_columnar(plaintext_str, key1, key2):
    """Simulate Double Columnar Transposition cipher step by step"""
    steps = []
    
    cipher = classical.DoubleColumnarTransposition(key1, key2)
    
    steps.append({
        'step': 1, 'name': 'Keyword Setup',
        'description': 'Prepare transposition keywords',
        'data': {
            'first_key': key1.upper(),
            'second_key': key2.upper(),
            'first_columns': len(key1),
            'second_columns': len(key2)
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Column Order Calculation',
        'description': 'Determine column reading order alphabetically',
        'data': {
            'first_order': str(cipher.order1),
            'second_order': str(cipher.order2)
        }
    })
    
    steps.append({
        'step': 3, 'name': 'First Transposition',
        'description': 'Write plaintext in grid, read by column order',
        'data': {
            'method': 'Write row-by-row, read column-by-column'
        }
    })
    
    temp = cipher._columnar_encrypt(plaintext_str.replace(' ', '').upper(), cipher.order1, len(key1))
    
    steps.append({
        'step': 4, 'name': 'First Pass Complete',
        'description': 'Intermediate ciphertext from first transposition',
        'data': {
            'intermediate': temp[:50] + ('...' if len(temp) > 50 else '')
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Second Transposition',
        'description': 'Apply columnar transposition again with second key',
        'data': {
            'method': 'Transpose intermediate text with second key'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 6, 'name': 'Encryption Complete',
        'description': 'Double columnar transposition complete',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext, 'key1': key1, 'key2': key2, 'algorithm': 'Double Columnar Transposition'}


def simulate_ecc(plaintext_bytes):
    """Simulate ECC (ECIES) encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for ECC encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    keygen_start = time.time()
    private_key, public_key = ecc.generate_ecc_keypair()
    keygen_time = (time.time() - keygen_start) * 1000
    
    steps.append({
        'step': 2, 'name': 'ECC Key Pair Generation',
        'description': 'Generate elliptic curve key pair (secp256r1)',
        'data': {
            'curve': 'secp256r1 (NIST P-256)',
            'key_size': '256 bits',
            'generation_time_ms': f"{keygen_time:.2f}"
        }
    })
    
    steps.append({
        'step': 3, 'name': 'ECIES Protocol',
        'description': 'Use Elliptic Curve Integrated Encryption Scheme',
        'data': {
            'protocol': 'ECIES',
            'components': 'ECDH + KDF + AES-GCM'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Ephemeral Key Generation',
        'description': 'Generate temporary key pair for this message',
        'data': {
            'purpose': 'One-time key for ECDH',
            'security': 'Perfect forward secrecy'
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Shared Secret Derivation',
        'description': 'Perform ECDH to get shared secret',
        'data': {
            'method': 'Ephemeral private × Recipient public',
            'kdf': 'HKDF-SHA256 for key derivation'
        }
    })
    
    encrypt_start = time.time()
    encrypted_data = ecc.encrypt_ecc(plaintext_bytes, public_key)
    encrypt_time = (time.time() - encrypt_start) * 1000
    
    steps.append({
        'step': 6, 'name': 'AES-GCM Encryption',
        'description': 'Encrypt plaintext with derived key using AES-GCM',
        'data': {
            'cipher': 'AES-256-GCM',
            'ciphertext_length': len(encrypted_data['ciphertext']),
            'time_ms': f"{encrypt_time:.2f}"
        }
    })
    
    steps.append({
        'step': 7, 'name': 'Output Components',
        'description': 'ECIES output includes multiple components',
        'data': {
            'ephemeral_public_key': encrypted_data['ephemeral_public_key'][:16].hex() + '...',
            'iv_length': len(encrypted_data['iv']),
            'tag_length': len(encrypted_data['tag']),
            'total_overhead': len(encrypted_data['ephemeral_public_key']) + len(encrypted_data['iv']) + len(encrypted_data['tag'])
        }
    })
    
    return {
        'steps': steps,
        'keygen_time': float(keygen_time),
        'encrypt_time': float(encrypt_time),
        'private_key': private_key,
        'encrypted_data': encrypted_data
    }


# ==================== API ENDPOINTS ====================

@app.route('/')
def index():
    return send_file('crypto_frontend.html')


# AES endpoint
@app.route('/api/aes', methods=['POST'])
def aes_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        
        start_time = time.time()
        ciphertext, tag = aes.encrypt_gcm(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'iv': iv.hex(),
            'tag': tag.hex(),
            'key': key.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/aes-simulate', methods=['POST'])
def aes_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        
        result = simulate_aes_gcm(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# RSA endpoint (FIXED)
@app.route('/api/rsa', methods=['POST'])
def rsa_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        MAX_RSA_SIZE = 190
        
        if len(input_bytes) > MAX_RSA_SIZE:
            return jsonify({
                'success': False, 
                'error': f'RSA can only encrypt up to {MAX_RSA_SIZE} bytes. Your input is {len(input_bytes)} bytes. For larger files, please use symmetric encryption like AES.'
            })
        
        keygen_start = time.time()
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()
        keygen_time = (time.time() - keygen_start) * 1000
        
        start_time = time.time()
        encrypted_data = public_key.encrypt(input_bytes, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))
        encrypt_time = (time.time() - start_time) * 1000
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return jsonify({
            'success': True,
            'algorithm': 'RSA',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data),
            'keygenTime': f"{keygen_time:.0f}",
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
            'private_key': private_pem.decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/rsa-simulate', methods=['POST'])
def rsa_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        MAX_RSA_SIZE = 190
        if len(input_bytes) > MAX_RSA_SIZE:
            return jsonify({
                'success': False, 
                'error': f'RSA can only encrypt up to {MAX_RSA_SIZE} bytes. Your input is {len(input_bytes)} bytes.'
            })
        
        result = simulate_rsa(input_bytes)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# DES endpoints
@app.route('/api/des', methods=['POST'])
def des_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_des_key()
        iv = secrets.token_bytes(8)
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_des(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'DES',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/des-simulate', methods=['POST'])
def des_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_des_key()
        iv = secrets.token_bytes(8)
        
        result = simulate_des(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# 3DES endpoints
@app.route('/api/3des', methods=['POST'])
def des3_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_3des_key()
        iv = secrets.token_bytes(8)
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_3des(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': '3DES',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/3des-simulate', methods=['POST'])
def des3_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_3des_key()
        iv = secrets.token_bytes(8)
        
        result = simulate_3des(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Blowfish endpoints
@app.route('/api/blowfish', methods=['POST'])
def blowfish_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_blowfish_key(16)
        iv = secrets.token_bytes(8)
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_blowfish(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Blowfish',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/blowfish-simulate', methods=['POST'])
def blowfish_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_blowfish_key(16)
        iv = secrets.token_bytes(8)
        
        result = simulate_blowfish(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ChaCha20 endpoints
@app.route('/api/chacha20', methods=['POST'])
def chacha20_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_chacha20_key()
        nonce = symmetric.generate_chacha20_nonce()
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_chacha20(input_bytes, key, nonce)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'ChaCha20',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'nonce': nonce.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/chacha20-simulate', methods=['POST'])
def chacha20_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_chacha20_key()
        nonce = symmetric.generate_chacha20_nonce()
        
        result = simulate_chacha20(input_bytes, key, nonce)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Playfair endpoints (FIXED - handle text properly)
@app.route('/api/playfair', methods=['POST'])
def playfair_endpoint():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Playfair cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key = data.get('key', 'KEYWORD')
        
        cipher = classical.PlayfairCipher(key)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Playfair',
            'originalName': data['name'],
            'originalSize': len(plaintext),
            'encryptedSize': len(ciphertext),
            'key': key,
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/playfair-simulate', methods=['POST'])
def playfair_simulate():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Playfair cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key = data.get('key', 'KEYWORD')
        
        result = simulate_playfair(plaintext, key)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Hill endpoints (FIXED)
@app.route('/api/hill', methods=['POST'])
def hill_endpoint():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Hill cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key_matrix = data.get('keyMatrix', [[3, 3], [2, 5]])
        
        cipher = classical.HillCipher(key_matrix)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Hill',
            'originalName': data['name'],
            'originalSize': len(plaintext),
            'encryptedSize': len(ciphertext),
            'keyMatrix': key_matrix,
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/hill-simulate', methods=['POST'])
def hill_simulate():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Hill cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key_matrix = data.get('keyMatrix', [[3, 3], [2, 5]])
        
        result = simulate_hill(plaintext, key_matrix)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Vigenère endpoints (FIXED)
@app.route('/api/vigenere', methods=['POST'])
def vigenere_endpoint():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Vigenère cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key = data.get('key', 'SECRET')
        
        cipher = classical.VigenereCipher(key)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Vigenere',
            'originalName': data['name'],
            'originalSize': len(plaintext),
            'encryptedSize': len(ciphertext),
            'key': key,
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/vigenere-simulate', methods=['POST'])
def vigenere_simulate():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Vigenère cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key = data.get('key', 'SECRET')
        
        result = simulate_vigenere(plaintext, key)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Rail Fence endpoints (FIXED)
@app.route('/api/railfence', methods=['POST'])
def railfence_endpoint():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Rail Fence cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        rails1 = data.get('rails1', 3)
        rails2 = data.get('rails2', 4)
        
        cipher = classical.DoubleRailFenceCipher(rails1, rails2)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Double Rail Fence',
            'originalName': data['name'],
            'originalSize': len(plaintext),
            'encryptedSize': len(ciphertext),
            'rails1': rails1,
            'rails2': rails2,
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/railfence-simulate', methods=['POST'])
def railfence_simulate():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Rail Fence cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        rails1 = data.get('rails1', 3)
        rails2 = data.get('rails2', 4)
        
        result = simulate_railfence(plaintext, rails1, rails2)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Columnar endpoints (FIXED)
@app.route('/api/columnar', methods=['POST'])
def columnar_endpoint():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Columnar cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key1 = data.get('key1', 'HACK')
        key2 = data.get('key2', 'CRYPTO')
        
        cipher = classical.DoubleColumnarTransposition(key1, key2)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Double Columnar Transposition',
            'originalName': data['name'],
            'originalSize': len(plaintext),
            'encryptedSize': len(ciphertext),
            'key1': key1,
            'key2': key2,
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/columnar-simulate', methods=['POST'])
def columnar_simulate():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Columnar cipher only works with text files (UTF-8 encoded)'})
        else:
            plaintext = data['data']
        
        key1 = data.get('key1', 'HACK')
        key2 = data.get('key2', 'CRYPTO')
        
        result = simulate_columnar(plaintext, key1, key2)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ECC endpoints (FIXED - bytes serialization)
@app.route('/api/ecc', methods=['POST'])
def ecc_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        private_key, public_key = ecc.generate_ecc_keypair()
        
        start_time = time.time()
        encrypted_data = ecc.encrypt_ecc(input_bytes, public_key)
        encrypt_time = (time.time() - start_time) * 1000
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return jsonify({
            'success': True,
            'algorithm': 'ECC (ECIES)',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data['ciphertext']),
            'ephemeral_public_key': encrypted_data['ephemeral_public_key'].hex(),
            'iv': encrypted_data['iv'].hex(),
            'tag': encrypted_data['tag'].hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'),
            'private_key': private_pem.decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ecc-simulate', methods=['POST'])
def ecc_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        result = simulate_ecc(input_bytes)
        
        if 'private_key' in result:
            private_pem = result['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            result['private_key_pem'] = private_pem.decode('utf-8')
            del result['private_key']
        
        if 'encrypted_data' in result:
            enc_data = result['encrypted_data']
            result['ephemeral_public_key'] = enc_data['ephemeral_public_key'].hex()
            result['iv'] = enc_data['iv'].hex()
            result['tag'] = enc_data['tag'].hex()
            result['ciphertext'] = base64.b64encode(enc_data['ciphertext']).decode('utf-8')
            result['private_key'] = result['private_key_pem']
            result['algorithm'] = 'ECC (ECIES)'
            del result['encrypted_data']
        
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Decryption endpoints
@app.route('/api/decrypt-aes', methods=['POST'])
def decrypt_aes():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        key = bytes.fromhex(encrypted_file['key'])
        iv = bytes.fromhex(encrypted_file['iv'])
        tag = bytes.fromhex(encrypted_file['tag'])
        
        start_time = time.time()
        plaintext = aes.decrypt_gcm(ciphertext, key, iv, tag)
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-rsa', methods=['POST'])
def decrypt_rsa():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        private_key_pem = encrypted_file['private_key'].encode('utf-8')
        
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        start_time = time.time()
        plaintext = private_key.decrypt(ciphertext, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-des', methods=['POST'])
def decrypt_des():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        key = bytes.fromhex(encrypted_file['key'])
        iv = bytes.fromhex(encrypted_file['iv'])
        
        start_time = time.time()
        plaintext = symmetric.decrypt_des(ciphertext, key, iv)
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-3des', methods=['POST'])
def decrypt_3des():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        key = bytes.fromhex(encrypted_file['key'])
        iv = bytes.fromhex(encrypted_file['iv'])
        
        start_time = time.time()
        plaintext = symmetric.decrypt_3des(ciphertext, key, iv)
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-blowfish', methods=['POST'])
def decrypt_blowfish():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        key = bytes.fromhex(encrypted_file['key'])
        iv = bytes.fromhex(encrypted_file['iv'])
        
        start_time = time.time()
        plaintext = symmetric.decrypt_blowfish(ciphertext, key, iv)
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-chacha20', methods=['POST'])
def decrypt_chacha20():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        key = bytes.fromhex(encrypted_file['key'])
        nonce = bytes.fromhex(encrypted_file['nonce'])
        
        start_time = time.time()
        plaintext = symmetric.decrypt_chacha20(ciphertext, key, nonce)
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-playfair', methods=['POST'])
def decrypt_playfair():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = encrypted_file['ciphertext']
        key = encrypted_file['key']
        
        cipher = classical.PlayfairCipher(key)
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        decrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'isText': True,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-hill', methods=['POST'])
def decrypt_hill():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = encrypted_file['ciphertext']
        key_matrix = encrypted_file['keyMatrix']
        
        cipher = classical.HillCipher(key_matrix)
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        decrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'isText': True,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-vigenere', methods=['POST'])
def decrypt_vigenere():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = encrypted_file['ciphertext']
        key = encrypted_file['key']
        
        cipher = classical.VigenereCipher(key)
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        decrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'isText': True,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-railfence', methods=['POST'])
def decrypt_railfence():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = encrypted_file['ciphertext']
        rails1 = int(encrypted_file['rails1'])
        rails2 = int(encrypted_file['rails2'])
        
        cipher = classical.DoubleRailFenceCipher(rails1, rails2)
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        decrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'isText': True,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-columnar', methods=['POST'])
def decrypt_columnar():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = encrypted_file['ciphertext']
        key1 = encrypted_file['key1']
        key2 = encrypted_file['key2']
        
        cipher = classical.DoubleColumnarTransposition(key1, key2)
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        decrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'isText': True,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt-ecc', methods=['POST'])
def decrypt_ecc():
    try:
        data = request.json
        encrypted_file = json.loads(data['encryptedFile'])
        
        ciphertext = base64.b64decode(encrypted_file['ciphertext'])
        ephemeral_public_key = bytes.fromhex(encrypted_file['ephemeral_public_key'])
        iv = bytes.fromhex(encrypted_file['iv'])
        tag = bytes.fromhex(encrypted_file['tag'])
        private_key_pem = encrypted_file['private_key'].encode('utf-8')
        
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        encrypted_data = {
            'ciphertext': ciphertext,
            'ephemeral_public_key': ephemeral_public_key,
            'iv': iv,
            'tag': tag
        }
        
        start_time = time.time()
        plaintext = ecc.decrypt_ecc(encrypted_data, private_key)
        decrypt_time = (time.time() - start_time) * 1000
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext),
            'decryptTime': f"{decrypt_time:.2f}",
            'originalName': encrypted_file.get('originalName', 'decrypted_file')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Generic decrypt endpoint
@app.route('/api/decrypt', methods=['POST'])
def decrypt_endpoint():
    try:
        data = request.json
        
        # Unpack the encryptedFile wrapper if present (used by frontend uploads)
        if 'encryptedFile' in data and isinstance(data['encryptedFile'], str):
            data = json.loads(data['encryptedFile'])
            
        algorithm = data['algorithm']
        
        if algorithm == 'AES':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            tag = bytes.fromhex(data['tag'])
            
            plaintext = aes.decrypt_gcm(ciphertext, key, iv, tag)
            
        elif algorithm == 'DES':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            
            plaintext = symmetric.decrypt_des(ciphertext, key, iv)
            
        elif algorithm == '3DES':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            
            plaintext = symmetric.decrypt_3des(ciphertext, key, iv)
            
        elif algorithm == 'Blowfish':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            
            plaintext = symmetric.decrypt_blowfish(ciphertext, key, iv)
            
        elif algorithm == 'ChaCha20':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            nonce = bytes.fromhex(data.get('nonce', data.get('iv', '')))
            
            plaintext = symmetric.decrypt_chacha20(ciphertext, key, nonce)
            
        elif algorithm == 'Playfair':
            ciphertext = data['ciphertext']
            key = data['key']
            
            cipher = classical.PlayfairCipher(key)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Hill':
            ciphertext = data['ciphertext']
            key_matrix = data['keyMatrix']
            
            cipher = classical.HillCipher(key_matrix)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Vigenere':
            ciphertext = data['ciphertext']
            key = data['key']
            
            cipher = classical.VigenereCipher(key)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Double Rail Fence':
            ciphertext = data['ciphertext']
            rails1 = int(data['rails1'])
            rails2 = int(data['rails2'])
            
            cipher = classical.DoubleRailFenceCipher(rails1, rails2)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Double Columnar Transposition':
            ciphertext = data['ciphertext']
            key1 = data['key1']
            key2 = data['key2']
            
            cipher = classical.DoubleColumnarTransposition(key1, key2)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'RSA':
            ciphertext = base64.b64decode(data['ciphertext'])
            private_key = serialization.load_pem_private_key(
                data['private_key'].encode('utf-8'), password=None, backend=default_backend()
            )
            plaintext = private_key.decrypt(ciphertext, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            ))

        elif algorithm in ['ECC', 'ECC (ECIES)']:
            ciphertext = base64.b64decode(data['ciphertext'])
            ephemeral_public_key = bytes.fromhex(data['ephemeral_public_key'])
            iv = bytes.fromhex(data['iv'])
            tag = bytes.fromhex(data['tag'])
            private_key = serialization.load_pem_private_key(
                data['private_key'].encode('utf-8'), password=None, backend=default_backend()
            )
            encrypted_data = {
                'ciphertext': ciphertext,
                'ephemeral_public_key': ephemeral_public_key,
                'iv': iv,
                'tag': tag
            }
            plaintext = ecc.decrypt_ecc(encrypted_data, private_key)

        else:
            return jsonify({'success': False, 'error': f'Unknown algorithm: {algorithm}'})
        
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Binary Download Endpoints
@app.route('/api/download-aes-binary', methods=['POST'])
def download_aes_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        
        ciphertext, tag = aes.encrypt_gcm(input_bytes, key, iv)
        
        binary_data = json.dumps({
            'algorithm': 'AES',
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key': key.hex(),
            'iv': iv.hex(),
            'tag': tag.hex(),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_aes_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-rsa-binary', methods=['POST'])
def download_rsa_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        MAX_RSA_SIZE = 190
        if len(input_bytes) > MAX_RSA_SIZE:
            return jsonify({
                'success': False, 
                'error': f'RSA can only encrypt up to {MAX_RSA_SIZE} bytes. Your input is {len(input_bytes)} bytes.'
            }), 400
        
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()
        
        encrypted_data = public_key.encrypt(input_bytes, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        binary_data = json.dumps({
            'algorithm': 'RSA',
            'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
            'private_key': private_pem.decode('utf-8'),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_rsa_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-des-binary', methods=['POST'])
def download_des_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_des_key()
        iv = secrets.token_bytes(8)
        
        ciphertext = symmetric.encrypt_des(input_bytes, key, iv)
        
        binary_data = json.dumps({
            'algorithm': 'DES',
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key': key.hex(),
            'iv': iv.hex(),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_des_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-3des-binary', methods=['POST'])
def download_3des_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_3des_key()
        iv = secrets.token_bytes(8)
        
        ciphertext = symmetric.encrypt_3des(input_bytes, key, iv)
        
        binary_data = json.dumps({
            'algorithm': '3DES',
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key': key.hex(),
            'iv': iv.hex(),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_3des_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-blowfish-binary', methods=['POST'])
def download_blowfish_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_blowfish_key(16)
        iv = secrets.token_bytes(8)
        
        ciphertext = symmetric.encrypt_blowfish(input_bytes, key, iv)
        
        binary_data = json.dumps({
            'algorithm': 'Blowfish',
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key': key.hex(),
            'iv': iv.hex(),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_blowfish_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-chacha20-binary', methods=['POST'])
def download_chacha20_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_chacha20_key()
        nonce = symmetric.generate_chacha20_nonce()
        
        ciphertext = symmetric.encrypt_chacha20(input_bytes, key, nonce)
        
        binary_data = json.dumps({
            'algorithm': 'ChaCha20',
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key': key.hex(),
            'nonce': nonce.hex(),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_chacha20_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-playfair-binary', methods=['POST'])
def download_playfair_binary():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Playfair cipher only works with text files'}), 400
        else:
            plaintext = data['data']
        
        key = data.get('key', 'KEYWORD')
        
        cipher = classical.PlayfairCipher(key)
        ciphertext = cipher.encrypt(plaintext)
        
        binary_data = json.dumps({
            'algorithm': 'Playfair',
            'ciphertext': ciphertext,
            'key': key,
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_playfair_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-hill-binary', methods=['POST'])
def download_hill_binary():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Hill cipher only works with text files'}), 400
        else:
            plaintext = data['data']
        
        key_matrix = data.get('keyMatrix', [[3, 3], [2, 5]])
        
        cipher = classical.HillCipher(key_matrix)
        ciphertext = cipher.encrypt(plaintext)
        
        binary_data = json.dumps({
            'algorithm': 'Hill',
            'ciphertext': ciphertext,
            'keyMatrix': key_matrix,
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_hill_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-vigenere-binary', methods=['POST'])
def download_vigenere_binary():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Vigenère cipher only works with text files'}), 400
        else:
            plaintext = data['data']
        
        key = data.get('key', 'SECRET')
        
        cipher = classical.VigenereCipher(key)
        ciphertext = cipher.encrypt(plaintext)
        
        binary_data = json.dumps({
            'algorithm': 'Vigenere',
            'ciphertext': ciphertext,
            'key': key,
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_vigenere_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-railfence-binary', methods=['POST'])
def download_railfence_binary():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Rail Fence cipher only works with text files'}), 400
        else:
            plaintext = data['data']
        
        rails1 = data.get('rails1', 3)
        rails2 = data.get('rails2', 4)
        
        cipher = classical.DoubleRailFenceCipher(rails1, rails2)
        ciphertext = cipher.encrypt(plaintext)
        
        binary_data = json.dumps({
            'algorithm': 'Double Rail Fence',
            'ciphertext': ciphertext,
            'rails1': rails1,
            'rails2': rails2,
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_railfence_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-columnar-binary', methods=['POST'])
def download_columnar_binary():
    try:
        data = request.json
        if data['type'] == 'file':
            file_bytes = base64.b64decode(data['data'])
            try:
                plaintext = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'error': 'Columnar cipher only works with text files'}), 400
        else:
            plaintext = data['data']
        
        key1 = data.get('key1', 'HACK')
        key2 = data.get('key2', 'CRYPTO')
        
        cipher = classical.DoubleColumnarTransposition(key1, key2)
        ciphertext = cipher.encrypt(plaintext)
        
        binary_data = json.dumps({
            'algorithm': 'Double Columnar Transposition',
            'ciphertext': ciphertext,
            'key1': key1,
            'key2': key2,
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_columnar_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-ecc-binary', methods=['POST'])
def download_ecc_binary():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        private_key, public_key = ecc.generate_ecc_keypair()
        encrypted_data = ecc.encrypt_ecc(input_bytes, public_key)
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        binary_data = json.dumps({
            'algorithm': 'ECC',
            'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'),
            'ephemeral_public_key': encrypted_data['ephemeral_public_key'].hex(),
            'iv': encrypted_data['iv'].hex(),
            'tag': encrypted_data['tag'].hex(),
            'private_key': private_pem.decode('utf-8'),
            'originalName': data.get('name', 'file')
        }).encode('utf-8')
        
        safe_name = sanitize_filename(data.get('name', 'file'))
        filename = f"encrypted_ecc_{safe_name}.enc"
        
        return send_file(
            io.BytesIO(binary_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download-decrypted', methods=['POST'])
def download_decrypted():
    try:
        data = request.json
        plaintext = data.get('plaintext', '')
        is_text = data.get('isText', True)
        original_name = data.get('originalName', 'file')
        
        safe_name = sanitize_filename(original_name) if original_name else 'file'
        if is_text:
            file_data = plaintext.encode('utf-8')
            filename = f"decrypted_{safe_name}.txt"
        else:
            file_data = base64.b64decode(plaintext)
            filename = f"decrypted_{safe_name}"
        
        return send_file(
            io.BytesIO(file_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


if __name__ == '__main__':
    print("🔐 Crypto Tool Server Starting...")
    print("Open: http://localhost:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)