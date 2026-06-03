#!/usr/bin/env python3
"""Test script to verify API simulation responses"""

import json
import base64
import sys
sys.path.insert(0, r'd:\crypto_tool-main')

from crypto_web_app import simulate_chacha20, simulate_aes_gcm
from algorithms.symmetric import generate_chacha20_key, generate_chacha20_nonce

# Test ChaCha20
print("=" * 60)
print("Testing ChaCha20 Simulation")
print("=" * 60)

test_data = b"Hello, World! This is a test message."
key = generate_chacha20_key()
nonce = generate_chacha20_nonce()

chacha_result = simulate_chacha20(test_data, key, nonce)
print(f"✓ Result keys: {list(chacha_result.keys())}")
print(f"✓ Steps count: {len(chacha_result['steps'])}")

for i, step in enumerate(chacha_result['steps']):
    print(f"\nStep {i+1}: {step['name']}")
    print(f"  - Has 'data' key: {'data' in step}")
    if 'data' in step:
        print(f"  - Data type: {type(step['data'])}")
        print(f"  - Data keys: {list(step['data'].keys()) if isinstance(step['data'], dict) else 'NOT A DICT'}")
        print(f"  - Number of keys: {len(step['data']) if isinstance(step['data'], dict) else 'N/A'}")
        if isinstance(step['data'], dict) and len(step['data']) > 0:
            # Show first 1-2 key-value pairs
            for j, (k, v) in enumerate(step['data'].items()):
                if j < 2:
                    val_str = str(v)[:50]
                    print(f"    {k}: {val_str}...")
    else:
        print(f"  - ❌ NO DATA KEY FOUND!")

print("\n" + "=" * 60)
print("Testing AES-GCM Simulation")
print("=" * 60)

import secrets
key = secrets.token_bytes(32)
iv = secrets.token_bytes(12)

aes_result = simulate_aes_gcm(test_data, key, iv)
print(f"✓ Result keys: {list(aes_result.keys())}")
print(f"✓ Steps count: {len(aes_result['steps'])}")

for i, step in enumerate(aes_result['steps']):
    print(f"\nStep {i+1}: {step['name']}")
    print(f"  - Has 'data' key: {'data' in step}")
    if 'data' in step:
        print(f"  - Data type: {type(step['data'])}")
        print(f"  - Data keys: {list(step['data'].keys()) if isinstance(step['data'], dict) else 'NOT A DICT'}")
        print(f"  - Number of keys: {len(step['data']) if isinstance(step['data'], dict) else 'N/A'}")
        if isinstance(step['data'], dict) and len(step['data']) > 0:
            for j, (k, v) in enumerate(step['data'].items()):
                if j < 2:
                    val_str = str(v)[:50]
                    print(f"    {k}: {val_str}...")
    else:
        print(f"  - ❌ NO DATA KEY FOUND!")

print("\n" + "=" * 60)
print("Testing JSON Serialization")
print("=" * 60)

try:
    json_str = json.dumps({'success': True, **chacha_result})
    print(f"✓ JSON serialization successful")
    parsed = json.loads(json_str)
    print(f"✓ JSON parsing successful")
    print(f"✓ Parsed keys: {list(parsed.keys())}")
    print(f"✓ Parsed steps count: {len(parsed['steps'])}")
    if len(parsed['steps']) > 0:
        step0 = parsed['steps'][0]
        print(f"✓ First step data: {step0.get('data', 'NO DATA')}")
except Exception as e:
    print(f"❌ JSON Error: {e}")

print("\n" + "=" * 60)
print("All tests completed!")
print("=" * 60)
