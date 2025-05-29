from flask import Flask, request, jsonify
from flask_cors import CORS
from rsa import encrypt as rsa_encrypt, decrypt as rsa_decrypt, generateKeys
from hmac_imp import hmac_sha256
from aes import aes_encrypt_block, aes_decrypt_block

app = Flask(__name__)
CORS(app)

@app.route('/rsa/encrypt', methods=['POST'])
def rsa_encrypt_route():
    try:
        data = request.json
        message = data['message']
        n, e, d = generateKeys()
        encrypted_bytes = rsa_encrypt(message, e, n)
        hex_encrypted = encrypted_bytes.hex()
        return jsonify({
            'encrypted': hex_encrypted,
            'n': str(n),
            'e': str(e),
            'd': str(d),
            'block_size': (n.bit_length() - 1) // 8
        })
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 400

@app.route('/rsa/decrypt', methods=['POST'])
def rsa_decrypt_route():
    data = request.json
    try:
        encrypted_hex = data['encrypted'].strip().replace(' ', '')
        print(f"Encrypted hex: {encrypted_hex[:32]}...")
        
        if not all(c in '0123456789ABCDEFabcdef' for c in encrypted_hex):
            return jsonify({'error': 'Invalid hex format. Please provide the encrypted message in hexadecimal format.'}), 400
        
        try:
            n = int(str(data['n']).strip())
            d = int(str(data['d']).strip())
            print(f"Received keys - n: {str(n)}, d: {str(d)}")
            
            if n <= 0 or d <= 0:
                return jsonify({'error': 'Invalid key values. Both n and d must be positive numbers.'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid key format. The modulus (n) and private key (d) must be valid numbers.'}), 400
            
        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            n_byte_size = (n.bit_length() + 7) // 8
            
            if len(encrypted_bytes) % n_byte_size != 0:
                return jsonify({'error': f'Invalid encrypted message length.'}), 400
            
            decrypted = rsa_decrypt(encrypted_bytes, d, n)
            print(f"Successfully decrypted message: {decrypted}.")
            return jsonify({'decrypted': decrypted})
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
            
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 400

# HMAC endpoint
@app.route('/hmac/sign', methods=['POST'])
def hmac_sign_route():
    data = request.json
    message = data['message'].encode('utf-8')
    key = data['key'].encode('utf-8')
    hmac = hmac_sha256(key, message)
    return jsonify({'hmac': hmac.hex()})

# AES endpoint
@app.route('/aes/encrypt', methods=['POST'])
def aes_encrypt_route():
    data = request.json
    message = data['message'].encode('utf-8')
    key = data['key'].encode('utf-8')
    if len(message) % 16 != 0:
        message += b'\0' * (16 - (len(message) % 16))
    if len(key) < 16:
        key = key + b'\0' * (16 - len(key))
    elif len(key) > 16:
        key = key[:16]
    
    encrypted = aes_encrypt_block(message, key)
    return jsonify({'encrypted': encrypted.hex()})

@app.route('/aes/decrypt', methods=['POST'])
def aes_decrypt_route():
    try:
        data = request.json
        encrypted_hex = data['encrypted'].strip()
        key = data['key'].encode('utf-8')

        # Validate hex format
        if not all(c in '0123456789ABCDEFabcdef' for c in encrypted_hex):
            return jsonify({'error': 'Invalid hex format. Please provide the encrypted message in hexadecimal format.'}), 400

        # Convert hex to bytes
        try:
            encrypted = bytes.fromhex(encrypted_hex)
        except ValueError:
            return jsonify({'error': 'Invalid hex string.'}), 400

        # Validate block size
        if len(encrypted) % 16 != 0:
            return jsonify({'error': 'Invalid encrypted message length. AES requires 16-byte blocks.'}), 400

        # Pad or truncate key to 16 bytes
        if len(key) < 16:
            key = key + b'\0' * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]

        # Decrypt the message
        decrypted = aes_decrypt_block(encrypted, key)
        
        # Remove padding
        decrypted = decrypted.rstrip(b'\0')
        
        try:
            return jsonify({'decrypted': decrypted.decode('utf-8')})
        except UnicodeDecodeError:
            return jsonify({'error': 'Failed to decode decrypted message as UTF-8.'}), 400

    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

if __name__ == '__main__':
    app.run(debug=True)