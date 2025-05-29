from flask import Flask, request, jsonify
from flask_cors import CORS
from rsa import encrypt as rsa_encrypt, decrypt as rsa_decrypt, generateKeys
from hmac_imp import hmac_sha256
from aes import aes_encrypt_block, aes_decrypt_block

app = Flask(__name__)
CORS(app)


def validate_hex(hex_string: str) -> tuple[bool, str]:
    hex_string = hex_string.strip()
    if not all(c in "0123456789ABCDEFabcdef" for c in hex_string):
        return (
            False,
            "Invalid hex format. Please provide the message in hexadecimal format.",
        )
    return True, ""


def hex_to_bytes(hex_string: str) -> tuple[bytes | None, str]:
    try:
        return bytes.fromhex(hex_string), ""
    except ValueError:
        return None, "Invalid hex string."


def pad_key(key: bytes, block_size: int = 16) -> bytes:
    if len(key) < block_size:
        return key + b"\0" * (block_size - len(key))
    return key[:block_size]


def validate_block_size(data: bytes, block_size: int) -> tuple[bool, str]:
    if len(data) % block_size != 0:
        return False, f"Invalid message length. Requires {block_size}-byte blocks."
    return True, ""


def error_response(message: str, status_code: int = 400) -> tuple[dict, int]:
    return jsonify({"error": message}), status_code


@app.route("/rsa/encrypt", methods=["POST"])
def rsa_encrypt_route():
    try:
        data = request.json
        message = data["message"]
        n, e, d = generateKeys()
        encrypted_bytes = rsa_encrypt(message, e, n)
        hex_encrypted = encrypted_bytes.hex()
        return jsonify(
            {
                "encrypted": hex_encrypted,
                "n": str(n),
                "e": str(e),
                "d": str(d),
                "block_size": (n.bit_length() - 1) // 8,
            }
        )
    except Exception as e:
        return error_response(f"Encryption failed: {str(e)}")


@app.route("/rsa/decrypt", methods=["POST"])
def rsa_decrypt_route():
    data = request.json
    try:
        encrypted_hex = data["encrypted"].strip().replace(" ", "")

        is_valid, error_message = validate_hex(encrypted_hex)
        if not is_valid:
            return error_response(error_message)

        try:
            n = int(str(data["n"]).strip())
            d = int(str(data["d"]).strip())

            if n <= 0 or d <= 0:
                return error_response(
                    "Invalid key values. Both n and d must be positive numbers."
                )
        except ValueError:
            return error_response(
                "Invalid key format. The modulus (n) and private key (d) must be valid numbers."
            )

        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            n_byte_size = (n.bit_length() + 7) // 8

            is_valid, error_message = validate_block_size(encrypted_bytes, n_byte_size)
            if not is_valid:
                return error_response(error_message)

            decrypted = rsa_decrypt(encrypted_bytes, d, n)
            return jsonify({"decrypted": decrypted})
        except Exception as e:
            return error_response(f"Decryption failed: {str(e)}")

    except Exception as e:
        return error_response(f"An error occurred: {str(e)}")


@app.route("/hmac/sign", methods=["POST"])
def hmac_sign_route():
    try:
        data = request.json
        message = data["message"].encode("utf-8")
        key = data["key"].encode("utf-8")
        hmac = hmac_sha256(key, message)
        return jsonify({"hmac": hmac.hex()})
    except Exception as e:
        return error_response(f"HMAC signing failed: {str(e)}")


@app.route("/aes/encrypt", methods=["POST"])
def aes_encrypt_route():
    try:
        data = request.json
        message = data["message"].encode("utf-8")
        key = data["key"].encode("utf-8")

        # Pad message to block size
        if len(message) % 16 != 0:
            message += b"\0" * (16 - (len(message) % 16))

        # Pad key
        key = pad_key(key)

        encrypted = aes_encrypt_block(message, key)
        return jsonify({"encrypted": encrypted.hex()})
    except Exception as e:
        return error_response(f"Encryption failed: {str(e)}")


@app.route("/aes/decrypt", methods=["POST"])
def aes_decrypt_route():
    try:
        data = request.json
        encrypted_hex = data["encrypted"].strip()
        key = data["key"].encode("utf-8")

        is_valid, error_message = validate_hex(encrypted_hex)
        if not is_valid:
            return error_response(error_message)

        encrypted, error_message = hex_to_bytes(encrypted_hex)
        if encrypted is None:
            return error_response(error_message)

        is_valid, error_message = validate_block_size(encrypted, 16)
        if not is_valid:
            return error_response(error_message)

        key = pad_key(key)

        decrypted = aes_decrypt_block(encrypted, key)

        decrypted = decrypted.rstrip(b"\0")

        try:
            return jsonify({"decrypted": decrypted.decode("utf-8")})
        except UnicodeDecodeError:
            return error_response("Failed to decode decrypted message as UTF-8.")

    except Exception as e:
        return error_response(f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    app.run(debug=True)
