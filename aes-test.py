import aes

if __name__ == "__main__":
    key = b"ThisIsA16ByteKey"
    plaintext = b"SimpleAESExample"
    cipher = aes.aes_encrypt_block(plaintext, key)
    print("Ciphertext (hex):", cipher.hex())