import aes


if __name__ == "__main__":
    key = b"ThisIsA16ByteKey"
    plaintext = b"SimpleAESExample"
    ciphertext = aes.aes_encrypt_block(plaintext, key)
    decrypted = aes.aes_decrypt_block(ciphertext, key)
    
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted:", decrypted)
