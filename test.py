from aes import aes_encrypt_block
from rsa import generateKeys, encrypt
from hmac_imp import hmac_sha256
from utils import timeTaken

message = "Hello World"
message_bytes = message.encode()
key_16_bytes = b"thisisasecretkey"  # 16-byte key for AES and HMAC

@timeTaken
def run_aes():
    aes_encrypt_block(message_bytes.ljust(16, b'\0'), key_16_bytes)

@timeTaken
def run_rsa():
    n, e, d = generateKeys()
    encrypt(message, e, n)

@timeTaken
def run_hmac():
    hmac_sha256(key_16_bytes, message_bytes)

# Run tests
run_aes()
run_rsa()
run_hmac()
