import hmac_imp

def run_tests():
    key = b"kuromi"
    message = b"Hello"

    hmac = hmac_imp.hmac_sha256(key, message)
    print("HMAC (hex):", hmac.hex())


run_tests()