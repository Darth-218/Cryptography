#!/bin/python3

# n-bit RSA implementation

from time import time, perf_counter

# TODO:
# 1. Generate primes
# 2. Calculate `e`
# 3. Calculate `d`

from hashlib import sha256
from numpy import gcd

# TODO: Implement SHA and GCD from scratch


def getEntropy() -> int:
    entropy = 0 ^ int(time() * 1_000_000) & 0xFF_FF
    for _ in range(100):
        entropy ^= int(perf_counter() * 1_000_000) & 0xFF
    return entropy & 0xFF_FF_FF_FF


def generateBytes(length: int, seed: int = 0) -> bytes:
    seed = getEntropy() if seed == 0 else seed
    output = b""
    for _ in range(length):
        next = sha256(seed.to_bytes(32)).digest()
        output += next[:1]
        seed = int.from_bytes(next)
    return output


def generatePrime(bitlength: int) -> int:
    while True:
        prime = (
            int.from_bytes(generateBytes(bitlength // 8)) | (1 << (bitlength - 1))
        ) | 1
        if prime.bit_length() == bitlength and isPrime(prime):
            return prime


def isPrime(number: int) -> bool:
    for i in range(2, number):
        if number % i == 0:
            return False
    return True


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y


def mod_inverse(e, phi_n):
    g, d, _ = extended_gcd(e, phi_n)
    if g != 1:
        raise ValueError("No inverse exists")
    return d % phi_n


def generateKeys(bitlength: int, e: int = 65537):
    while True:
        p = generatePrime(bitlength)
        q = generatePrime(bitlength)
        while q == p:
            q = generatePrime(bitlength)
        t = (p - 1) * (q - 1)
        if gcd(e, t) == 1:
            break
    n = p * q
    d = mod_inverse(e, t)
    return (n, e, d)


def encrypt(m, e, n) -> int:
    return pow(m, e, n)


def decrypt(c, d, n) -> int:
    return pow(c, d, n)


if __name__ == "__main__":
    keys = generateKeys(32)
    message = "hellllllllll"
    length = len(message)

    m = int.from_bytes(message.encode("latin-1"))
    print("original ", m.to_bytes(length).decode("latin-1"))

    c = encrypt(m, keys[1], keys[0])
    print("encrypted", c.to_bytes(length).decode("latin-1"))

    m = decrypt(c, keys[2], keys[0])
    print("decrypted", m.to_bytes(length).decode("latin-1"))
