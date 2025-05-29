#!/bin/python3

from time import time, perf_counter

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def getEntropy() -> int:
    entropy = 0 ^ int(time() * 1_000_000) & 0xFF_FF
    for _ in range(100):
        entropy ^= int(perf_counter() * 1_000_000) & 0xFF
    return entropy & 0xFF_FF_FF_FF


def selectPrime() -> int:
    primes = [
        32771,
        32779,
        32783,
        32789,
        32797,
        32801,
        32803,
        32831,
        32833,
        32839,
        32843,
        32869,
        32887,
        32909,
        32911,
        32917,
        32933,
        32939,
        32941,
        32957,
        32969,
        32971,
        32983,
        32987,
        32993,
        32999,
        33013,
        33023,
        33029,
        33037,
        33049,
        33053,
        33071,
        33073,
        33083,
        33091,
        33107,
        33113,
        33119,
        33149,
        33151,
        33161,
        33179,
        33181,
        33191,
        33199,
        33203,
        33211,
        33223,
        33247,
        33287,
        33289,
        33301,
        33311,
        33317,
        33329,
        33331,
        33343,
        33347,
        33349,
        33353,
        33359,
        33377,
        33391,
        33403,
        33409,
        33413,
        33427,
        33457,
        33461,
        33469,
        33479,
        33487,
        33493,
        33503,
        33521,
        33529,
        33533,
        33547,
        33563,
        33569,
        33577,
        33581,
        33587,
        33589,
        33599,
        33601,
        33613,
        33617,
        33619,
        33623,
        33629,
        33637,
        33641,
        33647,
        33679,
        33703,
        33713,
        33721,
        33739,
        33749,
        33751,
        33757,
        33767,
        33769,
        33773,
        33791,
        33797,
        33809,
        33811,
        33827,
        33829,
        33851,
        33857,
        33863,
        33871,
        33889,
        33893,
        33911,
        33923,
        33931,
        33937,
        33941,
        33961,
        33967,
        33997,
        34019,
        34031,
        34033,
        34039,
        34057,
        34061,
        34123,
        34127,
        34129,
        34141,
        34147,
        34157,
        34159,
        34171,
        34183,
        34211,
        34213,
        34217,
        34231,
        34253,
        34259,
        34261,
        34267,
        34273,
        34283,
        34297,
        34301,
        34303,
        34313,
        34319,
        34327,
        34337,
        34351,
        34361,
        34367,
        34369,
        34381,
        34403,
        34421,
        34429,
        34439,
        34457,
        34469,
        34471,
        34483,
        34487,
        34499,
        34501,
        34511,
        34513,
        34519,
        34537,
        34543,
        34549,
        34583,
        34589,
        34591,
        34603,
        34607,
        34613,
        34631,
        34649,
        34651,
        34667,
        34673,
        34679,
        34687,
        34693,
        34703,
        34721,
        34729,
        34739,
        34747,
        34757,
    ]
    return primes[getEntropy() % len(primes)]


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y


def mod_inverse(e: int, phi_n: int) -> int:
    g, d, _ = extended_gcd(e, phi_n)
    if g != 1:
        raise ValueError("No inverse exists")
    return d % phi_n


def generateKeys() -> tuple[int, int, int]:
    p, q = selectPrime(), selectPrime()

    while q == p:
        q = selectPrime()

    n: int = p * q
    phi_n: int = (p - 1) * (q - 1)
    e: int = 65537
    while gcd(e, phi_n) != 1:
        e += 2
    d: int = mod_inverse(e, phi_n)

    return (n, e, d)


def encrypt(message: str, e: int, n: int) -> bytes:
    try:
        message_bytes = message.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError("Message contains invalid characters for UTF-8 encoding")
        
    max_block_size = (n.bit_length() - 1) // 8
    if max_block_size < 1:
        raise ValueError("Key size is too small to encrypt any data")
        
    n_byte_size = (n.bit_length() + 7) // 8
    
    blocks = [message_bytes[i : i + max_block_size] for i in range(0, len(message_bytes), max_block_size)]
    encrypted_bytes = b""
    
    for i, block in enumerate(blocks):
        if len(block) < max_block_size:
            padding_length = max_block_size - len(block)
            block = block + bytes([padding_length] * padding_length)
            
        m = int.from_bytes(block, byteorder="big")
        if m >= n:
            raise ValueError(f"Message block {i+1} is too large for the given key size")
            
        c = pow(m, e, n)
        
        encrypted_block = c.to_bytes(n_byte_size, byteorder="big")
        encrypted_bytes += encrypted_block
        
    return encrypted_bytes


def decrypt(encrypted_bytes: bytes, d: int, n: int) -> str:
    n_byte_size = (n.bit_length() + 7) // 8
    max_block_size = (n.bit_length() - 1) // 8
    decrypted_bytes = b""
    blocks = [encrypted_bytes[i:i+n_byte_size] for i in range(0, len(encrypted_bytes), n_byte_size)]
    
    if not blocks:
        raise ValueError("No data to decrypt")
    
    for i, block in enumerate(blocks):
        try:
            c = int.from_bytes(block, byteorder="big")
            if c >= n:
                raise ValueError(f"Block {i+1}: Encrypted value is larger than modulus")
            
            m_decrypted = pow(c, d, n)
            
            if i < len(blocks) - 1:
                block_bytes = m_decrypted.to_bytes(max_block_size, byteorder="big")
            else:
                try:
                    block_bytes = m_decrypted.to_bytes(max_block_size, byteorder="big")
                except OverflowError:
                    block_len = (m_decrypted.bit_length() + 7) // 8
                    if block_len == 0:
                        block_len = 1
                    block_bytes = m_decrypted.to_bytes(block_len, byteorder="big")
            
            decrypted_bytes += block_bytes
            
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    try:
        if decrypted_bytes:
            padding_length = decrypted_bytes[-1]
            if padding_length > 0 and padding_length <= max_block_size:
                if all(x == padding_length for x in decrypted_bytes[-padding_length:]):
                    decrypted_bytes = decrypted_bytes[:-padding_length]
        
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Decryption failed: The keys used for decryption don't match the encryption keys")


if __name__ == "__main__":
    n, e, d = generateKeys()
    print(f"Public key (n, e): ({n}, {e})")
    print(f"Private key d: {d}\n")

    message = "orignal lsdfklsdj fjkdjiouewoiureoiuwoieruwoieruweoiruweioruwoeruwioeru"
    print(f"Original message: {message}")
    encrypted_bytes = encrypt(message, e, n)
    print(f"Encrypted message (hex): {encrypted_bytes.hex()}")

    decrypted_message = decrypt(encrypted_bytes, d, n)
    print(f"Decrypted message: {decrypted_message}")
