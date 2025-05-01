# Algorithms to Implement

## **1. HMAC (Hash-Based Message Authentication Code)**  

### **Core Idea**:  

HMAC combines a cryptographic hash function (e.g., SHA-256) with a secret key to produce a fixed-size authentication tag.  

### **Implementation Steps**:  

1. **Key Preparation**:  
   - If the key is longer than the hash function’s block size, it is hashed first.  
   - If shorter, it is padded with zeros.  
2. **Inner & Outer Keys**:  
   - Create two derived keys:  
     - `inner_key = key XOR 0x36` (repeated)  
     - `outer_key = key XOR 0x5C` (repeated)  
3. **Hash Twice**:  
   - Compute `inner_hash = Hash(inner_key + message)`.  
   - Compute `HMAC = Hash(outer_key + inner_hash)`.  

## **2. AES (Advanced Encryption Standard)**  

### **Core Idea**:  

AES is a symmetric block cipher that processes data in fixed 128-bit blocks using a secret key (128/192/256 bits).  

### **Implementation Steps (for 128-bit key)**:  

1. **Key Expansion**:  
   - The original key is expanded into multiple round keys (10 rounds for AES-128).  
2. **Initial Round**:  
   - `AddRoundKey`: XOR the block with the first round key.  
3. **Main Rounds (9 rounds)**:  
   - **SubBytes**: Substitute each byte using a lookup table (S-box).  
   - **ShiftRows**: Shift rows of the state matrix.  
   - **MixColumns**: Mix columns using matrix multiplication (omitted in the final round).  
   - **AddRoundKey**: XOR with the next round key.  
4. **Final Round**:  
   - Same as main rounds but skips `MixColumns`.  

## **3. RSA (Rivest-Shamir-Adleman)**  

### **Core Idea**:  

An asymmetric encryption system based on the difficulty of factoring large integers.  

### **Implementation Steps**:  

1. **Key Generation**:  
   - Choose two large primes (**p** and **q**).  
   - Compute **n = p × q** and **φ(n) = (p-1)(q-1)**.  
   - Select **e** (public exponent, often 65537) such that **1 < e < φ(n)**.  
   - Compute **d** (private exponent) where **d ≡ e⁻¹ mod φ(n)**.  
   - **Public Key**: `(e, n)`  
   - **Private Key**: `(d, n)`  
2. **Encryption**:  
   - For plaintext **m**, compute ciphertext **c ≡ mᵉ mod n**.  
3. **Decryption**:  
   - Recover plaintext **m ≡ cᵈ mod n**.  

