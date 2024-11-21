def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    # Extended Euclidean Algorithm to find modular inverse
    m0, x0, x1 = phi, 0, 1
    while e > 1:
        q = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_rsa_keys():
    # Choose two prime numbers (for simplicity, smaller primes)
    p = 61  # Example prime
    q = 53  # Example prime
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(public_key, message):
    e, n = public_key
    m = int(message, 16)  # Convert hex string to integer
    c = pow(m, e, n)      # Encrypt as integer
    return c

def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    m = pow(ciphertext, d, n)  # Decrypt as integer
    hex_message = hex(m)[2:].zfill(16)   # Convert back to hexadecimal string
    return hex_message


