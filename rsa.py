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
    # Gunakan bilangan prima yang lebih besar
    p = 7919  # Contoh bilangan prima besar
    q = 7873
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Nilai umum untuk eksponen publik
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# Fungsi untuk enkripsi dengan RSA
def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext

# Fungsi untuk dekripsi dengan RSA
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext





