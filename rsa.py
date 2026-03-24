import random
from math import gcd

# --- Basic primality test (sufficient for toy RSA) ---
def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r = int(n**0.5)
    for i in range(3, r + 1, 2):
        if n % i == 0:
            return False
    return True

# --- Generate a random prime in a range ---
def generate_prime(start=100, end=300):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p


def extended_gcd(a, b):
    """
    Return a tuple (g, x, y) such that:
        g = gcd(a, b)
        x, y satisfy the equation: a*x + b*y = g
    This is the 'extended' part: it not only finds gcd,
    but also the coefficients that express it.
    """

    # Base case: gcd(a, 0) = a
    # And the equation becomes: a*1 + 0*0 = a
    if b == 0:
        return a, 1, 0

    # Recursively apply the algorithm:
    # gcd(a, b) == gcd(b, a % b)
    gcd_value, x1, y1 = extended_gcd(b, a % b)

    # Now unwind the recursion:
    # The previous call gave us:
    #     b*x1 + (a % b)*y1 = gcd
    #
    # But a % b = a - (a // b)*b
    # Substitute that in and rearrange to express gcd in terms of a and b.
    x = y1
    y = x1 - (a // b) * y1

    return gcd_value, x, y


def modulus_inverse(a, m):
    """
    Compute the modular inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    """

    # Run the extended Euclidean algorithm
    gcd_value, x, _ = extended_gcd(a, m)

    # If gcd != 1, then a has no inverse modulo m
    if gcd_value != 1:
        raise ValueError("No modular inverse exists because gcd(a, m) != 1")

    # x may be negative; modulo m gives the positive representative
    return x % m


# --- Key generation ---
def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        # fallback if phi accidentally shares a factor
        e = 3

    d = modulus_inverse(e, phi)
    return (e, n), (d, n)

# --- Encryption / Decryption ---
def encrypt(m, public_key):
    e, n = public_key
    return pow(m, e, n)

def decrypt(c, private_key):
    d, n = private_key
    return pow(c, d, n)

# --- Demo ---
public_key, private_key = generate_keys()
message = 42

cipher = encrypt(message, public_key)
plain = decrypt(cipher, private_key)

print("Public key:", public_key)
print("Private key:", private_key)
print("Message:", message)
print("Cipher:", cipher)
print("Decrypted:", plain)
