import random
from math import gcd


def is_prime(n: int) -> bool:
    """Trial-division primality test."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def generate_prime(start: int = 100, end: int = 300) -> int:
    """
    Pick a random prime in [start, end].
    Raises if the range contains no primes (avoids silent infinite loop).
    """
    candidates = [n for n in range(start, end + 1) if is_prime(n)]
    if not candidates:
        raise ValueError(f"No primes exist in range [{start}, {end}]")
    return random.choice(candidates)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Returns (g, x, y) such that  a*x + b*y = g = gcd(a, b).

    Derivation of the recurrence:
      We know  gcd(a, b) == gcd(b, a % b),  so recurse on (b, a % b).
      The recursive call returns (g, x1, y1) satisfying:
          b*x1 + (a % b)*y1 = g
      Since  a % b = a - (a // b)*b,  substituting gives:
          b*x1 + (a - (a // b)*b)*y1 = g
          a*y1 + b*(x1 - (a // b)*y1) = g
      So the new coefficients for (a, b) are:
          x = y1
          y = x1 - (a // b)*y1
    """
    if b == 0:
        return a, 1, 0  # base case: a*1 + 0*0 = a

    g, x_rec, y_rec = extended_gcd(b, a % b)

    x = y_rec
    y = x_rec - (a // b) * y_rec

    return g, x, y


def modular_inverse(a: int, m: int) -> int:
    """
    Returns x such that (a * x) % m == 1.
    Requires gcd(a, m) == 1 (i.e. a and m are coprime).
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (gcd = {g}, must be 1)")
    return x % m  # ensure positive result


def generate_keys(prime_start: int = 100, prime_end: int = 300) -> tuple[tuple[int, int], tuple[int, int]]:
    """
    Generate an RSA key pair: ((e, n), (d, n)).

      n   = p * q          — public modulus
      phi = (p-1)*(q-1)    — Euler's totient (kept secret)
      e                    — public exponent, coprime with phi
      d   = e⁻¹ mod phi    — private exponent

    Encryption:  c = m^e mod n
    Decryption:  m = c^d mod n
    """
    # Regenerate until we get a valid phi that's coprime with e=65537
    e = 65537
    while True:
        p = generate_prime(prime_start, prime_end)
        q = generate_prime(prime_start, prime_end)
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break  # valid pair found

    n = p * q
    d = modular_inverse(e, phi)

    public_key  = (e, n)
    private_key = (d, n)
    return public_key, private_key


def encrypt(message: int, public_key: tuple[int, int]) -> int:
    """Encrypt an integer message: c = message^e mod n."""
    e, n = public_key
    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: tuple[int, int]) -> int:
    """Decrypt a ciphertext integer: m = ciphertext^d mod n."""
    d, n = private_key
    return pow(ciphertext, d, n)


def text_to_int(text: str) -> int:
    """Encode text as UTF-8 bytes, then interpret those bytes as one big integer."""
    return int.from_bytes(text.encode("utf-8"), byteorder="big")

def int_to_text(n: int) -> str:
    """Reverse: figure out how many bytes we need, convert back, then decode."""
    byte_length = (n.bit_length() + 7) // 8  # minimum bytes needed
    return n.to_bytes(byte_length, byteorder="big").decode("utf-8")


if __name__ == "__main__":
    public_key, private_key = generate_keys()
    message = "Hi"

    message_int = text_to_int(message)
    ciphertext  = encrypt(message_int, public_key)
    recovered   = int_to_text(decrypt(ciphertext, private_key))

    print(f"Public key:  {public_key}")
    print(f"Private key: {private_key}")
    print(f"Message:     {message}")
    print(f"Ciphertext:  {ciphertext}")
    print(f"Decrypted:   {recovered}")
    assert recovered == message, "Decryption failed!"