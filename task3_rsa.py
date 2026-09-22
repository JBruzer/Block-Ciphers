import hashlib

from Crypto.Util.number import getPrime

from task1_dh import derive_key, aes_encrypt, aes_decrypt

E = 65537

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse (a and m not coprime)")
    return x % m


def generate_keypair(bits=2048):
    half = bits // 2
    while True:
        p, q = getPrime(half), getPrime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if egcd(E, phi)[0] == 1:       
            d = modinv(E, phi)
            return (n, E), (n, d)


def encrypt(m, pub):
    n, e = pub
    assert 0 <= m < n, "message integer must be < n"
    return pow(m, e, n)


def decrypt(c, priv):
    n, d = priv
    return pow(c, d, n)


def str_to_int(s):
    return int.from_bytes(s.encode(), "big")


def int_to_str(i):
    return i.to_bytes((i.bit_length() + 7) // 8, "big").decode()


def part1_roundtrip():
    print("Part 1: textbook RSA key gen + encrypt/decrypt")
    pub, priv = generate_keypair(2048)
    n = pub[0]
    print(f"  modulus n: {n.bit_length()} bits, e = {E}")
    for msg in ["Hi Bob!", "RSA works", "malleable?"]:
        m = str_to_int(msg)
        c = encrypt(m, pub)
        back = int_to_str(decrypt(c, priv))
        print(f"  {msg!r:14} -> c={str(c)[:24]}...  -> {back!r}  ok={back == msg}")
    print()
    return pub, priv


def part2_malleability_mitm(pub, priv):
    print("Part 2: Mallory fixes the RSA key exchange via malleability")
    n, e = pub

    s_bob = 0xDEADBEEFCAFE
    _c = encrypt(s_bob, pub)

    r = 12345 # Mallory chooses a random r and computes c' = r^e * c mod n
    c_prime = pow(r, e, n)

    s_alice = decrypt(c_prime, priv)         # == r
    k_alice = derive_key(s_alice) 
    c0 = aes_encrypt(k_alice, "Hi Bob!") 

    k_mallory = derive_key(r) 
    print(f"  Mallory chose r = {r}, sent c' = r^e mod n")
    print(f"  Alice's s' = c'^d mod n = {s_alice}  (== r: {s_alice == r})")
    print(f"  keys match: {k_alice == k_mallory}")
    print(f"  Mallory decrypts c0 -> {aes_decrypt(k_mallory, c0)!r}")

    # Now demonstrate that Mallory can tamper with a ciphertext to double a payment.
    m = 1000
    c = encrypt(m, pub)
    c_tampered = (c * pow(2, e, n)) % n
    m_tampered = decrypt(c_tampered, priv)
    print(f"  Tamper: enc(1000) * 2^e decrypts to {m_tampered} "
          f"(= 2*1000: {m_tampered == 2000})")
    print("    -> an attacker can silently alter a value")
    print()


def part3_signature_forgery(pub, priv):
    print("Part 3: RSA signature forgery via malleability")
    n = pub[0]

    def sign(m):
        return decrypt(m, priv)              # m^d mod n
    def verify(m, sig):
        return encrypt(sig, pub) == m % n    # sig^e mod n == m

    m1, m2 = 42, 1337
    sig1, sig2 = sign(m1), sign(m2)

    #   sig1*sig2 = m1^d * m2^d = (m1*m2)^d = Sign(m3)
    m3 = (m1 * m2) % n
    forged = (sig1 * sig2) % n

    print(f"  captured Sign({m1}), Sign({m2})")
    print(f"  forged Sign({m1}*{m2}) = sig1*sig2 mod n")
    print(f"  verifies as valid: {verify(m3, forged)}")
    print()


if __name__ == "__main__":
    pub, priv = part1_roundtrip()
    part2_malleability_mitm(pub, priv)
    part3_signature_forgery(pub, priv)
