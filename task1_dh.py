import hashlib
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

IV = bytes(16)


def derive_key(s):
    return hashlib.sha256(str(s).encode()).digest()[:16]


def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(message.encode(), AES.block_size))


def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def diffie_hellman(q, g, label=""):
    print(f"--- Diffie-Hellman {label} ---")
    print(f"  public params: q ({q.bit_length()} bits), g = {g}")

    xa = secrets.randbelow(q - 2) + 1 # Alice's private key
    xb = secrets.randbelow(q - 2) + 1 # Bob's private key

    ya = pow(g, xa, q)   # Alice's public key              
    yb = pow(g, xb, q)   # Bob's public key             
    s_alice = pow(yb, xa, q)  # Alice's shared secret       
    s_bob = pow(ya, xb, q)    # Bob's shared secret        

    print(f"  Alice's shared secret == Bob's: {s_alice == s_bob}")
    ka, kb = derive_key(s_alice), derive_key(s_bob)
    print(f"  Alice's AES key: {ka.hex()}")
    print(f"  Bob's   AES key: {kb.hex()}")
    assert ka == kb, "key agreement failed"

    # Exchange two encrypted messages over the shared key.
    c0 = aes_encrypt(ka, "Hi Bob!")          # Alice -> Bob
    c1 = aes_encrypt(kb, "Hi Alice!")        # Bob   -> Alice
    print(f"  Bob   decrypts c0 -> {aes_decrypt(kb, c0)!r}")
    print(f"  Alice decrypts c1 -> {aes_decrypt(ka, c1)!r}")
    print()
    return ka


IETF_Q = int(
    "B10B8F96A080E01DAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E286"
    "75A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D"
    "90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F"
    "0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
IETF_G = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
    "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
    "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)


if __name__ == "__main__":
    diffie_hellman(37, 5, label="(toy params q=37, g=5)")
    diffie_hellman(IETF_Q, IETF_G, label="(1024-bit IETF group)")
