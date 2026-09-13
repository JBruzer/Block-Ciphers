import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_SIZE = 16

KEY = os.urandom(AES_BLOCK_SIZE)
IV = os.urandom(AES_BLOCK_SIZE)
PREFIX = b"userid=456;userdata="
SUFFIX = b";session-id=31337"


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def pkcs7_pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid padded data length")
    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-padding_length]


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != AES_BLOCK_SIZE or len(key) != AES_BLOCK_SIZE:
        raise ValueError("AES-128 requires 16-byte keys and blocks")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != AES_BLOCK_SIZE or len(key) != AES_BLOCK_SIZE:
        raise ValueError("AES-128 requires 16-byte keys and blocks")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(block) + decryptor.finalize()


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(plaintext)
    previous_ciphertext = iv
    blocks = []
    for start in range(0, len(padded), AES_BLOCK_SIZE):
        plaintext_block = padded[start:start + AES_BLOCK_SIZE]
        ciphertext_block = aes_encrypt_block(
            xor_bytes(plaintext_block, previous_ciphertext), key
        )
        blocks.append(ciphertext_block)
        previous_ciphertext = ciphertext_block
    return b"".join(blocks)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError("CBC ciphertext must contain complete AES blocks")
    previous_ciphertext = iv
    blocks = []
    for start in range(0, len(ciphertext), AES_BLOCK_SIZE):
        ciphertext_block = ciphertext[start:start + AES_BLOCK_SIZE]
        plaintext_block = xor_bytes(
            aes_decrypt_block(ciphertext_block, key), previous_ciphertext
        )
        blocks.append(plaintext_block)
        previous_ciphertext = ciphertext_block
    return pkcs7_unpad(b"".join(blocks))


def submit(user_input: str) -> bytes:
    sanitized = user_input.replace(";", "%3B").replace("=", "%3D")
    message = PREFIX + sanitized.encode("utf-8") + SUFFIX
    return encrypt_cbc(message, KEY, IV)


def verify(ciphertext: bytes) -> bool:
    plaintext = decrypt_cbc(ciphertext, KEY, IV)
    return b";admin=true;" in plaintext


def cbc_bitflipping_attack() -> bytes:
    original_block = b":admin<true:AAAA"
    target_block = b";admin=true;AAAA"
    ciphertext = bytearray(submit("A" * 12 + original_block.decode("ascii")))

    difference = xor_bytes(original_block, target_block)
    previous_block_start = AES_BLOCK_SIZE
    for index, delta in enumerate(difference):
        ciphertext[previous_block_start + index] ^= delta
    return bytes(ciphertext)


def main() -> None:
    print("Sanitization blocks direct user input:", verify(submit(";admin=true;")))
    forged_ciphertext = cbc_bitflipping_attack()
    print("Modified ciphertext grants admin:", verify(forged_ciphertext))


if __name__ == "__main__":
    main()
