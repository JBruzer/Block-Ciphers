from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_SIZE = 16
BMP_HEADER_SIZE = 54

def pkcs7_pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    # Pad the input data using PKCS#7 padding to make its length a multiple of the block size.
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def xor_bytes(left: bytes, right: bytes) -> bytes:
    # Perform a byte-wise XOR operation between two byte strings of equal length.
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    # Encrypt a single block of data using AES-128 in ECB mode.
    if len(block) != AES_BLOCK_SIZE or len(key) != AES_BLOCK_SIZE:
        raise ValueError("AES-128 requires a 16-byte key and 16-byte blocks")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    # Encrypt the plaintext using AES-128 in ECB mode with PKCS#7 padding.
    padded = pkcs7_pad(plaintext)
    return b"".join(
        aes_encrypt_block(padded[start : start + AES_BLOCK_SIZE], key)
        for start in range(0, len(padded), AES_BLOCK_SIZE)
    )


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    # Encrypt the plaintext using AES-128 in CBC mode with PKCS#7 padding.
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC requires a 16-byte IV")

    padded = pkcs7_pad(plaintext)
    previous_ciphertext = iv
    ciphertext_blocks = []

    for start in range(0, len(padded), AES_BLOCK_SIZE):
        plaintext_block = padded[start : start + AES_BLOCK_SIZE]
        chained_block = xor_bytes(plaintext_block, previous_ciphertext)
        ciphertext_block = aes_encrypt_block(chained_block, key)
        ciphertext_blocks.append(ciphertext_block)
        previous_ciphertext = ciphertext_block

    return b"".join(ciphertext_blocks)


def encrypt_bmp(input_path: Path, output_path: Path, mode: str) -> tuple[bytes, bytes | None]:
    # Encrypt a BMP file using AES-128 in either ECB or CBC mode, preserving the BMP header.
    original = input_path.read_bytes()
    if len(original) < BMP_HEADER_SIZE or original[:2] != b"BM":
        raise ValueError("Input must be a BMP with at least a 54-byte header")

    header, pixel_data = original[:BMP_HEADER_SIZE], original[BMP_HEADER_SIZE:]
    key = os.urandom(AES_BLOCK_SIZE)

    if mode == "ecb":
        encrypted_pixels = encrypt_ecb(pixel_data, key)
        iv = None
    else:
        iv = os.urandom(AES_BLOCK_SIZE)
        encrypted_pixels = encrypt_cbc(pixel_data, key, iv)

    output_path.write_bytes(header + encrypted_pixels)
    return key, iv


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt a BMP with manual AES ECB or CBC")
    parser.add_argument("input_bmp", type=Path)
    parser.add_argument("output_bmp", type=Path)
    parser.add_argument("--mode", choices=("ecb", "cbc"), required=True)
    args = parser.parse_args()

    key, iv = encrypt_bmp(args.input_bmp, args.output_bmp, args.mode)
    print(f"Wrote {args.output_bmp}")
    print(f"AES-128 key (hex): {key.hex()}")
    if iv is not None:
        print(f"CBC IV (hex):      {iv.hex()}")


if __name__ == "__main__":
    main()
