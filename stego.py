import hashlib, io, sys
import numpy as np
from PIL import Image

MAGIC = b"STEG"

def seed_from_password(password):
    return int.from_bytes(hashlib.sha256(password.encode("utf-8")).digest()[:8], "big")

def capacity_bytes(h, w, channels=3):
    return (h * w * channels) // 8

def bytes_to_bits(data):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))  # MSB first

def bits_to_bytes(bits):
    bits = np.asarray(bits, dtype=np.uint8)
    bits = np.pad(bits, (0, -len(bits) % 8))
    return np.packbits(bits).tobytes()

def frame_payload(kind, payload):
    return MAGIC + (b"\x00" if kind == "text" else b"\x01") + len(payload).to_bytes(4, "big") + payload

def _perm(password, total):
    return np.random.default_rng(seed_from_password(password)).permutation(total)

def embed(cover_path, out_path, kind, payload, password):
    arr = np.array(Image.open(cover_path).convert("RGB"))
    flat = arr.reshape(-1).copy()              # flat index == pixel*3 + channel
    bits = bytes_to_bits(frame_payload(kind, payload))
    if len(bits) > flat.size:
        raise ValueError("payload too large for this cover")
    pos = _perm(password, flat.size)[:len(bits)]
    flat[pos] = (flat[pos] & 0xFE) | bits
    Image.fromarray(flat.reshape(arr.shape)).save(out_path, "PNG")

def extract(stego_path, password):
    flat = np.array(Image.open(stego_path).convert("RGB")).reshape(-1)
    perm = _perm(password, flat.size)
    header = bits_to_bytes(flat[perm[:72]] & 1)
    if header[:4] != MAGIC:
        return None, None
    kind = "text" if header[4] == 0 else "image"
    n = int.from_bytes(header[5:9], "big")
    if (9 + n) * 8 > flat.size:
        return None, None
    payload = bits_to_bytes(flat[perm[72:72 + n * 8]] & 1)
    return (kind, payload.decode("utf-8")) if kind == "text" else (kind, payload)

if __name__ == "__main__":
    cover, pw = "apple_logo_cover.png", "secret"
    embed(cover, "stego_text.png", "text", "This is a secret".encode(), pw)
    buf = io.BytesIO(); Image.open("laptop_secret.png").convert("RGB").save(buf, "PNG")
    embed(cover, "stego_laptop.png", "image", buf.getvalue(), pw)
    a = np.array(Image.open(cover).convert("RGB")).astype(int)
    for f in ("stego_text.png", "stego_laptop.png"):
        print(f, "max pixel diff vs cover:", np.abs(np.array(Image.open(f).convert("RGB")).astype(int) - a).max())
    h, w, _ = a.shape
    print("cover", (h, w), "capacity bytes", capacity_bytes(h, w), "laptop payload bytes", len(buf.getvalue()))
    print("recovered text:", extract("stego_text.png", pw))
    k, data = extract("stego_laptop.png", pw)
    Image.open(io.BytesIO(data)).save("recovered_laptop.png")
    print("recovered image kind:", k, "identical to original:", data == buf.getvalue())
    print("wrong password:", extract("stego_text.png", "wrong"))
    try: embed(cover, "x.png", "image", bytes(h * w * 3 // 8), pw)
    except ValueError as e: print("oversized payload ->", e)
