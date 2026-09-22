import secrets

from task1_dh import derive_key, aes_encrypt, aes_decrypt, IETF_Q, IETF_G


def part1_key_fixing(q, g):
    print("Part 1: Mallory replaces Y_A and Y_B with q  (key fixing)")

    xa = secrets.randbelow(q - 2) + 1
    xb = secrets.randbelow(q - 2) + 1
    _ya, _yb = pow(g, xa, q), pow(g, xb, q)

    yb_seen_by_alice = q   # Mallory replaces Bob's public key with q         
    ya_seen_by_bob = q     # Mallory replaces Alice's public key with q       

    s_alice = pow(yb_seen_by_alice, xa, q)  # Alice computes shared secret with tampered public key   
    s_bob = pow(ya_seen_by_bob, xb, q)      # Bob computes shared secret with tampered public key  
    s_mallory = 0    # Mallory knows the shared secret because she replaced the public keys with q, which results in a shared secret of 0 for both Alice and Bob.                          

    print(f"  s computed by Alice   : {s_alice}")
    print(f"  s computed by Bob     : {s_bob}")
    print(f"  s guessed by Mallory  : {s_mallory}")

    # Alice and Bob encrypt real messages; Mallory decrypts with her known key.
    c0 = aes_encrypt(derive_key(s_alice), "Hi Bob!")
    c1 = aes_encrypt(derive_key(s_bob), "Hi Alice!")
    k_m = derive_key(s_mallory)
    print(f"  Mallory decrypts c0 -> {aes_decrypt(k_m, c0)!r}")
    print(f"  Mallory decrypts c1 -> {aes_decrypt(k_m, c1)!r}")
    print()


def part2_generator_tampering(q):
    print("Part 2: Mallory tampers with the generator g")

    for g_bad in (1, q, q - 1):
        xa = secrets.randbelow(q - 2) + 1
        xb = secrets.randbelow(q - 2) + 1
        ya, yb = pow(g_bad, xa, q), pow(g_bad, xb, q)
        s_alice = pow(yb, xa, q)
        s_bob = pow(ya, xb, q)

        if g_bad == 1:
            candidates = [1]
        elif g_bad == q:
            candidates = [0]
        else:                       # g = q-1 ≡ -1
            candidates = [1, q - 1]

        c0 = aes_encrypt(derive_key(s_alice), "Hi Bob!")

        # Mallory tries each candidate key until one decrypts cleanly.
        recovered = None
        for s_guess in candidates:
            try:
                recovered = aes_decrypt(derive_key(s_guess), c0)
                break
            except (ValueError, KeyError):
                continue

        tag = "q" if g_bad == q else ("q-1" if g_bad == q - 1 else "1")
        print(f"  g set to {tag:>3}: s_alice==s_bob {s_alice == s_bob}, "
              f"candidates {candidates} -> Mallory reads c0 as {recovered!r}")
    print()


if __name__ == "__main__":
    part1_key_fixing(IETF_Q, IETF_G)
    part2_generator_tampering(IETF_Q)
