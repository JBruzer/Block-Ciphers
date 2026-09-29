import multiprocessing as mp
import time

import bcrypt
from nltk.corpus import words

SHADOW_PATH = "shadow.txt"
MIN_LEN, MAX_LEN = 6, 10          # assignment: plaintext passwords are 6..10 letters


def load_shadow(path):
    """Parse `username:bcrypt_hash` lines into a list of (user, hash) tuples."""
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            user, digest = line.split(":", 1)
            entries.append((user, digest))
    return entries


def candidate_words():
    seen = set()
    out = []
    for w in words.words():
        w = w.lower()
        if MIN_LEN <= len(w) <= MAX_LEN and w not in seen:
            seen.add(w)
            out.append(w)
    return out


_TARGET = None
_WORDS = None


def _init_worker(target_hash, wordlist):
    global _TARGET, _WORDS
    _TARGET = target_hash
    _WORDS = wordlist


def _check_chunk(index_range):
    lo, hi = index_range
    for w in _WORDS[lo:hi]:
        if bcrypt.checkpw(w.encode(), _TARGET):
            return w
    return None


def crack_hash(digest, wordlist, pool_size, chunk=500):
    target = digest.encode()
    ranges = [(i, min(i + chunk, len(wordlist)))
              for i in range(0, len(wordlist), chunk)]

    start = time.perf_counter()
    with mp.Pool(pool_size, initializer=_init_worker,
                 initargs=(target, wordlist)) as pool:
        for i, result in enumerate(pool.imap(_check_chunk, ranges)):
            if result is not None:
                pool.terminate()
                # chunks complete roughly in order; report guesses through this one
                guesses = (i + 1) * chunk
                return result, time.perf_counter() - start, guesses
    return None, time.perf_counter() - start, len(wordlist)


def parse_bcrypt(digest):
    _, algo, cost, tail = digest.split("$")
    return algo, cost, tail[:22], tail[22:]


def main():
    print(f"Loading shadow file from {SHADOW_PATH}...")
    entries = load_shadow(SHADOW_PATH)
    print(f"Loaded {len(entries)} entries from the shadow file.")
    wordlist = candidate_words()
    cores = mp.cpu_count()

    total_start = time.perf_counter()
    for user, digest in entries:
        # bcrypt hash header: $<algo>$<cost>$<22-char salt><31-char hash>
        algo, cost, salt, hashval = parse_bcrypt(digest)
        print()
        print(f"User: {user}")
        print(f"Algorithm: {algo}")
        print(f"Workfactor: {cost}")
        print(f"Salt: {salt}")
        print(f"Hash value: {hashval}")

        pw, secs, guesses = crack_hash(digest, wordlist, cores)
        if pw:
            print(f"Cracked password: {pw}  ({guesses} guesses, {secs:.2f}s)")
        else:
            print(f"Password not found in dictionary  ({secs:.2f}s)")
    print(f"\nTotal time: {time.perf_counter() - total_start:.2f}s")


if __name__ == "__main__":
    main()
