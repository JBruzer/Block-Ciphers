import multiprocessing as mp
import time

import bcrypt
from nltk.corpus import words

MIN_LEN, MAX_LEN = 6, 10


def load_shadow(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            user, digest = line.split(":", 1)
            entries.append((user, digest))
    return entries


def parse_bcrypt(digest):
    _, algo, cost, tail = digest.split("$")
    return algo, cost, tail[:22], tail[22:]


def candidate_words():
    seen = set()
    out = []
    for w in words.words():
        w = w.lower()
        if MIN_LEN <= len(w) <= MAX_LEN and w not in seen:
            seen.add(w)
            out.append(w)
    return out

_WORDLIST = None
_GROUPS = None  # {(cost, salt): {hash_tail: user}} 


def _init_worker(wordlist, groups):
    global _WORDLIST, _GROUPS
    _WORDLIST = wordlist
    _GROUPS = groups


def _check_chunk(task):
    group_key, lo, hi = task
    cost, salt = group_key
    salt_hash_by_tail = _GROUPS[group_key]
    salt_prefix = f"$2b${cost}${salt}".encode()
    hits = []
    for w in _WORDLIST[lo:hi]:
        digest = bcrypt.hashpw(w.encode(), salt_prefix).decode()
        tail = digest[-31:]
        if tail in salt_hash_by_tail:
            hits.append((salt_hash_by_tail[tail], w))
    return group_key, hi, hits


def _task_stream(groups, ranges):
    for lo, hi in ranges:
        any_active = False
        for key, still_unsolved in groups.items():
            if still_unsolved:
                any_active = True
                yield (key, lo, hi)
        if not any_active:
            return


def crack_all(entries, cores, chunk=200, on_found=None):
    groups = {}
    for user, digest in entries:
        _, _, salt, tail = parse_bcrypt(digest)
        cost = digest.split("$")[2]
        groups.setdefault((cost, salt), {})[tail] = user
    # Frozen snapshot for the workers; `groups` itself gets mutated below as
    # users are solved, to drive `_task_stream`'s early-stop.
    frozen_groups = {k: dict(v) for k, v in groups.items()}

    wordlist = candidate_words()
    n = len(wordlist)
    ranges = [(lo, min(lo + chunk, n)) for lo in range(0, n, chunk)]

    results = {user: {"password": None, "seconds": None, "guesses": None} for user, _ in entries}
    max_guesses_seen = {key: 0 for key in groups}
    unsolved = len(results)
    start = time.perf_counter()

    with mp.Pool(cores, initializer=_init_worker, initargs=(wordlist, frozen_groups)) as pool:
        for group_key, hi, hits in pool.imap_unordered(_check_chunk, _task_stream(groups, ranges)):
            max_guesses_seen[group_key] = max(max_guesses_seen[group_key], hi)
            for user, word in hits:
                if results[user]["password"] is None:
                    results[user]["password"] = word
                    results[user]["seconds"] = time.perf_counter() - start
                    results[user]["guesses"] = max_guesses_seen[group_key]
                    if on_found is not None:
                        on_found(user, word, results[user]["seconds"], results[user]["guesses"])
                    # drop this user's hash from the live group so
                    # _task_stream stops issuing work for a fully-solved group
                    tail = next(t for t, u in groups[group_key].items() if u == user)
                    del groups[group_key][tail]
                    unsolved -= 1
            if unsolved == 0:
                pool.terminate()
                break

    elapsed = time.perf_counter() - start
    for user, r in results.items():
        if r["password"] is None:
            r["seconds"] = elapsed
            r["guesses"] = n
    return results
