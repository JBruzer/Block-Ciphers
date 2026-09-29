import hashlib
import random
import string
import time


def sha256_hash(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()


def truncate_hash(hash_string, bits):
    hex_chars = (bits + 3) // 4                 # ceil(bits/4) chars needed
    value = int(hash_string[:hex_chars], 16)
    mask = (1 << bits) - 1                     
    return value & mask


def hamming_distance(s1, s2):
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))


def random_string(length=10):
    return "".join(random.choice(string.ascii_letters) for _ in range(length))

def find_hamming_distance_1():
    base = random_string(10)
    i = random.randrange(len(base))
    # pick a different letter for position i
    replacement = random.choice([c for c in string.ascii_letters if c != base[i]])
    modified = base[:i] + replacement + base[i + 1:]
    assert hamming_distance(base, modified) == 1
    return base, modified


def find_collision(bits, max_attempts=5_000_000):
    seen = {}
    start = time.perf_counter()
    for attempts in range(1, max_attempts + 1):
        s = random_string(10)
        h = truncate_hash(sha256_hash(s), bits)
        if h in seen and seen[h] != s:
            return seen[h], s, attempts, time.perf_counter() - start
        seen[h] = s
    return None, None, max_attempts, time.perf_counter() - start


def task_1a():
    print("Task 1a: SHA256 hashes of arbitrary inputs")
    for text in ["Hello, World!", "Python", "Cryptography"]:
        print(f"Input: {text}")
        print(f"SHA256: {sha256_hash(text)}")
    print()


def task_1b():
    print("Task 1b: Strings with Hamming distance of 1")
    for i in range(1, 4):
        s1, s2 = find_hamming_distance_1()
        h1, h2 = sha256_hash(s1), sha256_hash(s2)
        print(f"Pair {i}:")
        print(f"  s1 = {s1}   h1 = {h1}")
        print(f"  s2 = {s2}   h2 = {h2}")
    print()


def task_1c():
    print("Task 1c: Finding collisions for truncated hashes")
    bits_list, time_list, inputs_list = [], [], []
    rows, timeouts = [], []
    for bits in range(8, 51, 2):
        a, b, attempts, elapsed = find_collision(bits)
        if a is None:
            timeouts.append((bits, attempts))
            continue
        rows.append((bits, a, b, attempts, elapsed))
        bits_list.append(bits)
        time_list.append(elapsed)
        inputs_list.append(attempts)

    # results table
    print(f"{'Bits':>5} | {'Input 1':>10} | {'Input 2':>10} | {'Attempts':>10} | {'Time (s)':>10}")
    print("-" * 60)
    for bits, a, b, attempts, elapsed in rows:
        print(f"{bits:>5} | {a:>10} | {b:>10} | {attempts:>10} | {elapsed:>10.4f}")
    for bits, attempts in timeouts:
        print(f"{bits:>5} | timed out after {attempts} attempts")

    _plot(bits_list, time_list, inputs_list)


def _plot(bits_list, time_list, inputs_list):
    try:
        import matplotlib
        matplotlib.use("Agg")          # no display needed
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed - skipping collision_analysis.png)")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    ax1.plot(bits_list, time_list, "o-", color="tab:blue")
    ax1.set(xlabel="Digest size (bits)", ylabel="Collision time (s)",
            title="Digest Size vs Collision Time")
    ax1.set_yscale("log")              # exponential growth reads better on log
    ax1.grid(True, which="both", alpha=0.3)

    ax2.plot(bits_list, inputs_list, "s-", color="tab:red", label="measured")
    # overlay theoretical birthday bound 2^(bits/2) for comparison
    theory = [2 ** (b / 2) for b in bits_list]
    ax2.plot(bits_list, theory, "--", color="gray", label="2^(bits/2) theory")
    ax2.set(xlabel="Digest size (bits)", ylabel="Inputs tried",
            title="Digest Size vs Number of Inputs")
    ax2.set_yscale("log")
    ax2.legend()
    ax2.grid(True, which="both", alpha=0.3)

    fig.tight_layout()
    fig.savefig("collision_analysis.png", dpi=120)
    print("\nSaved graphs as 'collision_analysis.png'")


def task_1_main():
    random.seed()                      # nondeterministic; seed(0) for repeatable
    task_1a()
    task_1b()
    task_1c()


if __name__ == "__main__":
    task_1_main()
