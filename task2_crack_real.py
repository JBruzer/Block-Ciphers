"""
Module 4 - Task 2: crack the real bcrypt shadow file from Canvas.

Run:
  python task2_crack_real.py

Loads shadow_real.txt, cracks every hash via crack_lib.crack_all (one
multiprocessing pool spanning all users, sharing bcrypt calls across users
who share a salt), and writes task2_results.txt with a copy of the printed
table for the report.
"""

import os
import time

from crack_lib import load_shadow, parse_bcrypt, crack_all

SHADOW_PATH = "shadow_real.txt"
RESULTS_PATH = "task2_results.txt"


def _report_progress(user, password, seconds, guesses):
    print(f"  cracked {user:<10} -> {password:<12} ({seconds:.1f}s, {guesses} guesses)", flush=True)


def main():
    entries = load_shadow(SHADOW_PATH)
    cores = os.cpu_count()
    print(f"Loaded {len(entries)} entries from {SHADOW_PATH}; using {cores} CPU cores.\n", flush=True)

    start = time.perf_counter()
    results = crack_all(entries, cores, on_found=_report_progress)
    total = time.perf_counter() - start

    header = f"{'User':<10} {'Algo':<5} {'Cost':<5} {'Salt':<24} {'Password':<12} {'Time (s)':>9} {'Guesses':>9}"
    lines = [header, "-" * len(header)]
    for user, digest in entries:
        algo, cost, salt, _ = parse_bcrypt(digest)
        r = results[user]
        pw = r["password"] or "NOT FOUND"
        lines.append(
            f"{user:<10} {algo:<5} {cost:<5} {salt:<24} {pw:<12} {r['seconds']:>9.2f} {r['guesses']:>9}"
        )
    lines.append("")
    lines.append(f"Total wall-clock time: {total:.2f}s")

    output = "\n".join(lines)
    print(output)
    with open(RESULTS_PATH, "w") as f:
        f.write(output + "\n")
    print(f"\nWrote results to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
