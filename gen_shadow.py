import bcrypt

WORK_FACTOR = 6       
SHADOW_PATH = "shadow.txt"

USERS = [
    ("Durin",  "abacus"),
    ("Gimli",  "anchor"),
    ("Thorin", "anthem"),
    ("Balin",  "ballad"),
]


def main():
    lines = []
    for username, password in USERS:
        salt = bcrypt.gensalt(rounds=WORK_FACTOR)
        digest = bcrypt.hashpw(password.encode(), salt).decode()
        lines.append(f"{username}:{digest}")
        print(f"  {username:8} <- {password!r:12} => {digest}")

    with open(SHADOW_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nWrote {len(USERS)} entries to {SHADOW_PATH} (work factor {WORK_FACTOR})")


if __name__ == "__main__":
    main()
