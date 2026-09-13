from pathlib import Path

import matplotlib.pyplot as plt


OUTPUT_DIR = Path("task3_graphs")
OUTPUT_DIR.mkdir(exist_ok=True)

block_sizes = [16, 64, 256, 1024, 8192, 16384]
aes_throughput_mb_s = {
    "AES-128-CBC": [514.98108, 1150.74500, 1191.09727, 1195.06681, 1165.98312, 1181.79626],
    "AES-192-CBC": [498.03268, 571.38699, 583.42381, 567.62907, 577.71152, 582.83349],
    "AES-256-CBC": [472.27549, 860.15865, 876.76771, 888.94281, 886.33474, 885.63359],
}

rsa_key_sizes = [1024, 2048, 3072, 4096]
rsa_operations_per_second = {
    "Sign": [5543.6, 724.4, 233.8, 103.8],
    "Verify": [71290.0, 22823.2, 10713.7, 6231.2],
    "Encrypt": [63556.4, 21541.5, 10457.7, 6094.3],
    "Decrypt": [4238.6, 713.0, 238.3, 102.8],
}


def plot_aes() -> None:
    figure, axis = plt.subplots(figsize=(9, 5.5), layout="constrained")
    for label, values in aes_throughput_mb_s.items():
        axis.plot(block_sizes, values, marker="o", linewidth=2, label=label)
    axis.set_xscale("log", base=2)
    axis.set_xticks(block_sizes, [str(size) for size in block_sizes])
    axis.set_xlabel("Block size (bytes)")
    axis.set_ylabel("Throughput (MB/s)")
    axis.set_title("AES-CBC throughput by block size")
    axis.grid(True, which="both", alpha=0.3)
    axis.legend()
    figure.savefig(OUTPUT_DIR / "task3_aes_throughput.png", dpi=200)
    plt.close(figure)


def plot_rsa() -> None:
    figure, axis = plt.subplots(figsize=(9, 5.5), layout="constrained")
    for label, values in rsa_operations_per_second.items():
        axis.plot(rsa_key_sizes, values, marker="o", linewidth=2, label=label)
    axis.set_yscale("log")
    axis.set_xticks(rsa_key_sizes, [str(size) for size in rsa_key_sizes])
    axis.set_xlabel("RSA key size (bits)")
    axis.set_ylabel("Operations per second (log scale)")
    axis.set_title("RSA throughput by key size")
    axis.grid(True, which="both", alpha=0.3)
    axis.legend()
    figure.savefig(OUTPUT_DIR / "task3_rsa_throughput.png", dpi=200)
    plt.close(figure)


if __name__ == "__main__":
    plot_aes()
    plot_rsa()
    print(f"Wrote graphs to {OUTPUT_DIR}")
