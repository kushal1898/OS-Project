"""
Real-Time OS Resource Utilization and File-Encryption Behavior Analyzer
Workload Generator & Multi-Mode Threat Simulator
"""

import os
import sys
import time
import json
import gzip
import atexit
import signal
import random
import string
import argparse
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

ACTIVE_WORKLOAD_FILE = ".active_workload.pid"


# ============================================================================
# 1. PID Broadcast for Reliable OS Attribution
# ============================================================================
def broadcast_pid(project_root: str, target_dir: str, mode: str) -> dict:
    """
    Writes PID broadcast into .active_workload.pid JSON file in the project root
    and creates numeric marker files in project root and target_dir so analyzer.py
    can correlate process telemetry and open file handles via psutil.
    """
    pid = os.getpid()
    proc_name = "python"
    if HAS_PSUTIL:
        try:
            proc_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_name = "python"

    payload = {
        "pid": pid,
        "process_name": proc_name,
        "mode": mode,
        "start_time": time.time(),
        "project_root": os.path.abspath(project_root),
        "target_dir": os.path.abspath(target_dir),
        "command": " ".join(sys.argv)
    }

    # 1. Write JSON .active_workload.pid in project root
    pid_json_path = os.path.join(project_root, ACTIVE_WORKLOAD_FILE)
    try:
        with open(pid_json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except OSError as err:
        print(f"[PID Broadcast Warning] Could not write {pid_json_path}: {err}")

    # 2. Write numeric marker mock_encryptor.pid in project root and target_dir
    for folder in (project_root, target_dir):
        if os.path.exists(folder):
            marker = os.path.join(folder, "mock_encryptor.pid")
            try:
                with open(marker, "w", encoding="utf-8") as f:
                    f.write(str(pid))
            except OSError as err:
                print(f"[PID Marker Warning] Could not write {marker}: {err}")

    return payload


def cleanup_pid(project_root: str, target_dir: str):
    """
    Cleans up PID marker files upon process exit.
    """
    targets = [
        os.path.join(project_root, ACTIVE_WORKLOAD_FILE),
        os.path.join(project_root, "mock_encryptor.pid"),
        os.path.join(target_dir, "mock_encryptor.pid")
    ]
    for p in targets:
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                continue


# ============================================================================
# 2. Test Corpus Seeder & Baseline Generators
# ============================================================================
def create_dummy_files(target_dir: str, count: int = 5):
    """
    Creates original baseline dummy_doc_0.txt through dummy_doc_4.txt files.
    Preserved for backwards compatibility with tests and analyzer expectations.
    """
    os.makedirs(target_dir, exist_ok=True)
    for i in range(count):
        filepath = os.path.join(target_dir, f"dummy_doc_{i}.txt")
        # Low entropy natural English text
        text = "This is a normal text file with normal words. " * 50
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(text)


def seed_test_directory(target_dir: str, count: int = 40):
    """
    Generates realistic structured text/CSV/JSON/log files in target_dir
    (each 32 KB to 128 KB with low entropy H ~ 4.2 bits/byte) so disk I/O
    syscalls (read_bytes, write_bytes) and CPU scheduling register clearly.
    Also ensures dummy_doc_0.txt through dummy_doc_4.txt are present.
    """
    os.makedirs(target_dir, exist_ok=True)
    # Ensure baseline dummy files exist
    create_dummy_files(target_dir, count=5)

    print(f"[*] Seeding {count} structured corpus files into {target_dir} (32 KB - 128 KB each, H ~ 4.2)...")

    text_template = (
        "Operating system kernel security analyzers observe process execution contexts and virtual memory allocations.\n"
        "Thread pools continuously dispatch I/O requests against filesystem blocks, caching hot inodes in RAM.\n"
        "Cryptographic attacks disrupt standard informational entropy by replacing structured words with uniform byte noise.\n"
        "Endpoint defenses cross-correlate write throughput and file descriptor handles to isolate malicious callers.\n"
    )

    for i in range(count):
        category = i % 4
        # Size distribution between 32 KB (32768) and 128 KB (131072)
        target_size = 32768 + ((i * 1337) % 96000)

        if category == 0:
            filename = f"corpus_document_{i:02d}.txt"
            content = (text_template * ((target_size // len(text_template)) + 1))[:target_size].encode("utf-8")

        elif category == 1:
            filename = f"audit_system_{i:02d}.log"
            lines = []
            for line_idx in range(target_size // 120 + 1):
                sec = line_idx % 60
                msec = (line_idx * 17) % 1000
                tid = line_idx % 16
                lines.append(
                    f"2026-10-15 21:40:{sec:02d}.{msec:03d} [INFO] WorkerThread-{tid} "
                    f"Event ID={10000+line_idx} status=SUCCESS latency={10+(line_idx%25)}ms bytes={512+line_idx*4}"
                )
            content = ("\n".join(lines))[:target_size].encode("utf-8")

        elif category == 2:
            filename = f"financial_ledger_{i:02d}.csv"
            rows = ["transaction_id,timestamp,account_id,merchant,amount,currency,status,verified"]
            for row_idx in range(target_size // 90 + 1):
                rows.append(
                    f"TXN-{100000+row_idx},2026-10-15T21:40:00Z,ACC-{row_idx%100},"
                    f"GlobalEnterpriseCorp,{125.50+(row_idx%500):.2f},USD,CLEARED,true"
                )
            content = ("\n".join(rows))[:target_size].encode("utf-8")

        else:
            filename = f"config_schema_{i:02d}.json"
            base_dict = {
                "system_node_id": f"node_cluster_{i:02d}",
                "environment": "production_enterprise",
                "telemetry_enabled": True,
                "sampling_frequency_hz": 4,
                "services": [
                    {"service_name": f"microservice_{k}", "port": 8080 + k, "ssl": True, "timeout_seconds": 30}
                    for k in range(25)
                ],
                "security_rules": {
                    "max_failed_attempts": 5,
                    "session_timeout_minutes": 60,
                    "require_mfa": True
                }
            }
            raw_json = json.dumps(base_dict, indent=2) + "\n"
            content = (raw_json * ((target_size // len(raw_json)) + 1))[:target_size].encode("utf-8")

        filepath = os.path.join(target_dir, filename)
        with open(filepath, "wb") as f:
            f.write(content)

    print(f"[+] Seeding complete: {count} structured files ready in {target_dir}.")


def reset_target_directory(target_dir: str, count: int = 40):
    """
    Restores target_dir to clean plaintext baseline files (dummy_doc_0.txt to 4.txt
    plus seeded corpus), wiping out .locked, .enc, .gz, and marker files.
    """
    print(f"[*] Resetting {target_dir} to clean baseline state...")
    if os.path.exists(target_dir):
        for root, _, files in os.walk(target_dir):
            for f in files:
                full_p = os.path.join(root, f)
                if f.endswith((".locked", ".enc", ".encrypted", ".gz", ".pid", ".tmp")):
                    try:
                        os.remove(full_p)
                    except OSError:
                        continue

    # Recreate clean baseline
    seed_test_directory(target_dir, count=count)
    print(f"[+] Reset complete. {target_dir} has clean plaintext files ready.")


# ============================================================================
# 3. Three CLI Execution Modes
# ============================================================================
def execute_blitz_mode(target_dir: str):
    """
    Rapid High-I/O Ransomware Attack:
    Rapidly reads files in target_dir, encrypts them with high-entropy ciphertext
    (H > 7.95, uniform chi^2), writes them back with .locked suffix, with a 0.08s
    delay per file so the live OS SIGSTOP freeze happens mid-attack.
    """
    print("\n" + "=" * 70)
    print(">>> STARTING BLITZ MODE (Fast High-I/O Ransomware Attack)")
    print(f">>> Target Directory: {target_dir}")
    print(">>> Delay per file: 0.08s | Threat Expected: Immediate Canary + Velocity Spike")
    print("=" * 70 + "\n")

    files = sorted(os.listdir(target_dir))
    target_files = [
        f for f in files
        if not f.endswith((".locked", ".enc", ".pid", ".gz"))
        and os.path.isfile(os.path.join(target_dir, f))
    ]

    total = len(target_files)
    print(f"[*] Found {total} files to target. Beginning encryption traversal...")

    encrypted_count = 0
    total_bytes_written = 0

    for idx, fname in enumerate(target_files, start=1):
        filepath = os.path.join(target_dir, fname)
        locked_path = filepath + ".locked"

        try:
            # Read plaintext (disk read syscall)
            with open(filepath, "rb") as f_in:
                plaintext = f_in.read()

            # Generate high-entropy ciphertext (H > 7.95, uniform chi^2)
            ciphertext = os.urandom(len(plaintext) + 128)

            # Write encrypted output with .locked suffix (disk write syscall)
            with open(locked_path, "wb") as f_out:
                f_out.write(ciphertext)

            # Remove original file to simulate destructive ransomware
            try:
                os.remove(filepath)
            except OSError:
                pass

            encrypted_count += 1
            total_bytes_written += len(ciphertext)

            print(
                f"[BLITZ] [{idx:02d}/{total:02d}] Encrypted: {fname} -> "
                f"{os.path.basename(locked_path)} ({len(ciphertext)} bytes)"
            )

            # 0.08s delay so OS freeze is observable mid-stream
            time.sleep(0.08)

        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user.")
            break
        except OSError as err:
            print(f"[!] Error accessing {fname}: {err}")
            continue

    print(f"\n[+] Blitz simulation concluded: {encrypted_count}/{total} files encrypted ({total_bytes_written} bytes written).")


def execute_stealth_mode(target_dir: str):
    """
    Low-and-Slow Evasion Mode:
    Sleeps 1.5s between files to keep CPU% near 0.0%, proving that the analyzer
    catches attacks via Canary traps and Entropy Delta (Delta H) even when CPU usage is flat.
    """
    print("\n" + "=" * 70)
    print(">>> STARTING STEALTH MODE (Low-and-Slow Evasion Attack)")
    print(f">>> Target Directory: {target_dir}")
    print(">>> Delay per file: 1.50s | CPU%: Near 0.0% | Threat Expected: Canary + Delta H")
    print("=" * 70 + "\n")

    files = sorted(os.listdir(target_dir))
    target_files = [
        f for f in files
        if not f.endswith((".locked", ".enc", ".pid", ".gz"))
        and os.path.isfile(os.path.join(target_dir, f))
    ]

    total = len(target_files)
    print(f"[*] Found {total} files to target. Beginning slow stealth traversal...")

    encrypted_count = 0
    total_bytes_written = 0

    for idx, fname in enumerate(target_files, start=1):
        filepath = os.path.join(target_dir, fname)
        locked_path = filepath + ".locked"

        try:
            with open(filepath, "rb") as f_in:
                plaintext = f_in.read()

            ciphertext = os.urandom(len(plaintext) + 128)

            with open(locked_path, "wb") as f_out:
                f_out.write(ciphertext)

            try:
                os.remove(filepath)
            except OSError:
                pass

            encrypted_count += 1
            total_bytes_written += len(ciphertext)

            print(f"[STEALTH] [{idx:02d}/{total:02d}] Encrypted: {fname} (H > 7.95) -> Sleeping 1.5s (CPU flat)...")
            time.sleep(1.5)

        except KeyboardInterrupt:
            print("\n[!] Stealth attack interrupted by user.")
            break
        except OSError as err:
            print(f"[!] Error accessing {fname}: {err}")
            continue

    print(f"\n[+] Stealth simulation concluded: {encrypted_count}/{total} files encrypted ({total_bytes_written} bytes written).")


def execute_benign_mode(target_dir: str):
    """
    False-Positive Benchmark Mode:
    Compresses files using standard gzip (with valid 1F 8B magic header)
    into .gz backups without destroying originals.
    Spikes I/O and entropy but flagged as BENIGN_COMPRESSION by analyzer.py without triggering SIGSTOP.
    """
    print("\n" + "=" * 70)
    print(">>> STARTING BENIGN MODE (Gzip Compression Benchmark)")
    print(f">>> Target Directory: {target_dir}")
    print(">>> Delay per file: 0.05s | Magic Header: 1F 8B | Expected: High I/O, NO SIGSTOP")
    print("=" * 70 + "\n")

    files = sorted(os.listdir(target_dir))
    # Exclude canaries from benign backup to avoid tripping canaries during normal backup
    target_files = [
        f for f in files
        if not f.startswith("!000_canary") and not f.startswith("!001_canary")
        and not f.endswith((".gz", ".locked", ".enc", ".pid"))
        and os.path.isfile(os.path.join(target_dir, f))
    ]

    total = len(target_files)
    print(f"[*] Found {total} files for benign compression backup...")

    compressed_count = 0
    total_bytes_written = 0

    for idx, fname in enumerate(target_files, start=1):
        filepath = os.path.join(target_dir, fname)
        gz_path = filepath + ".gz"

        try:
            with open(filepath, "rb") as f_in:
                plaintext = f_in.read()

            # Compress with valid gzip header (1F 8B)
            compressed_data = gzip.compress(plaintext, compresslevel=6)

            with open(gz_path, "wb") as f_out:
                f_out.write(compressed_data)

            # Note: Originals are NOT deleted in benign backup mode
            compressed_count += 1
            total_bytes_written += len(compressed_data)

            print(
                f"[BENIGN] [{idx:02d}/{total:02d}] Compressed: {fname} -> "
                f"{os.path.basename(gz_path)} ({len(compressed_data)} bytes, 1F 8B header)"
            )
            time.sleep(0.05)

        except KeyboardInterrupt:
            print("\n[!] Benign benchmark interrupted by user.")
            break
        except OSError as err:
            print(f"[!] Error compressing {fname}: {err}")
            continue

    print(f"\n[+] Benign benchmark concluded: {compressed_count}/{total} files compressed ({total_bytes_written} bytes written, originals preserved).")


def simulate_encryption(target_dir: str):
    """
    Backwards-compatible legacy entrypoint for simulating encryption.
    Delegates to execute_blitz_mode.
    """
    execute_blitz_mode(target_dir)


# ============================================================================
# CLI Entrypoint
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="OS Workload Generator & Multi-Mode Threat Simulator (OS Analyzer Benchmark)"
    )
    parser.add_argument(
        "--mode",
        choices=["blitz", "stealth", "benign"],
        default="blitz",
        help="Execution mode: 'blitz' (fast high-I/O attack), 'stealth' (low-and-slow evasion), 'benign' (gzip benchmark). Default: blitz"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="N",
        help="Seed test directory with N realistic structured text/log/CSV/JSON files (default: 40)"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset test_monitor_dir to clean baseline files and clean up markers/backups"
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        default=None,
        help="Custom target directory to monitor/simulate (defaults to test_monitor_dir)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=40,
        help="Number of files to generate when seeding (default: 40)"
    )

    args = parser.parse_args()

    project_root = os.path.dirname(os.path.abspath(__file__))
    target_directory = os.path.abspath(args.target_dir) if args.target_dir else os.path.join(project_root, "test_monitor_dir")

    # If --reset requested
    if args.reset:
        reset_target_directory(target_directory, count=args.count)
        cleanup_pid(project_root, target_directory)
        return

    # If --seed N requested without running an attack
    if args.seed is not None:
        seed_test_directory(target_directory, count=args.seed)
        return

    # Check if target directory exists and has files, otherwise seed it
    if not os.path.exists(target_directory) or len(os.listdir(target_directory)) < 5:
        seed_test_directory(target_directory, count=args.count)

    # Broadcast PID for cross-verification
    broadcast_payload = broadcast_pid(project_root, target_directory, args.mode)
    atexit.register(cleanup_pid, project_root, target_directory)

    print(f"[*] Workload PID Broadcast: PID {broadcast_payload['pid']} ({broadcast_payload['process_name']}) registered in {ACTIVE_WORKLOAD_FILE}")

    try:
        if args.mode == "blitz":
            execute_blitz_mode(target_directory)
        elif args.mode == "stealth":
            execute_stealth_mode(target_directory)
        elif args.mode == "benign":
            execute_benign_mode(target_directory)
    finally:
        cleanup_pid(project_root, target_directory)


if __name__ == "__main__":
    main()
