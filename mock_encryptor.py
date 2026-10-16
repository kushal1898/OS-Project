"""
========================================================================================
[MOCK WORKLOAD & ENCRYPTION SIMULATOR]
SYLLABUS MAPPING: BCSE303L - Silberschatz "Operating System Concepts" (Modules 2 - 7)
========================================================================================

Role & Purpose:
  Simulates two distinct OS workload profiles inside test_monitor_dir/:
    1. ATTACK MODE (--mode attack):
       - Simulates rapid cryptographic encryption.
       - Generates high disk write system calls and high Shannon entropy (H > 7.9 bits/byte).
       - Provides steady visual pacing (0.25s per file) allowing students to observe:
           Step A: CPU scheduling priority demotion (Module 3)
           Step B: Process preemption & suspension to STOPPED state (Module 2 & 3)
           Step C: Access Matrix permission revocation via os.chmod (Module 7)
           Step D: Process SIGKILL termination (Module 2)
           Step E: Write-Ahead Journal recovery rollback (Module 6)
    2. NORMAL MODE (--mode normal):
       - Simulates standard benign application behavior (appending low-entropy text logs, H approx 4.3).
       - Demonstrates that normal workloads run to completion without OS intervention.
    3. RESET UTILITY (--reset):
       - Re-seeds test_monitor_dir/ with clean, readable plaintext files.
========================================================================================
"""

import os
import sys
import time
import json
import stat
import math
import random
import argparse
from pathlib import Path

# Configure utf-8 stdout if supported by OS terminal
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ======================================================================================
# TEXTBOOK TEXT GENERATOR (LOW SHANNON ENTROPY ~4.3 BITS/BYTE)
# ======================================================================================

OS_CONCEPTS_PARAGRAPHS = [
    "Operating systems provide core resource abstractions including process management, CPU scheduling, virtual memory paging, and storage file systems. In Silberschatz Operating System Concepts, cooperating processes coordinate execution through bounded buffer queues synchronized with semaphores and mutual exclusion mutex locks. ",
    "The CPU scheduler allocates processor cycles to threads based on priority levels, preemption policies, and time quantum slices. When process threads execute concurrent workloads, context switching preserves register state, program counters, and stack pointers within the Process Control Block. ",
    "Virtual memory paging maps virtual addresses into physical memory frames while monitoring page fault rates and resident working set allocations. Modern operating systems ensure security through access control matrices and protection domains that govern read, write, and execute permissions. ",
    "Storage management architectures incorporate write-ahead logging and journal transactions to guarantee consistency across unexpected crash events. File system drivers maintain inode tables, directory hierarchies, and block allocation structures on persistent secondary storage devices. "
]

def generate_plaintext_content(target_kb: int = 50) -> str:
    """
    Generates realistic, low-entropy textbook prose (~4.3 bits/byte)
    matching the specified size in kilobytes (~50 KB).
    """
    blocks = []
    current_size = 0
    target_bytes = target_kb * 1024

    i = 0
    while current_size < target_bytes:
        paragraph = OS_CONCEPTS_PARAGRAPHS[i % len(OS_CONCEPTS_PARAGRAPHS)]
        block = f"Section {i+1}: {paragraph}\n\n"
        blocks.append(block)
        current_size += len(block.encode('utf-8'))
        i += 1

    return "".join(blocks)


def calculate_entropy(data: bytes) -> float:
    """
    Shannon Entropy helper for live terminal output.
    H(X) = - SUM( P(x) * log2(P(x)) )
    """
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 3)


# ======================================================================================
# PID REGISTRATION & CLEANUP (.active_pid.json)
# ======================================================================================

def register_active_pid(target_dir: str, mode: str):
    """
    Writes process metadata (PID, start timestamp, mode) to .active_pid.json
    so analyzer.py immediately locks onto this Process Control Block (PCB).
    """
    pid = os.getpid()
    payload = {
        "pid": pid,
        "mode": mode,
        "start_time": time.time(),
        "command": sys.argv[0],
        "target_dir": os.path.abspath(target_dir)
    }

    locations = [
        os.path.join(os.getcwd(), ".active_pid.json"),
        os.path.join(target_dir, ".active_pid.json")
    ]

    for loc in locations:
        try:
            with open(loc, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

    print(f"[PID REGISTRATION] Registered Workload PID {pid} to .active_pid.json")


def clear_active_pid(target_dir: str):
    """
    Removes .active_pid.json files on clean completion or reset.
    """
    locations = [
        os.path.join(os.getcwd(), ".active_pid.json"),
        os.path.join(target_dir, ".active_pid.json")
    ]
    for loc in locations:
        if os.path.exists(loc):
            try:
                os.remove(loc)
            except Exception:
                pass


# ======================================================================================
# SEEDING & RESET LOGIC
# ======================================================================================

def seed_test_files(target_dir: str, count: int = 25) -> list:
    """
    Populates target_dir with up to count realistic plaintext files (~40-50 KB each).
    Keeps dummy_doc_0.txt through dummy_doc_4.txt intact and supplements with
    reports, CSV logs, and database records.
    """
    os.makedirs(target_dir, exist_ok=True)
    created = []

    # File manifest: 5 dummy docs + reports + databases + system logs
    manifest = [f"dummy_doc_{i}.txt" for i in range(5)]
    manifest += [f"report_{i:02d}.txt" for i in range(1, 11)]
    manifest += [f"database_{i:02d}.csv" for i in range(1, 6)]
    manifest += [f"system_log_{i:02d}.log" for i in range(1, 6)]

    manifest = manifest[:count]

    for fname in manifest:
        fpath = os.path.join(target_dir, fname)
        
        # Ensure file has write permissions
        if os.path.exists(fpath):
            try:
                os.chmod(fpath, stat.S_IREAD | stat.S_IWRITE | stat.S_IWUSR)
            except Exception:
                pass

        # Write clean plaintext content (~40 KB)
        content = generate_plaintext_content(target_kb=40)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        created.append(fname)

    return created


def reset_environment(target_dir: str, count: int = 25):
    """
    Restores test_monitor_dir/ to a completely clean baseline:
      1. Removes any .locked, .enc, or .tmp artifacts.
      2. Re-seeds all files with clean low-entropy plaintext.
      3. Clears .active_pid.json.
    """
    print(f"\n[RESET] Restoring {target_dir} to clean baseline state...")
    os.makedirs(target_dir, exist_ok=True)

    # 1. Remove encrypted or temporary artifacts
    for entry in os.listdir(target_dir):
        if entry.endswith((".locked", ".enc", ".encrypted", ".tmp")) or entry == ".active_pid.json":
            p = os.path.join(target_dir, entry)
            try:
                os.chmod(p, stat.S_IREAD | stat.S_IWRITE | stat.S_IWUSR)
                os.remove(p)
            except Exception:
                pass

    # 2. Re-seed clean files
    seeded = seed_test_files(target_dir, count=count)
    clear_active_pid(target_dir)

    print(f"[RESET] Successfully re-seeded {len(seeded)} clean plaintext files.")
    print(f"[RESET] All permissions restored and .active_pid.json cleared.")


# ======================================================================================
# SIMULATION WORKLOAD ENGINES
# ======================================================================================

def run_attack_simulation(target_dir: str, delay: float = 0.25):
    """
    ATTACK MODE:
    Simulates ransomware behavior by iterating through files, reading original content,
    and overwriting with cryptographically random bytes (H > 7.9 bits/byte).
    Paced with delay (0.25s) to allow real-time observation of OS scheduling and defenses:
      - Files 1-2: Priority throttled (Module 3).
      - Files 3-4: Process preempted/suspended (Module 2) -> Revoked (Module 7) -> Terminated -> Journal Rollback (Module 6).
    """
    files_to_encrypt = [
        f for f in sorted(os.listdir(target_dir))
        if os.path.isfile(os.path.join(target_dir, f))
        and not f.startswith(".")
        and not f.endswith((".locked", ".enc", ".baseline"))
    ]

    print("\n" + "=" * 80)
    print(f"[ATTACK SIMULATOR] Launching Encryption Workload on {len(files_to_encrypt)} files")
    print(f"[ATTACK SIMULATOR] Target Directory: {target_dir}")
    print(f"[ATTACK SIMULATOR] Pacing Delay    : {delay}s per file")
    print("=" * 80 + "\n")

    files_attacked = 0
    for idx, filename in enumerate(files_to_encrypt, start=1):
        filepath = os.path.join(target_dir, filename)

        try:
            # 1. Read existing content (Generates read system calls & disk activity)
            with open(filepath, "rb") as f:
                orig_bytes = f.read()

            orig_entropy = calculate_entropy(orig_bytes)
            file_kb = len(orig_bytes) / 1024.0

            # 2. Generate high-entropy ciphertext simulation (os.urandom produces H ~ 7.95)
            encrypted_payload = os.urandom(len(orig_bytes) + 256)
            new_entropy = calculate_entropy(encrypted_payload)

            # 3. Overwrite file with encrypted payload (Generates write system calls)
            with open(filepath, "wb") as f:
                f.write(encrypted_payload)

            files_attacked += 1
            print(f"[{idx:02d}/{len(files_to_encrypt):02d}] ENCRYPTED: {filename:<20} "
                  f"Size: {file_kb:5.1f} KB | "
                  f"Entropy: {orig_entropy:.2f} -> {new_entropy:.2f} bits/byte [HIGH]")

            # Pacing interval allowing OS analyzer to observe telemetry and trigger defense
            time.sleep(delay)

        except PermissionError:
            print(f"\n[!] ACCESS DENIED on {filename}:")
            print(f"    Operating System Protection invoked os.chmod / Access Matrix lock!")
            print(f"    Process cannot write further. OS defense mechanism active.")
            break
        except Exception as e:
            print(f"[!] Operation interrupted on {filename}: {e}")
            break

    print("\n" + "-" * 80)
    print(f"[ATTACK SIMULATOR] Workload ended after attempting {files_attacked} files.")
    print("-" * 80)


def run_normal_simulation(target_dir: str, delay: float = 0.25):
    """
    NORMAL MODE:
    Simulates benign application behavior by appending natural text log entries (H ~ 4.2).
    Demonstrates that legitimate processes run smoothly without triggering OS defenses.
    """
    target_files = [
        f for f in sorted(os.listdir(target_dir))
        if os.path.isfile(os.path.join(target_dir, f))
        and not f.startswith(".")
        and not f.endswith((".locked", ".enc", ".baseline"))
    ]

    print("\n" + "=" * 80)
    print(f"[BENIGN WORKLOAD] Running Normal Application Workload on {len(target_files)} files")
    print(f"[BENIGN WORKLOAD] Appending low-entropy text records (Expected H: 3.5 - 4.5)")
    print("=" * 80 + "\n")

    for idx, filename in enumerate(target_files, start=1):
        filepath = os.path.join(target_dir, filename)
        try:
            # Benign append operation
            log_entry = (
                f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] AUDIT LOG ENTRY: "
                f"Routine system checkpoint verification completed successfully.\n"
            )
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(log_entry)

            with open(filepath, "rb") as f:
                current_bytes = f.read()
            current_entropy = calculate_entropy(current_bytes)

            print(f"[{idx:02d}/{len(target_files):02d}] NORMAL WRITE: {filename:<20} "
                  f"Entropy: {current_entropy:.2f} bits/byte [NORMAL/BENIGN]")

            time.sleep(delay)

        except Exception as e:
            print(f"[!] Error processing {filename}: {e}")

    print("\n" + "-" * 80)
    print(f"[BENIGN WORKLOAD] All {len(target_files)} files processed normally with 0 security alerts.")
    print("-" * 80)


# ======================================================================================
# CLI ENTRY POINT
# ======================================================================================

def main():
    parser = argparse.ArgumentParser(
        description="OS-Project Mock Workload & Encryption Simulator (BCSE303L Syllabus Mapped)"
    )
    parser.add_argument(
        "--mode", choices=["attack", "normal"], default="attack",
        help="Workload mode: 'attack' (ransomware high-entropy simulation) or 'normal' (benign text writes)"
    )
    parser.add_argument(
        "--seed", type=int, default=25,
        help="Number of plaintext test files to seed in target directory (default: 25)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.25,
        help="Pacing delay in seconds between file operations (default: 0.25s)"
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Restores target directory to clean baseline plaintext files and clears .active_pid.json"
    )
    parser.add_argument(
        "--dir", type=str, default="test_monitor_dir",
        help="Target monitored directory (default: test_monitor_dir)"
    )

    args = parser.parse_args()
    target_dir = os.path.abspath(args.dir)

    # 1. Reset command
    if args.reset:
        reset_environment(target_dir, count=args.seed)
        return

    # 2. Check if seeding is necessary
    if not os.path.exists(target_dir) or len([f for f in os.listdir(target_dir) if not f.startswith(".")]) < 5:
        print(f"[SEED] Initializing target directory with {args.seed} test files...")
        seed_test_files(target_dir, count=args.seed)

    # 3. Register active PID for PCB tracking in analyzer.py
    register_active_pid(target_dir, mode=args.mode)

    try:
        if args.mode == "attack":
            run_attack_simulation(target_dir, delay=args.delay)
        else:
            run_normal_simulation(target_dir, delay=args.delay)
    finally:
        # Note: If the process is terminated via SIGKILL from analyzer.py,
        # .active_pid.json will remain as forensic proof of the terminated PID.
        # Otherwise, clean up on normal exit.
        clear_active_pid(target_dir)


if __name__ == "__main__":
    main()
