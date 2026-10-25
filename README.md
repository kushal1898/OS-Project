# 🛡️ Real-Time OS Resource Utilization & File-Encryption Behavior Analyzer
> **Course Syllabus Mapping:** BCSE303L — Operating Systems (Textbook: *Operating System Concepts* by Silberschatz, Galvin, and Gagne)  
> **Architecture Principle:** 1 Class = 1 Exact Syllabus Module (Modules 2, 3, 4, 5, 6, and 7)

---

## 📌 Project Executive Summary

Traditional antivirus systems rely on static virus signatures or brittle magic-byte headers, failing against zero-day cryptographic ransomware. **OS-Analyzer** is an educational, real-time operating system behavioral monitor designed to detect and neutralize rapid file encryption attacks using fundamental operating system mechanisms:

1. **Information Theory & Storage Entropy**: Real-time single-byte **Shannon Entropy** ($0.0 \le H \le 8.0$ bits/byte) to detect cryptographic randomness.
2. **Process Abstraction & Telemetry**: Live **Process Control Block (PCB)** tracking including process states (`READY/RUNNING` $\to$ `WAITING/STOPPED` $\to$ `TERMINATED`), Resident Set Size (**RSS Working Set** memory), and I/O system calls.
3. **Concurrency & Synchronization**: Classic **Bounded-Buffer Producer-Consumer Pipeline** synchronized with counting Semaphores and a Mutex Lock.
4. **Crash Recovery & Journaling**: **Write-Ahead Logging (WAL)** checkpointing file inodes and transaction states (`COMMITTED`, `DIRTY`, `RECOVERED`) with automatic rollback.
5. **Access Control & Scheduling Defenses**: Separation of **Security Policy** from **OS Mechanisms** — enforcing dynamic CPU scheduling priority demotion, process preemption/suspension, and **Access Control Matrix** permission revocation via `os.chmod`.

---

## 🚀 Quickstart & How to Run the Project

### 1. Prerequisites & Virtual Environment
Ensure Python 3.8+ is installed. Clone or open the repository in your terminal:

```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Install dependencies (strictly standard library + psutil, watchdog, rich)
pip install -r requirements.txt
```

---

### 2. Complete Command Cheat Sheet

| Mode | Command Line | Description |
| :--- | :--- | :--- |
| **Option 1A (Live Attack Demo)** | `python main.py --demo attack` | **Recommended for Viva!** Single-command automated attack & defense demo. Paced at 1.2s per file. |
| **Option 1B (Benign Workload)** | `python main.py --demo normal` | Proves normal text writes run unhindered (0 alerts, threat score = 0). |
| **Option 2 (Manual Two-Terminal)** | *Terminal 1:* `python main.py`<br>*Terminal 2:* `python mock_encryptor.py --mode attack --delay 2.0` | Interactive mode: watch the monitor in Terminal 1 while triggering the attack in Terminal 2. |
| **Option 3A (Clean Environment)** | `python mock_encryptor.py --reset` | Restores `test_monitor_dir/` to 25 pristine plaintext files and clears locks. |
| **Option 3B (Module Self-Test)** | `python analyzer.py` | Direct terminal unit test validating all 6 syllabus modules. |

> [!TIP]
> **Terminal Font Size / Zoom:** If the dashboard feels large or crowded on your screen, hold **`Ctrl`** and scroll your **Mouse Wheel Down** (or press **`Ctrl` + `-`** in Windows Terminal) to zoom out and make the display sharp and compact.

---

### 3. Execution Methods in Detail

#### Method A: Single-Command Automated Live Demo (Recommended for Viva)
Run the automated demo in a single terminal. It automatically resets `test_monitor_dir/` with 25 clean plaintext files, launches the dashboard, and initiates the workload at a human-observable pace (1.2s per file):

```bash
# Automated Ransomware Attack & OS Defense Demo:
python main.py --demo attack

# Automated Benign Workload Demo (Proves normal apps run unhindered):
python main.py --demo normal
```

**What happens live on screen (Two-Stage Defense):**
1. **At T=0s**: Clean baseline. Top banner is **GREEN** (`SYSTEM SECURE`).
2. **At T=3.2s (Stage 1 Warning — Module 3)**: File 1 entropy spikes $\to$ Top banner turns **YELLOW**, and the scheduler demotes the process CPU priority to `IDLE` (nice 64/19).
3. **At T=4.4s (Stage 2 Hard Defense — Modules 2, 7 & 6)**: File 2 is touched $\to$ Top banner turns **RED**, process is preempted, write rights are revoked via `chmod`, process is terminated via `SIGKILL`, and both files are restored from the Write-Ahead Journal!

#### Method B: Two-Terminal Interactive Walkthrough
For a step-by-step presentation where you control the attack from a separate window:

*Note: You must start Terminal 1 first so the defender is active!*

```bash
# Terminal 1 — Start the OS Analyzer Dashboard:
python main.py

# Terminal 2 — Trigger the Workload Simulator:
python mock_encryptor.py --reset
python mock_encryptor.py --mode normal --delay 1.0
python mock_encryptor.py --mode attack --delay 2.0
```

---

## 🖥️ Terminal Dashboard: Layout Architecture

When running [`main.py`](file:///main.py), the terminal displays a live dynamic status banner and a 2x2 syllabus grid:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  OS-ANALYZER: REAL-TIME RESOURCE UTILIZATION & ENCRYPTION ANALYZER | CPU: 8.4% | RAM: 32.1%             │
│  🛑 STAGE 2: THREAT MITIGATED (MOD 2, 7, 6) | Process Terminated (SIGKILL) | 2 Files Restored from WAL   │
├──────────────────────────────────────────────────┬─────────────────────────────────────────────────────┤
│ [MODULE 2 & 5] PCB & Working Set Virtual Memory  │ [MODULE 4] Producer-Consumer IPC & Semaphores       │
│ • Target PID / PPID: 14208 / 8192                │ • Producer Thread (Watchdog): LISTENING             │
│ • Process Name: python.exe (mock_encryptor.py)   │ • Consumer Thread (OS Engine): ACTIVE               │
│ • Textbook State: TERMINATED (SIGKILL)           │ • Bounded Buffer Queue: 0/20 slots (Capacity N=20)  │
│ • Scheduling Priority: 64 (THROTTLED/IDLE)       │ • empty_slots (Semaphore): 20 vacant                │
│ • Working Set RSS: 28.45 MB                      │ • filled_slots (Semaphore): 0 queued                │
│ • Page Faults: 3,412                             │ • mutex (Critical Section Lock): UNLOCKED [OK]      │
│ • I/O Syscalls: Read: 120 | Write: 84            │ • IPC Events Synchronized: Prod: 42 | Cons: 42      │
├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────┤
│ [MODULE 6] File System Table & Journal (WAL)     │ [MODULE 7 & 3] Access Control Matrix & Mitigation   │
│ • database_01.csv | Inode: 844421 | 4.45 -> 8.00 │ • Domain Rights:                                    │
│   Rate: 42.1 KB/s  | Status: RECOVERED           │   User_Admin: RWX | OS_Monitor: RWA | Workload: RW  │
│ • database_02.csv | Inode: 844422 | 4.45 -> 8.00 │ • OS Chronological Action Log:                      │
│   Rate: 38.6 KB/s  | Status: RECOVERED           │   [MOD 3] Demoted PID 14208 CPU priority to IDLE    │
│                                                  │   [MOD 2] Preempted & SUSPENDED PID 14208 (STOPPED) │
│ Summary: Inodes: 25 | Committed: 23 | Recovered: 2 │   [MOD 7] Revoked WRITE rights; applied S_IREAD     │
│                                                  │   [MOD 2] Sent SIGKILL to PID 14208 (TERMINATED)    │
│                                                  │   [MOD 6] Journal Replay: Restored 2 files          │
└──────────────────────────────────────────────────┴─────────────────────────────────────────────────────┘
```

---

## 🧮 Mathematical Detection Logic (Shannon Entropy)

### Shannon Entropy Formula
Shannon Entropy measures the average uncertainty or information density per byte:

$$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

Where:
- $x_i$ represents each possible byte value from `0x00` (`0`) to `0xFF` (`255`).
- $P(x_i)$ is the empirical probability of byte $x_i$ appearing in the file: $P(x_i) = \frac{\text{Count}(x_i)}{\text{Total Bytes}}$.
- The value is strictly bounded: $0.0 \le H(X) \le 8.0$ bits/byte.

### Why Shannon Entropy Works for Ransomware Detection
| File Type | Typical Shannon Entropy $H(X)$ | Explanation |
| :--- | :--- | :--- |
| **Plaintext / Source Code** | $3.0 - 4.5$ bits/byte | Skewed distribution: mostly lowercase letters, vowels, spaces, and punctuation. |
| **Compiled Binaries / Media** | $5.5 - 6.8$ bits/byte | Moderate distribution: structured headers, opcodes, and compressed metadata. |
| **Encrypted Ciphertext** | $> 7.2 - 8.0$ bits/byte | **Uniform distribution**: Modern ciphers (AES-256, ChaCha20) output pseudorandom white noise where all 256 byte values appear with equal probability ($\approx 1/256$). |

---

## 🎓 Module-by-Module Viva Explanation Guide (BCSE303L)

Use this section to prepare for your viva and answer professor questions with precision.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      Syllabus Module Mapping at a Glance                        │
├──────────┬─────────────────────────────────┬────────────────────────────────────┤
│ Module   │ Silberschatz Concept             │ Implementing Class in analyzer.py  │
├──────────┼─────────────────────────────────┼────────────────────────────────────┤
│ Mod 2    │ OS Structures & System Calls    │ ProcessControlBlockInspector       │
│ Mod 3    │ CPU Scheduling & Preemption     │ SecurityPolicyAndMechanism         │
│ Mod 4    │ Threads & Synchronization (IPC) │ BoundedBufferEventQueue            │
│ Mod 5    │ Memory Management & Virtual Mem │ ProcessControlBlockInspector       │
│ Mod 6    │ Storage & File System (WAL)     │ WriteAheadJournalManager           │
│ Mod 7    │ Protection & Security Policy    │ AccessControlMatrix & SecurityPol. │
└──────────┴─────────────────────────────────┴────────────────────────────────────┘
```

---

### 📑 MODULE 2: Operating System Structures & System Calls
- **Syllabus Topic**: Process abstraction, Process Control Block (PCB), Process States, and POSIX/Win32 APIs.
- **Implementing Class**: [`ProcessControlBlockInspector`](file:///analyzer.py#L92)
- **Live Demo Action**: Watch Panel 1. As the encryptor starts, its textbook state shows `READY/RUNNING`. When defense triggers, it shifts to `WAITING/STOPPED` (via `proc.suspend()`), and finally to `TERMINATED` (via `proc.kill()`).

#### 💡 Viva Questions & 2-Sentence Model Answers:
> **Q1: What is a Process Control Block (PCB) and what does it contain?**  
> **Answer:** The PCB is the kernel data structure that stores the complete execution context of an active process. It tracks the Process ID (PID), program counter, CPU scheduling priority, memory working set pointers, and active I/O file descriptors.

> **Q2: Which operating system system calls are involved when terminating the rogue workload?**  
> **Answer:** On POSIX, the kernel delivers the `SIGSTOP` signal to suspend the task and `SIGKILL` (`kill(pid, 9)`) to immediately deallocate its PCB. On Windows, `psutil` issues the `NtSuspendProcess` and `TerminateProcess` Win32 kernel API calls.

---

### ⚡ MODULE 3: Process Management & CPU Scheduling
- **Syllabus Topic**: Preemptive CPU scheduling, process priorities, nice values, and throttling.
- **Implementing Class**: [`SecurityPolicyAndMechanism.enforce_os_mechanism()`](file:///analyzer.py#L742)
- **Live Demo Action**: When the workload first begins rapid I/O writes, the policy triggers `THROTTLE_PRIORITY`. The process's scheduling priority is demoted to `IDLE_PRIORITY_CLASS` (Windows) or `nice 19` (POSIX), starving it of CPU time slices.

#### 💡 Viva Questions & 2-Sentence Model Answers:
> **Q1: Why does the operating system demote the priority of an I/O-burst process?**  
> **Answer:** In multilevel queue and priority scheduling, deprioritizing an anomalous process via `nice` prevents CPU starvation of critical system tasks. It throttles the attacker's execution rate, buying time for the security monitor to evaluate whether to terminate it.

> **Q2: What is the difference between preemptive and non-preemptive scheduling here?**  
> **Answer:** Preemptive scheduling allows the OS kernel to forcefully interrupt a running process without its consent via timer interrupts or signals. We demonstrate this by calling `suspend()` to immediately pull the process off the CPU core into the `STOPPED` queue.

---

### 🔄 MODULE 4: Threads & Concurrency / Process Synchronization
- **Syllabus Topic**: Inter-Process Communication (IPC), Critical Sections, Producer-Consumer Bounded-Buffer, Semaphores, and Mutex Locks.
- **Implementing Class**: [`BoundedBufferEventQueue`](file:///analyzer.py#L293)
- **Live Demo Action**: Panel 2 displays the queue occupancy (`N/20 slots`), counting semaphores (`empty_slots` and `filled_slots`), and `mutex` state in real time as file events pass from the Watchdog listener to the analysis consumer.

#### 💡 Viva Questions & 2-Sentence Model Answers:
> **Q1: Why do we need both semaphores and a mutex lock in the bounded-buffer problem?**  
> **Answer:** Counting semaphores track resource availability (`empty_slots` prevents buffer overflow, while `filled_slots` prevents underflow on an empty queue). The binary `mutex` lock strictly guards the critical section so concurrent threads do not corrupt the shared queue pointers.

> **Q2: What would happen if we acquired the mutex before waiting on the empty_slots semaphore?**  
> **Answer:** That would cause a classic **deadlock**: the producer would lock the mutex and sleep waiting for an empty slot. Because it holds the mutex, the consumer could never enter the critical section to consume an item and free a slot.

---

### 🧠 MODULE 5: Memory Management & Virtual Memory
- **Syllabus Topic**: Working Set Model, Resident Set Size (RSS), Paging, and Page Faults.
- **Implementing Class**: [`ProcessControlBlockInspector.inspect_process()`](file:///analyzer.py#L125)
- **Live Demo Action**: Panel 1 displays the live Working Set RSS in Megabytes (`RSS MB`) and cumulative page faults as memory pages are paged in during cryptographic byte allocation.

#### 💡 Viva Questions & 2-Sentence Model Answers:
> **Q1: What is the Working Set Model and what is Resident Set Size (RSS)?**  
> **Answer:** The Working Set represents the collection of virtual memory pages actively referenced by a process during a recent time window $\Delta$. RSS is the exact amount of physical RAM allocated to that process, excluding pages swapped to disk.

> **Q2: Why do page faults occur during a file encryption attack?**  
> **Answer:** When the encryption workload reads massive files or allocates new ciphertext buffers in heap memory, it references virtual pages not yet mapped to physical frames. The Memory Management Unit (MMU) generates page fault interrupts to allocate and map physical memory frames on demand.

---

### 💾 MODULE 6: Storage & File System Management
- **Syllabus Topic**: Inodes, File System Journaling, Write-Ahead Logging (WAL), and Crash/Attack Recovery.
- **Implementing Class**: [`WriteAheadJournalManager`](file:///analyzer.py#L398)
- **Live Demo Action**: Panel 3 tracks inodes and transaction statuses. As files are encrypted, their status turns `DIRTY / UNCOMMITTED`. Once the attack is terminated, the engine triggers **Journal Recovery Replay**, rolling back corrupted files to their clean baseline snapshots (`RECOVERED`).

#### 💡 Viva Questions & 2-Sentence Model Answers:
> **Q1: What is Write-Ahead Logging (WAL) and how does it maintain file system integrity?**  
> **Answer:** WAL ensures that before any permanent modification is written to persistent disk blocks, an uncommitted log entry and metadata snapshot are recorded in a dedicated journal log. If a crash or malicious corruption occurs, the file system reads the journal to either replay committed transactions or roll back dirty, uncommitted changes.

> **Q2: What is an inode in an operating system file system?**  
> **Answer:** An inode (index node) is a kernel data structure that stores all metadata about a file—including file size, disk block pointers, ownership, and permission bits—independent of the file's directory name.

---

### 🛡️ MODULE 7: Protection, Security & Policy vs. Mechanism
- **Syllabus Topic**: Access Matrix model, Protection Domains, Principle of Least Privilege, and Separation of Policy from Mechanism.
- **Implementing Classes**: [`AccessControlMatrix`](file:///analyzer.py#L540) & [`SecurityPolicyAndMechanism`](file:///analyzer.py#L636)
- **Live Demo Action**: Panel 4 displays the live Access Matrix. When high entropy ($H > 7.2$) is detected, the policy decides `PREEMPT_AND_RECOVER`. The mechanism immediately updates `Workload_Process` to `READ_ONLY (WRITE REVOKED)` and invokes `os.chmod(stat.S_IREAD)` to lock the disk blocks against further writes.

#### 💡 Viva Questions & 2-Sentence Model Answers:
> **Q1: Explain the fundamental OS principle of separating "Policy" from "Mechanism".**  
> **Answer:** Policy defines *what decisions to make* based on heuristics (e.g., if Shannon Entropy $> 7.2$, flag as an attack), whereas Mechanism specifies *how the OS executes that decision* (e.g., invoking `proc.nice()`, `proc.kill()`, or `os.chmod()`). Separating them allows the system to update security thresholds without altering low-level kernel enforcement code.

> **Q2: How does the Access Matrix enforce the Principle of Least Privilege?**  
> **Answer:** The Access Matrix explicitly defines the minimal set of rights (Read, Write, Execute) that each Subject/Domain holds over each Object resource. When an anomaly occurs, the OS dynamically contracts the domain by stripping `WRITE` rights, ensuring the process cannot inflict further filesystem damage.

---

## 🏗️ Project Architecture & File Breakdown

```
os-analyzer/
├── analyzer.py          # Core Engine: Modules 2, 3, 4, 5, 6, 7 classes + OSAnalyzer orchestrator
├── main.py              # User Interface: 4-Panel Rich live terminal dashboard + --demo launcher
├── mock_encryptor.py    # Workload Simulator: Attack (H>7.9), Normal (H~4.3), and Reset utilities
├── requirements.txt     # Dependencies: psutil, watchdog, rich
├── test_monitor_dir/    # Monitored directory containing test files and .os_journal/
└── README.md            # Comprehensive project documentation & viva examination guide
```

---

## 🔒 Cross-Platform Safety

All process and filesystem interventions are safely wrapped with cross-platform checks:
- **Scheduling Priority**: Uses `psutil.IDLE_PRIORITY_CLASS` on Windows and `proc.nice(19)` on POSIX/Linux.
- **Process Suspension**: Invokes `proc.suspend()` across both platforms with `try/except (psutil.NoSuchProcess, psutil.AccessDenied)`.
- **Permission Locking**: Uses `os.chmod(path, stat.S_IREAD)` to apply read-only protection across NTFS and ext4 filesystems.

---

## 👥 Authors & Academic Context
- **Course**: Operating Systems (BCSE303L)
- **Textbook**: *Operating System Concepts* (10th Edition) — Abraham Silberschatz, Peter B. Galvin, Greg Gagne
- **Implementation**: Pure Python standard library + `psutil`, `watchdog`, and `rich`.
