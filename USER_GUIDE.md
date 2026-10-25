# 📘 OS-Analyzer: Complete User & Demonstration Guide
> **Course:** BCSE303L — Operating Systems Concepts  
> **Textbook Reference:** *Operating System Concepts* (10th Edition) — Silberschatz, Galvin, and Gagne  
> **Application:** Real-Time Operating System Telemetry, Process Control, and Behavioral Ransomware Neutralizer

---

## 🧭 Table of Contents
1. [What Is OS-Analyzer?](#-what-is-os-analyzer)
2. [Why We Built It: The Core Problem](#-why-we-built-it-the-core-problem)
3. [System Architecture at a Glance](#-system-architecture-at-a-glance)
4. [Prerequisites & Quick Setup](#-prerequisites--quick-setup)
5. [How to Run the Project](#-how-to-run-the-project)
   - [Method 1: Single-Command Automated Attack Demo (Best for Viva)](#method-1-single-command-automated-attack-demo-best-for-viva)
   - [Method 2: Automated Benign Workload Demo](#method-2-automated-benign-workload-demo)
   - [Method 3: Two-Terminal Manual Walkthrough](#method-3-two-terminal-manual-walkthrough)
   - [Method 4: Standalone Module Self-Test](#method-4-standalone-module-self-test)
   - [Method 5: Environment Reset Utility](#method-5-environment-reset-utility)
6. [Visual Dashboard Guide: Understanding the 4 Panels](#-visual-dashboard-guide-understanding-the-4-panels)
   - [Panel 1: [MODULE 2 & 5] Process Control Block (PCB) & Working Set](#panel-1-module-2--5-process-control-block-pcb--working-set)
   - [Panel 2: [MODULE 4] Producer-Consumer IPC & Semaphores](#panel-2-module-4-producer-consumer-ipc--semaphores)
   - [Panel 3: [MODULE 6] File System Table & Write-Ahead Journal (WAL)](#panel-3-module-6-file-system-table--write-ahead-journal-wal)
   - [Panel 4: [MODULE 7 & 3] Access Control Matrix & OS Mitigation Engine](#panel-4-module-7--3-access-control-matrix--os-mitigation-engine)
7. [The Complete Attack & Defense Lifecycle](#-the-complete-attack--defense-lifecycle)
8. [60-Second Viva Presentation Script](#-60-second-viva-presentation-script)
9. [Troubleshooting & Best Practices](#-troubleshooting--best-practices)

---

## 💡 What Is OS-Analyzer?

**OS-Analyzer** is an interactive, real-time operating system behavioral monitor and defense engine. Built with standard Python system libraries and Rich terminal interfaces, it tracks active workloads, analyzes filesystem modifications for cryptographic entropy, and automatically triggers operating system defense mechanisms—all strictly mapped to undergraduate Operating System syllabus concepts.

---

## 🎯 Why We Built It: The Core Problem

Traditional endpoint security solutions rely on **signature-based detection** (matching MD5/SHA256 hashes or known binary strings). This approach fails against modern ransomware attacks because:
1. Attackers can polymorphically recompile or pack payloads to yield completely new hashes.
2. Zero-day threats have no preexisting signatures in vendor databases.

### The Behavioral Approach
Rather than asking *"Who is this executable?"*, OS-Analyzer asks:  
> **"What is this process doing to the operating system's resources and disk blocks right now?"**

By correlating three real-time telemetry signals:
- **Data Randomness (Shannon Entropy):** Normal documents ($H \approx 4.3$ bits/byte) vs. Encrypted Ciphertext ($H > 7.9$ bits/byte).
- **Disk I/O Write Rate:** Bursts of rapid block overwrites ($> 100$ KB/s).
- **Process Memory & CPU Utilization:** Working set allocations and scheduling demand.

OS-Analyzer detects encryption behavior on the fly, demotes process scheduling priority, suspends execution, revokes filesystem write access, terminates the rogue PID, and rolls back all modified files using a **Write-Ahead Journal**.

---

## 🏛️ System Architecture at a Glance

The codebase follows a strict **1 Class = 1 Syllabus Module Architecture**:

```
                                  OS-ANALYZER ARCHITECTURE
                                  
                   ┌──────────────────────────────────────────────────┐
                   │    Monitored Directory: test_monitor_dir/        │
                   │    (25 Baseline Files: Docs, CSVs, Logs)         │
                   └─────────────────────────┬────────────────────────┘
                                             │ File Events
                                             ▼
            ┌────────────────────────────────────────────────────────────────┐
            │   [MODULE 4] BOUNDED-BUFFER PRODUCER-CONSUMER QUEUE            │
            │   • Producer : Watchdog Filesystem Listener Thread             │
            │   • Consumer : OSAnalyzer Telemetry Worker Thread              │
            │   • Mutex    : threading.Lock() (Mutual Exclusion)             │
            │   • Semaphores: empty_slots (20) & filled_slots (0)            │
            └────────────────────────────────┬───────────────────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────┐
│ [MODULE 2 & 5] PROCESS CONTROL BLOCK         │ │ [MODULE 7 & 3] SECURITY POLICY & SCHEDULING  │
│ ProcessControlBlockInspector                 │ │ SecurityPolicyAndMechanism                   │
│ • Inspects active workload PID via psutil    │ │ • Policy : Threat Score (0 - 100) based on   │
│ • Maps textbook states (RUNNING/STOPPED/TERM)│ │            Shannon Entropy, I/O rate, CPU%   │
│ • Tracks Resident Set Size (RSS Working Set) │ │ • Decision: NORMAL | THROTTLE | PREEMPT      │
│ • Records page faults and I/O syscall counts │ │ • Mechanism: psutil.nice() priority demote   │
└──────────────────────────────────────────────┘ └──────────────────────┬───────────────────────┘
                                                                        │
                                   ┌────────────────────────────────────┘
                                   ▼
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────┐
│ [MODULE 7 PART A] SYSTEM PROTECTION          │ │ [MODULE 6] STORAGE & JOURNAL CRASH RECOVERY  │
│ AccessControlMatrix                          │ │ WriteAheadJournalManager                     │
│ • Subjects: User_Admin, Monitor, Workload    │ │ • Checkpoints baseline files to .os_journal/ │
│ • Objects : test_monitor_dir/*, .os_journal/*│ │ • Inode tracking: COMMITTED vs DIRTY         │
│ • Revoke  : Transitions to READ_ONLY         │ │ • Journal Recovery Replay rolls back         │
│             Applies OS-level chmod lock      │ │   corrupted inodes to pristine plaintext     │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────┘
```

---

## ⚙️ Prerequisites & Quick Setup

### 1. Requirements
- **Python 3.8+** installed on your system.
- OS: Windows 10/11, Ubuntu/Linux, or macOS.

### 2. Virtual Environment Setup
Open your terminal inside the project directory:

```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Windows (Command Prompt)
python -m venv venv
.\venv\Scripts\activate.bat

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies used: `psutil>=5.9.0`, `watchdog>=3.0.0`, `rich>=13.0.0`)*

---

## 🚀 How to Run the Project

We provide multiple execution modes tailored for live demonstrations and testing:

### Method 1: Single-Command Automated Attack Demo (Best for Viva)

This is the recommended command for your viva evaluation. It resets all 25 test files to clean plaintext, launches the 4-panel dashboard with the dynamic Status Banner on the terminal's alternate screen buffer, and automatically fires the mock encryptor in the background after 2 seconds:

```bash
python main.py --demo attack
```

**What you will see live on screen (Graduated Two-Stage Defense):**
1. **At $T = 0s$ (Clean Baseline):** Dashboard opens. Top banner is **GREEN** (`🟢 SYSTEM SECURE (NORMAL)`). All 25 inodes show status `COMMITTED`, Working Set RSS is idle, and the Access Control Matrix shows standard `READ | WRITE` rights.
2. **At $T = 2.0s$:** The background attack workload begins (`mock_encryptor.py`).
   - Workload PID registers in **Panel 1** (State: `READY/RUNNING`).
   - Events enter **Panel 2** (Bounded Buffer occupancy increments, semaphore counters tick).
3. **At $T = 3.2s$ (Stage 1 Warning — Module 3):** File 1 (`database_01.csv`) is encrypted:
   - Shannon Entropy jumps from $4.45 \to 8.00$ bits/byte (marked `DIRTY`).
   - Top banner turns **YELLOW** (`⚠️ STAGE 1: SUSPICION (MODULE 3)`).
   - **Module 3 Scheduler:** Offending PID is demoted to `IDLE_PRIORITY_CLASS` (nice 64/19).
4. **At $T = 4.4s$ (Stage 2 Hard Defense — Modules 2, 7 & 6):** File 2 is touched (repeated violation):
   - Policy flags confirmed attack and executes the full mitigation pipeline:
     - **Module 2:** Process is preempted and suspended (`STOPPED`).
     - **Module 7:** Access Matrix revokes write access (`READ_ONLY`), applying OS `chmod` locks.
     - **Module 2:** Kernel delivers `SIGKILL`, terminating the rogue process (`TERMINATED`).
     - **Module 6:** Write-Ahead Journal Replay restores all corrupted files from `.os_journal/` baseline (`RECOVERED`).
   - Top banner turns **RED** (`🛑 STAGE 2: THREAT MITIGATED (MOD 2, 7, 6)`).
5. **Final State:** Attacker PID remains pinned in Panel 1 as `TERMINATED`, both compromised files are restored to clean plaintext, and the journal summary displays: `Committed: 23 | Dirty: 0 | Recovered: 2`.

Press `Ctrl + C` at any time to exit the dashboard.

---

### Method 2: Automated Benign Workload Demo

Demonstrates that normal user programs (low-entropy log appends, $H \approx 4.4$ bits/byte) run to completion without triggering false-positive alerts:

```bash
python main.py --demo normal
```

**Observation:** All 25 files are processed normally, top banner stays **GREEN**, threat score remains `0`, and no OS defenses are triggered.

---

### Method 3: Two-Terminal Manual Walkthrough

If you want to manually trigger the attack or adjust pacing while keeping the dashboard open in a separate window:

> [!IMPORTANT]
> **Order of Execution:** You must keep **Terminal 1** (`main.py`) running *before* executing commands in **Terminal 2**. If you run `mock_encryptor.py` by itself without the analyzer running, there is no defender active to intercept the attack!

#### Terminal 1 — Start the Monitor
```bash
python main.py
```

#### Terminal 2 — Control the Workload
```bash
# 1. Reset files to clean baseline
python mock_encryptor.py --reset

# 2. Run normal benign writes
python mock_encryptor.py --mode normal --delay 1.0

# 3. Run encryption attack with custom pacing (e.g. 2.0s per file)
python mock_encryptor.py --mode attack --delay 2.0
```

---

### Method 4: Standalone Module Self-Test

Directly executes the built-in unit tests verifying all 6 syllabus modules without rendering the graphical TUI:

```bash
python analyzer.py
```

**Expected Result:**
```text
[1] SHANNON ENTROPY TEST:           Plaintext: 4.4908 | Ciphertext: 7.8283 [PASS]
[2] MODULE 4 BOUNDED-BUFFER TEST:   Produced: True | Empty Sem: 4 | Full Sem: 1 [PASS]
[3] MODULE 2 & 5 PCB TEST:          State: READY/RUNNING | RSS: 24.3 MB [PASS]
[4] MODULE 6 & 7 JOURNAL & ACM:     Checkpointed: 26 | Rights: READ_ONLY | Restored: 1 [PASS]
[5] MODULE 7 & 3 POLICY & SCHED:    Normal: NORMAL (Score: 0) | Attack: PREEMPT (Score: 100) [PASS]
[SUCCESS] ALL SYLLABUS ENGINE MODULE TESTS PASSED!
```

---

### Method 5: Environment Reset Utility

If you ever want to reset `test_monitor_dir/` to clean plaintext files and remove all temporary lock artifacts:

```bash
python mock_encryptor.py --reset
```

---

## 🖥️ Visual Dashboard Guide: Understanding the 4 Panels

The dashboard is organized into a clean 2x2 grid where each quadrant maps to specific Silberschatz course chapters:

```
┌──────────────────────────────────────────────┬──────────────────────────────────────────────┐
│ [MODULE 2 & 5] PCB & Working Set Memory      │ [MODULE 4] Producer-Consumer IPC & Semaphores│
├──────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ [MODULE 6] File System Table & WAL Journal   │ [MODULE 7 & 3] Access Control & Mitigation   │
└──────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

---

### Panel 1: [MODULE 2 & 5] Process Control Block (PCB) & Working Set

| Field | Syllabus Meaning | What to Point Out During Viva |
| :--- | :--- | :--- |
| **Target PID / PPID** | Process ID & Parent Process ID | Identified via `.active_pid.json` or open file descriptor scanning. |
| **Process Name** | Executable Image Name | Displays `python.exe (mock_encryptor.py)`. |
| **Textbook State** | Silberschatz Process State Model | Starts as `READY/RUNNING` (green), transitions to `WAITING/STOPPED` (yellow) on suspension, and permanently pins to `TERMINATED (SIGKILL)` (red) after mitigation. |
| **CPU Scheduling Nice** | Scheduling Priority Value | Demotes from `32 (NORMAL)` to `64 (THROTTLED/IDLE)` on Windows, or `19` on Linux. |
| **Process CPU Load** | Instantaneous Core Utilization | Percentage of CPU cycles consumed by the workload. |
| **Working Set RSS (MB)** | Resident Set Size (Physical Memory) | Measures physical RAM frames allocated to the process working set. |
| **Page Faults** | MMU Page Fault Interrupts | Counts page fault exceptions as buffers are mapped into RAM. |
| **I/O Syscalls** | Read & Write System Calls | Cumulative count and byte volume of file read/write operations. |
| **Open Descriptors** | Kernel File Handle Table | Number of active file descriptors held open by the workload. |

---

### Panel 2: [MODULE 4] Producer-Consumer IPC & Semaphores

| Field | Synchronization Primitive | Explanation |
| :--- | :--- | :--- |
| **Producer Thread** | `Watchdog Listener` | Asynchronously captures filesystem change notifications. |
| **Consumer Thread** | `OSAnalyzer Engine` | Dequeues events, computes entropy, and evaluates policy. |
| **Bounded Buffer Queue** | Fixed Capacity ($N=20$) | Displays live occupancy (e.g., `2/20 slots`). |
| **empty_slots** | `threading.Semaphore(20)` | Counting semaphore tracking vacant buffer slots. Blocks producer if full. |
| **filled_slots** | `threading.Semaphore(0)` | Counting semaphore tracking occupied items. Blocks consumer if empty. |
| **mutex** | `threading.Lock()` | Binary mutual exclusion lock strictly protecting the critical section. |
| **IPC Events Processed** | Total Operations Counter | Confirms that produced events match consumed events with zero dropped items. |

---

### Panel 3: [MODULE 6] File System Table & Write-Ahead Journal (WAL)

| Field | File System Concept | Explanation |
| :--- | :--- | :--- |
| **File Name** | Directory Entry | Name of the file being monitored inside `test_monitor_dir/`. |
| **Inode** | Index Node Number | Unique filesystem inode / file ID retrieved via `os.stat().st_ino`. |
| **Shannon Entropy ($H$)** | Information Density Metric | Displays baseline entropy vs. current entropy (e.g., `4.45 -> 7.95 [HIGH]`). |
| **Write Rate** | Storage Throughput | Calculated as $\frac{\Delta \text{Bytes}}{\Delta \text{Time}}$ in KB/s. |
| **Journal Tx Status** | Transaction Lifecycle State | • `COMMITTED` (Green): Pristine baseline file.<br>• `DIRTY / UNCOMMITTED` (Red): In-flight encrypted file.<br>• `RECOVERED` (Cyan): Corrupted file successfully rolled back. |
| **Summary Bar** | Overall Inode Health | Displays total tracked inodes, committed files, dirty files, and recovered files. |

---

### Panel 4: [MODULE 7 & 3] Access Control Matrix & OS Mitigation Engine

Contains two coordinated sub-views:

#### 1. The Access Control Matrix Table
| Subject / Domain | `test_monitor_dir/*` | `.os_journal/*` |
| :--- | :--- | :--- |
| **`User_Admin`** | `READ \| WRITE \| EXECUTE` | `READ \| WRITE \| ADMIN` |
| **`OS_Analyzer_Monitor`** | `READ \| WRITE \| AUDIT` | `READ \| WRITE \| ADMIN` |
| **`Workload_Process`** | `READ \| WRITE` $\to$ **`READ_ONLY (WRITE REVOKED)`** | `NO_ACCESS` |

When an attack occurs, the OS dynamically contracts the `Workload_Process` domain to `READ_ONLY` and enforces an `os.chmod(S_IREAD)` lock on the physical files.

#### 2. The Chronological OS Mitigation Action Log
Records kernel interventions with timestamps:
1. `[MODULE 3 SCHEDULER]` Demoted PID CPU priority to IDLE class.
2. `[MODULE 2 PROCESS]` Preempted & SUSPENDED PID (State $\to$ `STOPPED`).
3. `[MODULE 7 PROTECTION]` Revoked WRITE rights; applied `S_IREAD` chmod lock.
4. `[MODULE 2 PROCESS]` Sent `SIGKILL` to PID (State $\to$ `TERMINATED`).
5. `[MODULE 6 FILE SYSTEM]` Replayed Journal: Restored $N$ files from baseline.

---

## 🔄 The Complete Attack & Defense Lifecycle

```
[1. Baseline Checkpoint]
     │ .os_journal/ initialized; Inodes & clean baselines COMMITTED.
     ▼
[2. Workload Ingestion]
     │ Watchdog captures file modification -> enqueued in Bounded Buffer.
     ▼
[3. Mathematical Entropy Analysis]
     │ H(X) calculated: Low (4.45) for text, Critical (>7.9) for cipher.
     ▼
[4. Security Policy Evaluation]
     │ Score calculated from H(X), ΔH, Write Rate, and CPU load.
     ▼
[5. OS Mechanism Enforcement]
     ├─► Priority Demotion    : Nice value demoted to IDLE (Module 3)
     ├─► Preemptive Suspension: Process suspended to STOPPED state (Module 2)
     ├─► Access Matrix Lock   : WRITE revoked; chmod S_IREAD applied (Module 7)
     ├─► Process Termination  : SIGKILL delivered; State -> TERMINATED (Module 2)
     └─► Journal Recovery     : Corrupted files rolled back from WAL (Module 6)
```

---

## 🎙️ 60-Second Viva Presentation Script

When demonstrating the project to an examiner, use this concise script:

> *"Good morning, Professor. Our project is the **Real-Time OS Resource Utilization and File-Encryption Behavior Analyzer**, built strictly around the **BCSE303L syllabus**.*
>
> *Traditional antiviruses fail against zero-day ransomware because attackers easily change file signatures. Instead, our project takes an **OS behavioral detection approach** using **Shannon Entropy**, **I/O write bursts**, and **working set memory telemetry**.*
>
> *Our architecture maps **one class to each exact course module**:*
> - *In **Panel 1**, you can see the **Process Control Block** (Module 2 & 5) tracking PID state transitions, Working Set memory, and I/O system calls.*
> - *In **Panel 2**, we implement the textbook **Bounded-Buffer Producer-Consumer Problem** (Module 4) using counting semaphores and a binary mutex lock.*
> - *In **Panel 3**, we implement **Write-Ahead Logging & Journaling** (Module 6) tracking inodes from `COMMITTED` to `DIRTY` to `RECOVERED`.*
> - *In **Panel 4**, we separate **Security Policy from OS Mechanism** (Module 7 & 3). When the threat score hits 100, the OS demotes the process scheduling priority, preemptively suspends it, revokes write permissions in the Access Matrix via `chmod`, delivers a `SIGKILL`, and triggers a journal recovery rollback to restore all encrypted files to pristine plaintext.*
>
> *I will now launch the automated demo with `python main.py --demo attack` to show you the entire lifecycle live."*

---

## 🔧 Troubleshooting & Best Practices

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Attacker encrypted all 25 files without stopping** | You ran `mock_encryptor.py` by itself without `main.py` running in another terminal. | The encryptor is only the attacker. To see defenses trigger, either use `python main.py --demo attack` (all-in-one) or start `python main.py` in Terminal 1 first before running the attack in Terminal 2. |
| **Dashboard text feels too large or cluttered** | Default terminal font size is large for multi-panel TUI. | Hold **`Ctrl`** and scroll your **Mouse Wheel Down** (or press **`Ctrl` + `-`**) inside the terminal window to zoom out and make the text smaller and crisp. |
| **Terminal screen feels cramped** | Terminal window size is too small for a 2x2 grid. | Maximize your terminal window or set dimensions to at least **110 columns $\times$ 32 rows**. |
| **`psutil.AccessDenied` warning** | Inspecting system-level protected PIDs without admin rights. | Normal behavior on Windows/Linux; OS-Analyzer safely handles this with `try/except` and focuses on the active user workload. |
| **Files remain in encrypted state** | Process was killed prematurely before recovery finished. | Run `python mock_encryptor.py --reset` to instantly restore 25 clean baseline files. |
| **Character encoding errors on Windows** | Legacy Command Prompt running non-UTF-8 code pages. | Both scripts automatically call `sys.stdout.reconfigure(encoding='utf-8')`. For best results, use **Windows Terminal (PowerShell)**. |
| **Git shows untracked baseline files** | New files generated inside `test_monitor_dir/`. | [`.gitignore`](file:///d:/Code%20Playground/OS-Project/.gitignore) is configured to ignore `.active_pid.json`, `.os_journal/`, and bytecode caches automatically. |

---

## 📚 Course Reference & Academic Integrity
- **Institution:** VIT University (or Affiliated Course Center)
- **Course Code:** BCSE303L — Operating Systems
- **Prescribed Reference:** Abraham Silberschatz, Peter Baer Galvin, Greg Gagne, *Operating System Concepts*, 10th Edition, John Wiley & Sons.
- **Components Developed:** 100% Python standard library + `psutil`, `watchdog`, and `rich`. Strict prohibition of out-of-scope math (no Chi-Square, no hidden canaries, no magic-byte bloat).
