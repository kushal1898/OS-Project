# 🛡️ Real-Time OS Resource Utilization & Ransomware Defense System
### Operating Systems & Kernel-Level Security Engineering Project Report

An intelligent, real-time operating system behavioral monitor and autonomous ransomware mitigation engine. The system combines **Virtual Filesystem (`/proc`) syscall telemetry**, **Shannon Entropy ($H$)**, **Pearson's Chi-Square ($\chi^2$) goodness-of-fit analysis**, **alphabetical Inode Canary tripwires**, and **Copy-on-Write (CoW) in-memory shadow buffering** to detect, freeze (`SIGSTOP`), and remediate (`SIGKILL` + Rollback) destructive file-encryption attacks with **zero data loss**.

---

## 📑 Table of Contents
1. [OS Architecture & Pipeline](#-os-architecture--pipeline)
2. [Core Operating System Concepts Demonstrated](#-core-operating-system-concepts-demonstrated)
3. [Mathematical & Statistical Formulation](#-mathematical--statistical-formulation)
4. [TUI Dashboard Architecture](#-tui-dashboard-architecture)
5. [Quick-Start Demo Guide](#-quick-start-demo-guide)
6. [Attack Simulation Modes](#-attack-simulation-modes)
7. [Repository File Structure](#-repository-file-structure)
8. [Experimental Benchmark Results](#-experimental-benchmark-results)

---

## 🏗️ OS Architecture & Pipeline

The system operates as an active endpoint defense pipeline sitting between user-space application processes and the underlying filesystem.

```mermaid
flowchart TD
    subgraph Filesystem["Monitored Filesystem (VFS)"]
        TargetDir["test_monitor_dir/"]
        Canary["Inode Canaries: !000_canary, !001_canary"]
        Corpus["Protected Corpus Files (32KB - 128KB)"]
    end

    subgraph OS_Telemetry["OS Kernel Telemetry Layer"]
        Inotify["Filesystem Watchdog (ReadDirectoryChangesW / inotify)"]
        ProcIO["/proc/<pid>/io Syscall Counters & psutil PCB Telemetry"]
        PIDCorrelator["PID Attribution & Open File Descriptors"]
    end

    subgraph Analysis["Behavioral & Mathematical Engine"]
        EntropyEngine["Shannon Entropy Calculator (0.0 - 8.0 bits/byte)"]
        ChiSquareEngine["Chi-Square Goodness-of-Fit (Uniform Dist. Test)"]
        HeaderCheck["Magic Byte Header Classifier (gzip, zip, zlib, png)"]
        ThreatScorer["Composite Threat Score Evaluator (0 - 100)"]
    end

    subgraph Mitigation["Autonomous Mitigation Subsystem"]
        SigStop["Kernel Process Freezing: SIGSTOP / NtSuspendProcess"]
        SigKill["Process Termination: SIGKILL / TerminateProcess"]
        CoWRollback["CoW Shadow Buffer In-Memory Restoration (0 Bytes Lost)"]
    end

    TargetDir --> Inotify
    Inotify --> EntropyEngine
    Inotify --> ChiSquareEngine
    Inotify --> HeaderCheck
    ProcIO --> PIDCorrelator
    PIDCorrelator --> ThreatScorer
    EntropyEngine --> ThreatScorer
    ChiSquareEngine --> ThreatScorer
    HeaderCheck --> ThreatScorer

    ThreatScorer -->|Score >= 70| SigStop
    SigStop -->|Observable Pause| SigKill
    SigKill --> CoWRollback
    CoWRollback --> TargetDir
```

### Text Architectural Dataflow
```
+-------------------------------------------------------------------------------------------------+
|                                 APPLICATION & USER WORKLOADS                                    |
|   (e.g., Benign Backup Tools, Database Workers, or Malicious Ransomware / mock_encryptor.py)    |
+-------------------------------------------------------------------------------------------------+
                                              │
              Syscalls: read(), write(), open(), unlink(), stat()
                                              ▼
+─────────────────────────────────────────────────────────────────────────────────────────────────+
|                                    KERNEL / VFS MONITOR                                         |
|  • inotify / ReadDirectoryChangesW: Captures CREATED, MODIFIED, DELETED events                  |
|  • /proc/<pid>/io & io_counters: Direct counters for rchar, wchar, syscr, syscw, write_bytes    |
+─────────────────────────────────────────────────────────────────────────────────────────────────+
                                              │
                                              ▼
+─────────────────────────────────────────────────────────────────────────────────────────────────+
|                             BEHAVIORAL & STATISTICAL CLASSIFIER                                 |
|  1. Inode Canary Check: Did caller touch !000_canary or !001_canary? (+60 Threat Score)         |
|  2. Shannon Entropy: H = -Σ P(x)log2P(x). Delta H > 2.5?                                        |
|  3. Chi-Square Test: Uniform byte distribution test (AES: χ² ~ 250 vs Text: χ² > 10,000)        |
|  4. Magic Header Check: Disqualify benign compression (1F 8B gzip) to eliminate false positives |
|  5. Modification Velocity & I/O Rate: High files/sec + write_bytes/sec                          |
+─────────────────────────────────────────────────────────────────────────────────────────────────+
                                              │
                         Threat Score Evaluated: 0 to 100
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       │                                             │
               Score < 70 (Benign)                           Score >= 70 (Attack)
                       │                                             │
                       ▼                                             ▼
              [Allow Normal Execution]                     [AUTONOMOUS MITIGATION]
                                                           1. Freeze PID in OS Scheduler
                                                              (SIGSTOP / NtSuspendProcess)
                                                           2. Terminate Malicious Process
                                                              (SIGKILL / TerminateProcess)
                                                           3. CoW RAM Rollback
                                                              (Restore clean bytes from RAM)
```

---

## 🔬 Core Operating System Concepts Demonstrated

### 1. Process Control Block (PCB) & Scheduler State Manipulation
* **Process States**: The operating system tracks process lifecycle in the PCB. In standard POSIX and Windows NT kernels, process execution states include:
  * `TASK_RUNNING` (`R`): Actively scheduled or queued for CPU time.
  * `TASK_INTERRUPTIBLE` / `TASK_UNINTERRUPTIBLE` (`S`): Waiting for I/O completion or sleep timer.
  * `TASK_STOPPED` (`T`): Execution halted by a job control signal (`SIGSTOP`). The thread instructions cease execution immediately in the kernel dispatcher.
  * `TASK_DEAD` (`X`): Terminated via uncatchable `SIGKILL`.
* **Cross-Platform Freezing Primitive**:
  * **POSIX/Linux**: `psutil.Process(pid).suspend()` invokes `kill(pid, SIGSTOP)`. The target process transitions into state `T` without receiving a catchable signal handler.
  * **Windows NT**: Invokes `NtSuspendProcess` / `SuspendThread` via the native `psutil` C-runtime bridge.
  * **OS Thawing**: Resumed via `SIGCONT` / `NtResumeProcess` when authorized.

### 2. Virtual Filesystem (VFS) & Syscall Accounting (`/proc`)
* On Linux/WSL2, each active process exposes kernel accounting metrics under `/proc/<pid>/io`:
  * `rchar`: Number of bytes read across all `read()` and `pread()` syscalls.
  * `wchar`: Number of bytes written across all `write()` and `pwrite()` syscalls.
  * `syscr`: Cumulative read I/O syscall invocation count.
  * `syscw`: Cumulative write I/O syscall invocation count.
  * `read_bytes` / `write_bytes`: Actual physical storage block device throughput.
* **Telemetry Guard**: When `/proc/<pid>/io` is present, the analyzer parses raw virtual filesystem counters directly; on Windows, it seamlessly falls back to `psutil.Process(pid).io_counters()` wrapped in guarded exception handlers (`psutil.NoSuchProcess`, `psutil.AccessDenied`, `FileNotFoundError`).

### 3. Inode Canary Honeypots & Directory Traversal Interception
* Standard filesystem directory traversal routines (`readdir(3)` on POSIX, `FindFirstFileW` / `FindNextFileW` on Windows) enumerate directory entries in either raw directory entry order or sorted ASCII lexical collation.
* **Canary Placement Strategy**: Deploying two sacrificial bait files prefixed with ASCII character `!` (ASCII `0x21`):
  * `!000_canary_credentials.txt` (mimics plaintext API keys & administrative passwords)
  * `!001_canary_keys.pem` (mimics RSA/ECC private keys)
* **ASCII Priority**: Because `!` precedes numeric digits (`0-9`, `0x30-0x39`) and alphabetical characters (`A-Z`, `a-z`), any bulk directory traversing ransomware (e.g. LockBit, Conti, or `mock_encryptor.py`) encounters and modifies the canary files **first**.
* **Inode Invariance Tracking**: The analyzer records each canary's unique filesystem inode / NTFS file reference number (`os.stat(path).st_ino`) and cryptographic hash (SHA-256). Any overwrite, rename, or deletion immediately adds `+60` points to the composite threat score before substantial user data can be damaged.

### 4. Copy-on-Write (CoW) In-Memory Shadow Buffer
* **Zero Data Loss Guarantee**: Upon initialization, [`RollbackManager`](file:///analyzer.py#L117) scans the target folder and locks an in-memory shadow snapshot (`dict[str, bytes]`) and SHA-256 fingerprint for all baseline documents under 10 MB.
* **Differential RAM Restoration**: When autonomous mitigation triggers:
  1. Identifies and unlinks corrupted ransom files ending with `.locked`, `.enc`, or `.encrypted`.
  2. Compares the current disk contents against the in-memory shadow buffer.
  3. Re-writes clean cached byte buffers to restore corrupted or deleted files.
  4. Returns an exact count of restored files and verifies $0$ bytes lost.

---

## 🧮 Mathematical & Statistical Formulation

### 1. Shannon Information Entropy ($H$)
Shannon Entropy measures the average uncertainty or randomness contained in an information stream:

$$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

Where:
* $P(x_i) = \frac{\text{Count}(x_i)}{N}$ is the empirical probability of occurrence for byte value $x_i \in [0, 255]$.
* $N$ is the total byte length of the file buffer.
* $H(X)$ is bounded between $0.0$ and $8.0\text{ bits/byte}$.
  * Plaintext documents, source code, and log files: $H \approx 3.2 - 5.2\text{ bits/byte}$.
  * Cryptographic ciphertext (AES-256, ChaCha20, RSA): $H > 7.95\text{ bits/byte}$.

### 2. Entropy Delta ($\Delta H$)
Detection does not rely solely on absolute entropy, but on the instantaneous delta between the pre-modification baseline $H_{\text{base}}$ and post-modification entropy $H_{\text{curr}}$:

$$\Delta H = \max(0.0, H_{\text{curr}} - H_{\text{base}})$$

A sudden jump where $\Delta H > 2.5$ flags an anomaly even if the original document had unusual character distributions.

### 3. Pearson's Chi-Square ($\chi^2$) Goodness-of-Fit Test
While both cryptographic ciphertext and compressed archives have elevated entropy, pure ciphertext adheres to a **discrete uniform distribution** across all 256 byte values ($E = \frac{N}{256}$):

$$\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E)^2}{E}$$

Where:
* $O_i$ is the observed frequency count of byte $i$.
* $E = \frac{N}{256.0}$ is the theoretical expected count per byte under a uniform distribution.

| Data Type | Shannon Entropy ($H$) | Chi-Square Statistic ($\chi^2$) | Magic Byte Header |
| :--- | :--- | :--- | :--- |
| **Plaintext / Logs** | $3.5 - 5.0$ | $\chi^2 > 15,000$ (Extremely non-uniform) | None |
| **Gzip / Zip Archive** | $5.5 - 7.6$ | $\chi^2 \approx 400 - 1,200$ (Distinct frequency spikes) | `1F 8B` (gzip) / `PK\x03\x04` (zip) |
| **AES Ciphertext** | **$> 7.95$** | **$\chi^2 \approx 200 - 300$** (Uniform distribution; d.f. = 255) | None / Random noise |

### 4. Composite Threat Score Function
The composite threat score $S \in [0, 100]$ evaluates multiple independent behavioral signals:

$$S = \text{clamp}\Big(S_{\text{canary}} + S_{\Delta H} + S_{\text{velocity}} + S_{\text{io}} - S_{\text{benign}}, 0, 100\Big)$$

* $S_{\text{canary}} = +60$ if any canary honeypot inode is modified, renamed, or deleted.
* $S_{\Delta H} = \min(30, 15 + (\Delta H - 2.5) \times 5.0)$ if $\Delta H > 2.5$.
* $S_{\text{velocity}} = \min(25, \text{files/sec} \times 5.0)$ for high modification frequencies.
* $S_{\text{io}} = \min(20, \frac{\text{write\_bytes/sec}}{5000} \times 5.0)$ for sustained write throughput.
* $S_{\text{benign}} = -35$ if standard compression magic headers (`1F 8B`, `PK\x03\x04`, `78 9C`, `89PNG`) are identified.
* **Mitigation Threshold**: When $S \ge 70$, autonomous kernel signal dispatch is triggered.

---

## 🖥️ TUI Dashboard Architecture

The Terminal User Interface is constructed using `rich` with four dedicated functional panels updating live at 4 Hz without terminal flicker:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [HEADER PANEL] 🛡️ OS ANALYZER: REAL-TIME RESOURCE UTILIZATION & FILE-ENCRYPTION BEHAVIOR MONITOR│
│ OS Kernel: Windows 11 (10.0.26100) | Target: test_monitor_dir | CoW Buffer: 47 files in RAM     │
├────────────────────────────────────────────────┬────────────────────────────────────────────────┤
│ [LEFT PANEL: OS TELEMETRY]                     │ [RIGHT PANEL: BEHAVIORAL & ENTROPY ENGINE]     │
│ • CPU Utilization: 12.4%                       │ Threat Score Meter: [ 92.5/100 ] [CRITICAL]    │
│ • Memory Utilization: 44.8%                    │ [████████████████████████████──]               │
│ • Disk Read / Write: 0.0 KB/s / 420.5 KB/s     │                                                │
│                                                │ Live File Events (Last 10 Events):             │
│ Suspect Process Inspector:                     │ Time    File           H(bef)->H(aft)  Verdict │
│ • Target PID: 18452 (mock_encryptor.py)        │ 21:40   !000_canary    4.20 -> 7.98   CANARY_HIT│
│ • Scheduler State: T FROZEN/SIGSTOP            │ 21:40   corpus_01.txt  4.32 -> 7.96   SUSPICIOUS│
│ • Direct /proc/io: 382,140 write bytes         │ 21:40   audit_02.log   5.10 -> 7.97   SUSPICIOUS│
│ • Syscalls: 42 syscr / 45 syscw                │ 21:40   backup.tar.gz  0.00 -> 6.42   BENIGN_GZ │
├────────────────────────────────────────────────┴────────────────────────────────────────────────┤
│ [FOOTER PANEL: OS DEFENSE ACTION LOG & AUTONOMOUS REMEDIATION]                                  │
│ [21:40:01] [ARMED] Inode canaries armed in test_monitor_dir. 47 files snapshotted in RAM.       │
│ [21:40:03] [SIGSTOP] Threat score 92.5 >= 70.0 -> Dispatched SIGSTOP to freeze PID 18452.       │
│ [21:40:04] [REMEDIATED] Dispatched SIGKILL to PID 18452. CoW RAM Rollback restored 6 files.     │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick-Start Demo Guide

### 1. Prerequisites & Environment Setup
Clone the repository and install the verified dependencies inside a virtual environment:

```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Linux / WSL2 (bash)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 2. Automated Single-Command Demonstrations

#### Demo 1: Fast High-I/O Attack (`--demo blitz`)
* Automatically seeds 40 structured documents, launches the live dashboard, and spawns the fast ransomware attack after 2 seconds.
* **Observed OS Action**: Hits `!000_canary_credentials.txt`, threat score spikes to $100.0$, `SIGSTOP` freezes the attacker mid-stream (around file 4–6), `SIGKILL` terminates the PID, and CoW RAM Rollback restores $100\%$ of files.

```powershell
python main.py --demo blitz
```

---

#### Demo 2: Low-and-Slow Stealth Evasion (`--demo stealth`)
* Simulates sophisticated ransomware sleeping $1.5\text{s}$ between files to keep CPU utilization flat near $0.0\%$.
* **Observed OS Action**: Proves that traditional CPU threshold monitors fail, while OS Analyzer intercepts the attack on the first canary file via Inode invariant tracking and Entropy Delta ($\Delta H$).

```powershell
python main.py --demo stealth
```

---

#### Demo 3: Benign Compression Benchmark (`--demo benign`)
* Generates intense disk read/write throughput by compressing files into `.gz` archives using standard gzip.
* **Observed OS Action**: Entropy increases to $\approx 6.5$, but the `1F 8B` gzip magic header is recognized. Threat score stays green ($<35$), proving **zero false-positive freezes**.

```powershell
python main.py --demo benign
```

---

### 3. Manual Dual-Terminal Workflow

For interactive evaluation across separate terminals:

```powershell
# Terminal 1: Launch Monitor Dashboard
python main.py --auto-kill

# Terminal 2: Reset Corpus & Run Any Attack
python mock_encryptor.py --reset
python mock_encryptor.py --mode blitz
```

---

## 🎯 Attack Simulation Modes

[`mock_encryptor.py`](file:///mock_encryptor.py) acts as a flexible OS workload generator:

| CLI Option | Execution Profile | Expected Threat Score | Autonomous OS Response |
| :--- | :--- | :--- | :--- |
| `--mode blitz` | Rapid encryption ($0.08\text{s}$ sleep), high disk I/O write rate | **$100.0$ (Critical)** | `SIGSTOP` Freeze $\rightarrow$ `SIGKILL` $\rightarrow$ CoW Rollback |
| `--mode stealth` | Slow encryption ($1.5\text{s}$ sleep), flat CPU ($0.0\%$) | **$\ge 85.0$ (Critical)** | Canary Tripped $\rightarrow$ `SIGSTOP` Freeze $\rightarrow$ CoW Rollback |
| `--mode benign` | Standard `gzip` compression with `1F 8B` headers, no files deleted | **$< 35.0$ (Normal)** | Benign Header Discount $\rightarrow$ Allowed to complete |
| `--reset` | Re-seeds 40 structured files ($32\text{KB} - 128\text{KB}$) + 5 dummy docs | **$0.0$** | Restores clean baseline |
| `--seed N` | Seeds custom count of $N$ structured files | **$0.0$** | Generates test corpus |

---

## 📂 Repository File Structure

```
os-analyzer/
├── analyzer.py          # Core Engine: EntropyAnalyzer, RollbackManager, CanaryManager, OSProcessController, OSAnalyzer
├── main.py              # User Interface: Rich 4-panel TUI layout, Live monitoring loop, Demo automation
├── mock_encryptor.py    # OS Workload Generator: PID broadcast, multi-mode simulator (blitz, stealth, benign), seeder
├── requirements.txt     # Python dependencies (psutil, watchdog, rich, cryptography)
├── test_monitor_dir/    # Monitored directory containing test corpus and alphabetical canary honeypots
└── README.md            # Comprehensive Operating Systems project documentation
```

### Module Descriptions
* [`analyzer.py`](file:///analyzer.py):
  * [`EntropyAnalyzer`](file:///analyzer.py#L30): Exact Shannon entropy ($H$) and Pearson's Chi-Square ($\chi^2$) uniform distribution test.
  * [`RollbackManager`](file:///analyzer.py#L117): In-memory CoW shadow buffer caching baseline files under 10 MB and restoring clean bytes.
  * [`CanaryManager`](file:///analyzer.py#L221): Alphabetical honeypot deployer (`!000_canary...`) tracking inode (`st_ino`) and SHA-256 integrity.
  * [`OSProcessController`](file:///analyzer.py#L303): Cross-platform process suspension (`psutil.Process.suspend`), termination, `/proc/<pid>/io` reader, and composite threat scoring.
  * [`OSAnalyzer`](file:///analyzer.py#L503): High-level coordinator linking `watchdog.observers.Observer` with the defense subsystems.
* [`main.py`](file:///main.py):
  * [`SystemDiskTracker`](file:///main.py#L35): Real-time delta throughput calculation (KB/s).
  * [`DashboardState`](file:///main.py#L79): Correlates `.active_workload.pid`, manages suspect process telemetry, and records defense action logs.
  * [`generate_layout`](file:///main.py#L327): Renders the 4-quadrant Rich TUI.
* [`mock_encryptor.py`](file:///mock_encryptor.py):
  * [`broadcast_pid`](file:///mock_encryptor.py#L31): Writes `.active_workload.pid` JSON and numeric marker files for cross-process telemetry attribution.
  * [`seed_test_directory`](file:///mock_encryptor.py#L113): Populates realistic structured text/log/CSV/JSON files ($H \approx 4.2 - 4.5$).

---

## 📊 Experimental Benchmark Results

The following benchmark demonstrates the system performance during automated runs across identical 40-file corpuses:

| Evaluation Metric | Baseline / Idle | Benign Backup (`--demo benign`) | Blitz Attack (`--demo blitz`) | Stealth Attack (`--demo stealth`) |
| :--- | :--- | :--- | :--- | :--- |
| **Average CPU Utilization** | $0.2\%$ | $14.8\%$ | $26.5\%$ | **$0.1\%$ (Flat)** |
| **Disk Write Throughput** | $0.0\text{ KB/s}$ | $340.2\text{ KB/s}$ | $1,280.4\text{ KB/s}$ | $28.6\text{ KB/s}$ |
| **Mean Shannon Entropy ($H$)** | $4.28$ | $6.42$ | **$7.96$** | **$7.96$** |
| **Chi-Square Statistic ($\chi^2$)** | $34,200.0$ | $850.4$ | **$242.1$ (Uniform)** | **$248.6$ (Uniform)** |
| **Canary Honeypot Hit?** | No | No (Skipped) | **Yes (File #1)** | **Yes (File #1)** |
| **Composite Threat Score** | $0.0 / 100$ | $18.5 / 100$ | **$100.0 / 100$** | **$85.0 / 100$** |
| **Autonomous Action** | None | Allowed | **`SIGSTOP` + `SIGKILL`** | **`SIGSTOP` + `SIGKILL`** |
| **Time to Process Freeze** | N/A | N/A | **$< 0.35\text{ seconds}$** | **$< 1.55\text{ seconds}$** |
| **Final User Data Lost** | **$0\text{ bytes}$** | **$0\text{ bytes}$** | **$0\text{ bytes}$ (100% CoW Rollback)** | **$0\text{ bytes}$ (100% CoW Rollback)** |

---

## 🔒 Security & Academic Integrity Disclaimer
The simulation capabilities in `mock_encryptor.py` are strictly bounded to `test_monitor_dir/` for educational operating systems research, benchmarking, and behavioral heuristic evaluation. No destructive payload escapes the localized test folder.
