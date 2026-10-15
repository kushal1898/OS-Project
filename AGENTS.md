# 🧠 AGENTS.md: Project Memory & Architecture Context
**Repository**: Real-Time OS Resource Utilization and File-Encryption Behavior Analyzer  
**Active Branch**: `version_2.0_test`  
**Last Updated**: October 15, 2026  
**Operating System Compatibility**: Windows NT (Tested on Windows 11) & Linux / WSL2  

---

## 📌 Executive Summary
This project is an advanced, production-grade Operating Systems & Endpoint Security Analyzer designed to detect, freeze, and remediate ransomware and malicious file-encryption behavior in real time with **zero data loss**.

Instead of relying on easily bypassed static signatures, it employs a behavioral and mathematical detection pipeline combining:
1. **Virtual Filesystem (`/proc`) & Kernel Telemetry**: Process Control Block (PCB) states, CPU/RAM, and disk I/O syscall rates (`syscr`, `syscw`, `read_bytes`, `write_bytes`).
2. **Shannon Entropy ($H$) & Pearson's Chi-Square ($\chi^2$) Goodness-of-Fit**: Distinguishing discrete uniform cipher distributions from natural text and compressed archives.
3. **Alphabetical Inode Honeypots (`!000_canary...`)**: Intercepting directory traversal routines on the very first file touched.
4. **Copy-on-Write (CoW) In-Memory Shadow Buffering**: Maintaining clean pre-attack baseline states in RAM to execute instantaneous rollback upon attack confirmation.
5. **Scheduler Process Suspension (`SIGSTOP` / `NtSuspendProcess`)**: Freezing suspect processes mid-attack before uncatchable termination (`SIGKILL` / `TerminateProcess`).

---

## 🏆 Completed Milestones & Phase Progress

### ✅ Phase 1: Core Mathematical & Mitigation Engine (`analyzer.py`)
* [`EntropyAnalyzer`](file:///analyzer.py#L30):
  * Exact Shannon entropy ($H \in [0.0, 8.0]$ bits/byte) using `collections.Counter` and `math.log2`.
  * Pearson's Chi-Square ($\chi^2$) uniform distribution test ($E = N / 256.0$). Pure ciphertext yields $\chi^2 \approx 200 - 300$, while text yields $\chi^2 > 15,000$.
  * Magic header recognition (`1F 8B` for gzip, `PK\x03\x04` for zip, `78 9C`/`78 01`/`78 DA` for zlib, `\x89PNG` for PNG).
* [`RollbackManager`](file:///analyzer.py#L117):
  * In-memory CoW shadow buffer for all baseline files under 10 MB (`dict[str, bytes]` + SHA-256 hash).
  * Automated unlinking of `.locked`, `.enc`, or `.encrypted` remnants.
  * Overwrites corrupted bytes with pristine cached buffers, guaranteeing $0$ bytes lost.
* [`CanaryManager`](file:///analyzer.py#L221):
  * Automatically deploys `!000_canary_credentials.txt` and `!001_canary_keys.pem`.
  * The `!` prefix guarantees top alphabetical sorting during directory traversal.
  * Tracks filesystem inode (`os.stat().st_ino`) and SHA-256 integrity; any tampering adds `+60` points to threat score.
* [`OSProcessController`](file:///analyzer.py#L303):
  * Composite threat scoring ($0 - 100$) integrating canary hits, entropy delta ($\Delta H > 2.5$), file modification velocity, and I/O write rate, with benign compression deductions.
  * `freeze_process(pid)`: Calls `psutil.Process(pid).suspend()` (`SIGSTOP` on POSIX / `NtSuspendProcess` on Windows).
  * `resume_process(pid)`: Calls `psutil.Process(pid).resume()` (`SIGCONT` on POSIX / `NtResumeProcess` on Windows).
  * `terminate_and_rollback(pid)`: Kills process (`SIGKILL` / `TerminateProcess`) and executes CoW rollback.
  * Direct `/proc/<pid>/io` reader with fallback to `psutil.Process(pid).io_counters()`.
* [`OSAnalyzer`](file:///analyzer.py#L503):
  * Multi-subsystem orchestrator using `watchdog.observers.Observer` and `FileSystemEventHandler`.
* **Self-Test Suite**: Comprehensive $5/5$ test block in `if __name__ == "__main__":` in `analyzer.py`.

### ✅ Phase 2: OS Workload Generator & Multi-Mode Simulator (`mock_encryptor.py`)
* **PID Broadcast**: Writes `.active_workload.pid` JSON in project root and numeric `mock_encryptor.pid` in root and `test_monitor_dir/`, with guaranteed cleanup via `atexit` and `finally`.
* **Realistic Corpus Seeder**: Helper `seed_test_directory(count=40)` creates 40 structured documents (32 KB to 128 KB, $H \approx 4.2 - 4.5$) across 4 formats:
  * Text documents (`corpus_document_*.txt`)
  * System logs (`audit_system_*.log`)
  * CSV ledgers (`financial_ledger_*.csv`)
  * JSON schemas (`config_schema_*.json`)
  * Keeps `dummy_doc_0.txt` through `dummy_doc_4.txt` intact.
* **Three CLI Attack Modes**:
  * `--mode blitz`: Rapid encryption ($0.08\text{s}$ delay), high I/O write throughput, catches freeze mid-attack at file ~4–6.
  * `--mode stealth`: Low-and-slow evasion ($1.5\text{s}$ delay), flat CPU ($0.0\%$), catches freeze via canary tripwire and $\Delta H$.
  * `--mode benign`: Gzip compression benchmark with `1F 8B` header, high I/O, originals preserved, threat score $<35$ (no `SIGSTOP`).
  * `--reset`: Cleans up artifacts and restores clean baseline corpus.

### ✅ Phase 3: Real-Time Terminal UI Dashboard (`main.py` & `requirements.txt`)
* Upgraded [`requirements.txt`](file:///requirements.txt) with `psutil`, `watchdog`, `rich`, and `cryptography`.
* Built 4-Panel Rich Live TUI (`rich.live.Live`, `rich.layout.Layout`, `rich.panel.Panel`, `rich.table.Table`):
  * **Header Panel**: Title, OS kernel version, target path, RAM shadow buffer status.
  * **Left Panel**: System CPU/Memory, delta Disk Read/Write throughput (KB/s), Suspect Process Inspector (`R`, `S`, `T FROZEN/SIGSTOP`, `X KILLED`, direct `/proc/io` counters).
  * **Right Panel**: Visual Threat Score Meter ($0 - 100$, Green/Yellow/Red) and live table of last 10 file events with entropy transitions (`H(before) -> H(after)`), Chi-Square, Header Type, and Verdict.
  * **Footer Panel**: Timestamped OS defense action log (Canary armed $\rightarrow$ `SIGSTOP` freeze $\rightarrow$ `SIGKILL` + CoW Rollback with $0$ bytes lost).
* **CLI Demo Automation**:
  * `python main.py` (live monitor)
  * `python main.py --demo blitz` (seeds, launches TUI, spawns blitz attack at $t=2\text{s}$, freezes, kills, rolls back)
  * `python main.py --demo stealth` (low-and-slow benchmark)
  * `python main.py --demo benign` (gzip false-positive benchmark)
  * `--auto-kill`: Automatic termination and remediation after freeze.

### ✅ Phase 4: Academic Project Documentation (`README.md`)
* Rewrote [`README.md`](file:///README.md) into a comprehensive academic systems report featuring:
  * Mermaid and ASCII architecture and dataflow diagrams.
  * Deep OS concept documentation (PCB, VFS, `/proc`, scheduler states, inode traversal priority, CoW memory buffering).
  * Exact mathematical formulation ($H(X)$, $\Delta H$, $\chi^2$ discrete uniform test, composite threat function).
  * Quick-start instructions for all demo modes and experimental benchmarks.

---

## 🛠️ Key CLI Commands Cheat Sheet

| Purpose | Command |
| :--- | :--- |
| **Run Unit Tests** | `python analyzer.py` |
| **Reset Baseline Corpus** | `python mock_encryptor.py --reset` |
| **Seed Custom Corpus Count** | `python mock_encryptor.py --seed 40` |
| **Launch Live Dashboard** | `python main.py` |
| **Launch Dashboard with Auto-Remediation** | `python main.py --auto-kill` |
| **Automated Blitz Attack Demo** | `python main.py --demo blitz` |
| **Automated Stealth Attack Demo** | `python main.py --demo stealth` |
| **Automated Benign Gzip Benchmark** | `python main.py --demo benign` |
| **Manual Attack Run (Terminal 2)** | `python mock_encryptor.py --mode blitz` |

---

## 🧠 Memory & Future Roadmap Notes

1. **Active Branch**: Work is currently on `version_2.0_test`.
2. **Cross-Platform OS Primitive Rule**:
   * Always wrap `psutil.Process.suspend()` and `psutil.Process.resume()` around platform identification (`NtSuspendProcess` on Windows NT, `SIGSTOP` on POSIX).
   * Direct `/proc/<pid>/io` reader must always have a graceful fallback to `io_counters()` wrapped in `(NoSuchProcess, AccessDenied, FileNotFoundError)`.
3. **CoW Shadow Buffer Limit**:
   * Default file limit is 10 MB per file (`MAX_FILE_SIZE = 10 * 1024 * 1024`) to prevent memory exhaustion.
4. **Potential Future Enhancements**:
   * Kernel eBPF probe integration on Linux (`sys_enter_write`, `sys_enter_unlinkat`).
   * Automated key-extraction via memory dumping (`/proc/<pid>/mem` or `MiniDumpWriteDump`) before issuing `SIGKILL`.
   * Webhook or SIEM alert exporter (JSON / Syslog format).
