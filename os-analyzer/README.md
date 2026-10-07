# 🛡️ OS Analyzer: Real-Time Activity & Ransomware Behavioral Monitor

An intelligent, lightweight, real-time operating system and filesystem analyzer designed to detect ransomware behavior, rapid encryption attacks, and anomalous process I/O activity through **Shannon Entropy analysis** and live system telemetry.

---

## 📌 Project Overview

**OS Analyzer** provides defensive security observability at the endpoint level. Traditional signature-based antivirus solutions often struggle against zero-day or polymorphically encrypted ransomware payloads. OS Analyzer takes a **behavioral and statistical detection** approach by monitoring:

1. **Filesystem Activity**: Capturing real-time file creation, modification, and deletion events in target directories using OS kernel-level notifications.
2. **Data Randomness (Shannon Entropy)**: Calculating information entropy per modified file on-the-fly. Plaintext documents typically have low entropy ($H \approx 3.0 - 5.0$), whereas AES/RSA-encrypted files exhibit high entropy ($H > 7.5$).
3. **Hardware Telemetry & Process I/O**: Tracking overall CPU and memory utilization alongside top I/O-consuming processes to pinpoint disk-thrashing or mass-encryption tasks.
4. **Live Terminal User Interface (TUI)**: Presenting all metrics, event logs, and security alerts inside a multi-panel dashboard built with `rich`.

```
                  ┌───────────────────────────────────────────────┐
                  │                 Target Folder                 │
                  └───────────────────────┬───────────────────────┘
                                          │ Watchdog Events
                                          ▼
┌──────────────────────┐        ┌───────────────────┐        ┌──────────────────────┐
│  Hardware Telemetry  │        │  File Event Loop  │        │   Shannon Entropy    │
│  • CPU & Memory %    │        │  • Created        │        │   Calculation Engine │
│  • Top I/O PIDs      │        │  • Modified       │───────>│   H = -Σ P(x)log2P(x)│
└──────────┬───────────┘        │  • Deleted        │        └──────────┬───────────┘
           │                    └─────────┬─────────┘                   │
           │                              │                             │
           └────────────────────────┐     │     ┌───────────────────────┘
                                    ▼     ▼     ▼
                        ┌───────────────────────────────┐
                        │      Rich Live Dashboard      │
                        │  • System Resources & I/O     │
                        │  • Recent File Events Stream  │
                        │  • Real-time Security Alerts  │
                        └───────────────────────────────┘
```

---

## ✨ Key Features

- 🔍 **Real-Time Filesystem Observation**: Powered by `watchdog`, asynchronously capturing file modifications with minimal overhead.
- 🧮 **Mathematical Entropy Detection**: Implements Shannon Entropy formula ($0.0 \le H \le 8.0$) to distinguish benign document edits from cryptographic overwrites.
- 🚨 **Automated Alerting**: Instantly flags files exceeding the $7.5$ entropy threshold and displays them in the dedicated Security Alerts panel.
- 📊 **Process I/O Tracking**: Identifies processes generating high disk read/write throughput using `psutil`.
- 🖥️ **Interactive Terminal GUI**: Responsive, multi-panel terminal interface updating at 2 Hz without screen flicker.
- 🧪 **Built-in Ransomware Simulation**: Includes a safe mock script (`mock_encryptor.py`) to simulate ransomware behavior and verify detection alerts in real time.

---

## 📂 Project Structure

```
os-analyzer/
├── analyzer.py          # Core engine: Shannon entropy calculation, file watcher, & psutil stats
├── main.py              # Application entry point: Rich terminal UI layout & live rendering loop
├── mock_encryptor.py    # Test utility: Creates dummy documents and simulates encryption attacks
├── requirements.txt     # Python dependencies
├── test_monitor_dir/    # Target directory monitored by the analyzer
└── README.md            # Comprehensive project documentation
```

### Module Breakdown

| File | Description |
| :--- | :--- |
| [`analyzer.py`](file:///analyzer.py) | Contains `calculate_entropy()`, `FileMonitorHandler`, and the `OSAnalyzer` class orchestrating watchdog observers, process metrics, and alert queues. |
| [`main.py`](file:///main.py) | Configures the 4-quadrant layout (`System Resources`, `Top I/O Processes`, `Recent File Events`, `Security Alerts`) and launches the live screen. |
| [`mock_encryptor.py`](file:///mock_encryptor.py) | Safely generates low-entropy test files, then overwrites them with `os.urandom()` bytes to trigger high-entropy detections. |

---

## ⚙️ Prerequisites & Installation

### 1. Prerequisites
- **Python 3.8+** installed on your system.
- OS: Windows, Linux, or macOS.

### 2. Clone or Navigate to the Directory
```bash
cd path/to/os-analyzer
```

### 3. Create & Activate a Virtual Environment

- **Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
- **Windows (CMD)**:
  ```cmd
  python -m venv venv
  .\venv\Scripts\activate.bat
  ```
- **Linux / macOS**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Dependencies: `rich`, `watchdog`, `psutil`)*

---

## 🚀 How to Run the Project

To experience the full detection cycle, it is recommended to use **two terminal windows**:

### Step 1: Start the OS Analyzer Dashboard (Terminal 1)

In your first terminal, launch the main analyzer:

```bash
python main.py
```

You will see the interactive TUI split into four panels:
1. **System Resources**: Live CPU and Memory percentage.
2. **Top I/O Processes**: Top disk-active processes by PID and total byte throughput.
3. **Recent File Events**: Stream of file creations, edits, deletions, and their computed entropy.
4. **Security Alerts**: List of flagged suspicious/encrypted files.

---

### Step 2: Run the Attack Simulation (Terminal 2)

In a separate terminal (with the virtual environment activated), trigger the mock encryptor:

```bash
python mock_encryptor.py
```

**What happens during simulation:**
1. Generates 5 dummy text files (`dummy_doc_0.txt` to `4.txt`) containing repetitive natural language sentences (Entropy $\approx 3.2 - 4.5$).
2. Terminal 1 logs `CREATED` events with normal entropy values.
3. After a brief pause, the script reads each document and overwrites it with cryptographically random bytes (`os.urandom`), simulating ransomware behavior.
4. Terminal 1 logs `MODIFIED` events with high entropy values ($H \approx 7.9 - 8.0$), highlighted in **red**.
5. The files are immediately flagged and listed in the **Security Alerts** panel.

---

### Step 3: Stop the Analyzer
Press `Ctrl + C` in Terminal 1 to gracefully shut down the watchdog observer and return to standard terminal mode.

---

## 🔬 Mathematical Detection Logic

### Shannon Entropy Formula
Shannon Entropy measures the average uncertainty or randomness of byte distributions in a file:

$$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

Where:
- $P(x_i)$ is the probability (frequency) of byte value $i$ (from `0x00` to `0xFF`) occurring in the file.
- When all 256 byte values are uniformly distributed (characteristic of strong ciphers and random noise), $H(X) \to 8.0$.
- Plaintext, source code, and structured formats typically range from $1.5$ to $5.5$.

### Decision Threshold
```python
# Entropy Heuristic in analyzer.py
if entropy > 7.5:
    if filepath not in self.suspicious_files:
        self.suspicious_files.append(filepath)
```

---

## 🛠️ Configuration & Customization

You can customize the target directory and thresholds directly in the code:

1. **Change Monitored Directory**:
   In [`main.py`](file:///main.py#L74):
   ```python
   target_directory = r"C:\path\to\your\custom_directory"
   ```
2. **Adjust Entropy Sensitivity**:
   In [`analyzer.py`](file:///analyzer.py#L77) and [`main.py`](file:///main.py#L58), change `7.5` to your preferred sensitivity threshold.
3. **Adjust Dashboard Refresh Rate**:
   In [`main.py`](file:///main.py#L82), tweak `refresh_per_second` and `time.sleep()`.

---

## 🔒 Security Disclaimer
The included `mock_encryptor.py` is strictly a benign simulation utility designed for testing behavioral detection heuristics inside the local `test_monitor_dir/`. It does not propagate across directories or harm system stability.
