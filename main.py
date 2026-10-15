"""
Real-Time OS Resource Utilization and File-Encryption Behavior Analyzer
Live Terminal UI (TUI) Dashboard & Autonomous OS Defense Mitigation Engine
"""

import os
import sys
import time
import json
import signal
import platform
import argparse
import threading
import subprocess
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.console import Console

from analyzer import OSAnalyzer, EntropyAnalyzer
import mock_encryptor


# ============================================================================
# 1. System Telemetry & Disk I/O Tracker
# ============================================================================
class SystemDiskTracker:
    """
    Computes per-second disk I/O read and write throughput in KB/s.
    """
    def __init__(self):
        self.prev_time = time.time()
        self.prev_read = 0
        self.prev_write = 0
        if HAS_PSUTIL:
            try:
                io = psutil.disk_io_counters()
                if io:
                    self.prev_read = io.read_bytes
                    self.prev_write = io.write_bytes
            except Exception:
                pass

    def get_throughput(self) -> tuple[float, float]:
        now = time.time()
        dt = max(0.001, now - self.prev_time)
        read_kb = 0.0
        write_kb = 0.0
        if HAS_PSUTIL:
            try:
                io = psutil.disk_io_counters()
                if io:
                    read_kb = max(0.0, (io.read_bytes - self.prev_read) / dt / 1024.0)
                    write_kb = max(0.0, (io.write_bytes - self.prev_write) / dt / 1024.0)
                    self.prev_read = io.read_bytes
                    self.prev_write = io.write_bytes
                    self.prev_time = now
            except Exception:
                pass
        return read_kb, write_kb


# ============================================================================
# 2. Dashboard State & Suspect Process Correlator
# ============================================================================
class DashboardState:
    """
    Tracks suspect process attributes, autonomous mitigation timeline,
    and action logs for the footer panel.
    """
    def __init__(self, project_root: str, target_dir: str, auto_kill: bool = False):
        self.project_root = os.path.abspath(project_root)
        self.target_dir = os.path.abspath(target_dir)
        self.auto_kill = auto_kill
        self.suspect_pid: int | None = None
        self.suspect_name: str = "mock_encryptor.py"
        self.suspect_mode: str = "N/A"
        self.frozen_time: float | None = None
        self.remediated_time: float | None = None
        self.terminated_pids: set[int] = set()
        self.action_logs: list[str] = []
        self.lock = threading.Lock()

        # Arming log
        self.add_log(
            "ARMED",
            "Canary trap armed in target directory (!000_canary_credentials.txt, !001_canary_keys.pem). Baseline CoW snapshot locked in RAM.",
            "bold cyan"
        )

    def add_log(self, tag: str, message: str, color: str = "white"):
        with self.lock:
            now_str = time.strftime("%H:%M:%S", time.localtime())
            self.action_logs.append(f"[{now_str}] [{color}][{tag}][/{color}] {message}")
            if len(self.action_logs) > 50:
                self.action_logs.pop(0)

    def discover_suspect(self, analyzer) -> int | None:
        with self.lock:
            # 1. Read .active_workload.pid JSON
            pid_json_p = os.path.join(self.project_root, ".active_workload.pid")
            if os.path.exists(pid_json_p):
                try:
                    with open(pid_json_p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pid_val = data.get("pid")
                        if pid_val and pid_val > 0:
                            self.suspect_pid = pid_val
                            self.suspect_name = data.get("process_name", "mock_encryptor.py")
                            self.suspect_mode = data.get("mode", "active")
                            return self.suspect_pid
                except (json.JSONDecodeError, OSError):
                    pass

            # 2. Check mock_encryptor.pid markers
            for folder in (self.target_dir, self.project_root):
                m_file = os.path.join(folder, "mock_encryptor.pid")
                if os.path.exists(m_file):
                    try:
                        with open(m_file, "r", encoding="utf-8") as mf:
                            pid_val = int(mf.read().strip())
                            if pid_val > 0:
                                self.suspect_pid = pid_val
                                self.suspect_name = "mock_encryptor.py"
                                return self.suspect_pid
                    except (ValueError, OSError):
                        pass

            # 3. Check analyzer frozen PIDs
            if analyzer.process_controller.frozen_pids:
                for f_pid in analyzer.process_controller.frozen_pids:
                    self.suspect_pid = f_pid
                    return self.suspect_pid

            return self.suspect_pid


def get_process_state(pid: int | None, frozen_pids: set[int], terminated_pids: set[int]) -> tuple[str, float, float]:
    """
    Returns (state_string, cpu_percent, memory_mb).
    States: R RUNNING, S SLEEPING, T FROZEN/SIGSTOP, X KILLED, or INACTIVE.
    """
    if not pid or pid <= 0:
        return "[dim]INACTIVE[/dim]", 0.0, 0.0

    if pid in terminated_pids:
        return "[bold red]X KILLED[/bold red]", 0.0, 0.0

    if not HAS_PSUTIL:
        if pid in frozen_pids:
            return "[bold yellow]T FROZEN/SIGSTOP[/bold yellow]", 0.0, 0.0
        return "[white]UNKNOWN[/white]", 0.0, 0.0

    try:
        proc = psutil.Process(pid)
        status = proc.status()
        cpu_pct = proc.cpu_percent(interval=None)
        mem_mb = proc.memory_info().rss / (1024.0 * 1024.0)

        if pid in frozen_pids or status in (psutil.STATUS_STOPPED, getattr(psutil, "STATUS_SUSPENDED", "suspended")):
            return "[bold yellow]T FROZEN/SIGSTOP[/bold yellow]", cpu_pct, mem_mb
        elif status == psutil.STATUS_RUNNING:
            return "[bold green]R RUNNING[/bold green]", cpu_pct, mem_mb
        elif status == psutil.STATUS_SLEEPING:
            return "[cyan]S SLEEPING[/cyan]", cpu_pct, mem_mb
        elif status in (psutil.STATUS_DEAD, psutil.STATUS_ZOMBIE):
            return "[bold red]X KILLED[/bold red]", 0.0, 0.0
        else:
            return f"[white]{status.upper()}[/white]", cpu_pct, mem_mb
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        if pid in terminated_pids or pid in frozen_pids:
            return "[bold red]X KILLED[/bold red]", 0.0, 0.0
        return "[dim]TERMINATED[/dim]", 0.0, 0.0


# ============================================================================
# 3. Component Builders
# ============================================================================
def build_threat_meter(threat_score: float) -> Panel:
    """
    Builds the Visual Threat Score Meter (0-100) with color coding:
    Green (<35), Yellow (35-69), Red (>=70).
    """
    score = max(0.0, min(100.0, threat_score))
    total_bars = 32
    filled = int((score / 100.0) * total_bars)
    empty = total_bars - filled

    if score < 35.0:
        color = "green"
        level = "NORMAL / LOW RISK"
        bar_char = "━"
    elif score < 70.0:
        color = "yellow"
        level = "ELEVATED ANOMALY"
        bar_char = "━"
    else:
        color = "bold red"
        level = "CRITICAL ATTACK DETECTED"
        bar_char = "█"

    bar = f"[{color}]{bar_char * filled}[/{color}][dim white]{'─' * empty}[/dim white]"
    content = Text.from_markup(
        f"Threat Level: [{color}]{score:5.1f}/100 [{level}][/{color}]\n[{bar}]"
    )
    border_color = "red" if score >= 70.0 else ("yellow" if score >= 35.0 else "green")
    return Panel(content, title="[bold]Behavioral Threat Score Meter (0-100)[/bold]", border_style=border_color)


def build_events_table(analyzer) -> Panel:
    """
    Builds the live table of the last 10 file events in test_monitor_dir/:
    Columns: Timestamp, File, H(before) -> H(after), Chi-Sq, Header Type, Verdict.
    """
    table = Table(expand=True, box=None, padding=(0, 1))
    table.add_column("Timestamp", style="cyan", width=9)
    table.add_column("File", style="white", ratio=2)
    table.add_column("H(before) -> H(after)", justify="center", ratio=2)
    table.add_column("Chi-Sq", justify="right", ratio=1)
    table.add_column("Header Type", ratio=2)
    table.add_column("Verdict", justify="center", ratio=2)

    events_snapshot = list(analyzer.file_events)[-10:]
    for ev in events_snapshot:
        t_str = time.strftime("%H:%M:%S", time.localtime(ev["time"]))
        fname = os.path.basename(ev["filepath"])
        curr_h = ev.get("entropy", 0.0)
        base_h = analyzer.baseline_entropies.get(os.path.abspath(ev["filepath"]), 3.50)
        chi_sq = ev.get("chi_square", 0.0)
        is_canary = ev.get("is_canary", False)

        # Header type detection
        if fname.endswith(".gz"):
            header_type = "[green]GZIP (1F 8B)[/green]"
        elif fname.endswith(".locked") or curr_h > 7.8:
            header_type = "[red]CIPHERTEXT[/red]"
        elif fname.startswith("!000") or fname.startswith("!001") or is_canary:
            header_type = "[yellow]CANARY_BAIT[/yellow]"
        elif curr_h > 0:
            header_type = "[dim]TEXT/RECORD[/dim]"
        else:
            header_type = "[dim]-[/dim]"

        # Verdict classification
        if is_canary or fname.startswith("!000") or fname.startswith("!001"):
            verdict = "[bold red]CANARY_HIT[/bold red]"
        elif fname.endswith(".gz") or ev.get("is_compressed", False):
            verdict = "[bold green]BENIGN_GZIP[/bold green]"
        elif curr_h > 7.5:
            verdict = "[bold red]SUSPICIOUS[/bold red]"
        else:
            verdict = "[green]CLEAN[/green]"

        # Formatting Entropy transition
        if curr_h > 7.5:
            h_str = f"[dim]{base_h:.2f}[/dim] -> [bold red]{curr_h:.2f}[/bold red]"
        elif curr_h > 0:
            h_str = f"{base_h:.2f} -> {curr_h:.2f}"
        else:
            h_str = f"{base_h:.2f} -> -"

        chi_str = f"{chi_sq:.1f}" if chi_sq > 0 else "-"

        table.add_row(t_str, fname, h_str, chi_str, header_type, verdict)

    return Panel(table, title="[bold]Behavioral & Entropy Engine (Last 10 Events)[/bold]", border_style="magenta")


def build_left_panel(analyzer, tracker, state) -> Layout:
    """
    Builds the Left Panel: OS Kernel Telemetry and Suspect Process Inspector.
    """
    left_layout = Layout()
    left_layout.split_column(
        Layout(name="sys_metrics", size=7),
        Layout(name="suspect_inspector", ratio=1)
    )

    # 1. Hardware System Metrics
    cpu_pct, mem_pct = analyzer.get_system_stats()
    read_kb, write_kb = tracker.get_throughput()

    sys_table = Table(expand=True, box=None, padding=(0, 1))
    sys_table.add_column("Metric", style="cyan")
    sys_table.add_column("Value", style="bold white")
    sys_table.add_column("Metric", style="cyan")
    sys_table.add_column("Value", style="bold white")

    cpu_color = "red" if cpu_pct > 75 else ("yellow" if cpu_pct > 40 else "green")
    mem_color = "red" if mem_pct > 80 else ("yellow" if mem_pct > 50 else "green")

    sys_table.add_row(
        "CPU Utilization:", f"[{cpu_color}]{cpu_pct:.1f}%[/{cpu_color}]",
        "Disk Read Throughput:", f"{read_kb:.1f} KB/s"
    )
    sys_table.add_row(
        "Memory Utilization:", f"[{mem_color}]{mem_pct:.1f}%[/{mem_color}]",
        "Disk Write Throughput:", f"[green]{write_kb:.1f} KB/s[/green]"
    )
    left_layout["sys_metrics"].update(
        Panel(sys_table, title="[bold]OS Kernel Hardware Telemetry[/bold]", border_style="cyan")
    )

    # 2. Suspect Process Inspector & Top I/O
    suspect_pid = state.suspect_pid
    state_str, proc_cpu, proc_ram = get_process_state(
        suspect_pid, analyzer.process_controller.frozen_pids, state.terminated_pids
    )

    io_stats = {"read_bytes": 0, "write_bytes": 0, "syscr": 0, "syscw": 0}
    if suspect_pid:
        io_stats = analyzer.process_controller.get_process_io_counters(suspect_pid)

    insp_table = Table(expand=True, box=None, padding=(0, 1))
    insp_table.add_column("Telemetry Field", style="dim cyan", ratio=1)
    insp_table.add_column("Live Counter / State", style="bold white", ratio=2)

    if suspect_pid:
        insp_table.add_row("Suspect Target PID:", f"[bold yellow]{suspect_pid}[/bold yellow] ({state.suspect_name})")
        insp_table.add_row("Process Scheduler State:", state_str)
        insp_table.add_row("CPU % / Memory RSS:", f"{proc_cpu:.1f}% / {proc_ram:.1f} MB")
        insp_table.add_row("Direct Disk Read (/proc/io):", f"{io_stats['read_bytes']:,} bytes")
        insp_table.add_row("Direct Disk Write (/proc/io):", f"[yellow]{io_stats['write_bytes']:,} bytes[/yellow]")
        insp_table.add_row("I/O Syscalls (syscr / syscw):", f"{io_stats['syscr']:,} read / {io_stats['syscw']:,} write")
    else:
        insp_table.add_row("Suspect Target PID:", "[dim]NO SUSPECT ACTIVE[/dim]")
        insp_table.add_row("Process Scheduler State:", "[dim]INACTIVE[/dim]")
        insp_table.add_row("CPU % / Memory RSS:", "[dim]0.0% / 0.0 MB[/dim]")
        insp_table.add_row("Direct Disk Read (/proc/io):", "[dim]0 bytes[/dim]")
        insp_table.add_row("Direct Disk Write (/proc/io):", "[dim]0 bytes[/dim]")
        insp_table.add_row("I/O Syscalls (syscr / syscw):", "[dim]0 read / 0 write[/dim]")

    # Append Top I/O processes below
    insp_table.add_row("[bold cyan]── Top Disk I/O Consumers ──[/bold cyan]", "[bold cyan]──────────────────────────[/bold cyan]")
    top_procs = analyzer.get_top_io_processes(limit=2)
    for p_id, p_name, rw_b in top_procs:
        p_name_short = p_name[:18] if len(p_name) > 18 else p_name
        insp_table.add_row(f"PID {p_id} ({p_name_short}):", f"{rw_b / 1024.0:,.1f} KB")

    left_layout["suspect_inspector"].update(
        Panel(insp_table, title="[bold]Suspect Process Inspector & Syscall Telemetry[/bold]", border_style="blue")
    )

    return left_layout


def build_footer_panel(state) -> Panel:
    """
    Builds the Footer Panel: Timestamped OS Defense Action Log.
    """
    recent_logs = state.action_logs[-5:]
    log_text = "\n".join(recent_logs) if recent_logs else "[dim]No security actions dispatched yet.[/dim]"
    return Panel(
        Text.from_markup(log_text),
        title="[bold]OS Defense Action Log & Autonomous Remediation[/bold]",
        border_style="red" if state.frozen_time else "cyan"
    )


def generate_layout(analyzer, tracker, state) -> Layout:
    """
    Builds the complete 4-panel split dashboard layout.
    """
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="main_body", ratio=1),
        Layout(name="footer", size=7)
    )
    layout["main_body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )

    # 1. Header Panel
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    kernel_info = f"{os_name} {os_release} ({os_version})"
    snap_count = len(analyzer.rollback_manager.snapshots)

    header_table = Table.grid(expand=True)
    header_table.add_column(ratio=2)
    header_table.add_column(ratio=1, justify="right")

    title_text = Text.from_markup(
        "[bold cyan]🛡️ OS ANALYZER: REAL-TIME RESOURCE UTILIZATION & FILE-ENCRYPTION BEHAVIOR MONITOR[/bold cyan]\n"
        f"[dim white]OS Platform:[/dim white] [white]{kernel_info}[/white] | "
        f"[dim white]Target Directory:[/dim white] [green]{analyzer.target_dir}[/green]"
    )
    status_text = Text.from_markup(
        "[bold green]● LIVE ACTIVE[/bold green]\n"
        f"[bold cyan]CoW Shadow Buffer:[/bold cyan] [bold yellow]{snap_count} files protected in RAM[/bold yellow]"
    )
    header_table.add_row(title_text, status_text)
    layout["header"].update(Panel(header_table, border_style="cyan"))

    # 2. Left Panel
    layout["left"].update(build_left_panel(analyzer, tracker, state))

    # 3. Right Panel
    right_layout = Layout()
    right_layout.split_column(
        Layout(name="threat_meter", size=4),
        Layout(name="file_events", ratio=1)
    )
    threat_score = analyzer.process_controller.threat_score
    right_layout["threat_meter"].update(build_threat_meter(threat_score))
    right_layout["file_events"].update(build_events_table(analyzer))
    layout["right"].update(right_layout)

    # 4. Footer Panel
    layout["footer"].update(build_footer_panel(state))

    return layout


# ============================================================================
# 4. Main Entrypoint & Demo Automation
# ============================================================================
def spawn_demo_workload(mode: str, target_dir: str, delay_seconds: float = 2.0):
    """
    Background worker that sleeps delay_seconds before executing mock_encryptor.py.
    """
    def worker():
        time.sleep(delay_seconds)
        cmd = [sys.executable, "mock_encryptor.py", "--mode", mode, "--target-dir", target_dir]
        subprocess.Popen(cmd)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def main():
    parser = argparse.ArgumentParser(
        description="Real-Time OS Resource Utilization and File-Encryption Behavior Analyzer"
    )
    parser.add_argument(
        "--demo",
        choices=["blitz", "stealth", "benign"],
        default=None,
        help="Automated demo mode: seeds target directory, launches TUI, and triggers attack/workload in 2s"
    )
    parser.add_argument(
        "--auto-kill",
        action="store_true",
        help="Automatically dispatch SIGKILL and CoW RAM Rollback after freezing suspect process"
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        default=None,
        help="Directory to monitor (defaults to test_monitor_dir)"
    )

    args = parser.parse_args()

    project_root = os.path.dirname(os.path.abspath(__file__))
    target_directory = os.path.abspath(args.target_dir) if args.target_dir else os.path.join(project_root, "test_monitor_dir")

    # In demo mode, automatically enable auto-kill for destructive attacks and reset baseline
    auto_kill_enabled = args.auto_kill or (args.demo in ["blitz", "stealth"])
    if args.demo:
        print(f"[*] Pre-seeding clean baseline for demo mode ({args.demo})...")
        mock_encryptor.reset_target_directory(target_directory, count=40)

    # Initialize Analyzer and State
    analyzer = OSAnalyzer(target_directory)
    tracker = SystemDiskTracker()
    state = DashboardState(project_root, target_directory, auto_kill=auto_kill_enabled)

    console = Console()
    console.print(f"[bold green]Starting OS Analyzer... Monitoring {target_directory}[/bold green]")

    analyzer.start()

    # Trigger demo workload if specified
    if args.demo:
        spawn_demo_workload(args.demo, target_directory, delay_seconds=2.0)
        state.add_log(
            "DEMO DISPATCH",
            f"Scheduled automated workload ({args.demo}) in 2 seconds...",
            "bold cyan"
        )

    try:
        with Live(generate_layout(analyzer, tracker, state), refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(0.25)

                # Discover suspect process
                suspect_pid = state.discover_suspect(analyzer)
                threat_score = analyzer.process_controller.threat_score

                # Autonomous OS Mitigation Logic
                if threat_score >= 70.0 and suspect_pid and suspect_pid not in state.terminated_pids:
                    # 1. Freeze with SIGSTOP / NtSuspendProcess if not already frozen
                    if suspect_pid not in analyzer.process_controller.frozen_pids:
                        frozen = analyzer.process_controller.freeze_process(suspect_pid)
                        if frozen:
                            state.frozen_time = time.time()
                            state.add_log(
                                "SIGSTOP DISPATCHED",
                                f"Threat score {threat_score:.1f} >= 70.0 detected -> Dispatched SIGSTOP / NtSuspendProcess to freeze PID {suspect_pid} in OS scheduler.",
                                "bold yellow"
                            )

                    # 2. Auto-Remediation (Terminate + CoW Rollback) after observable freeze pause
                    elif state.auto_kill and state.frozen_time and (time.time() - state.frozen_time >= 1.2):
                        summary = analyzer.process_controller.terminate_and_rollback(suspect_pid)
                        state.terminated_pids.add(suspect_pid)
                        state.remediated_time = time.time()
                        restored = summary.get("restored_files", [])
                        names_str = ", ".join(restored[:5])
                        if len(restored) > 5:
                            names_str += f" and {len(restored) - 5} more"
                        state.add_log(
                            "REMEDIATED",
                            f"Dispatched SIGKILL to terminate PID {suspect_pid}. CoW RAM Rollback restored {len(restored)} damaged files ({names_str}). 0 bytes lost.",
                            "bold green"
                        )

                # Update live view
                live.update(generate_layout(analyzer, tracker, state))

    except KeyboardInterrupt:
        pass
    finally:
        analyzer.stop()
        mock_encryptor.cleanup_pid(project_root, target_directory)
        console.print("[bold red]Analyzer stopped.[/bold red]")


if __name__ == "__main__":
    main()
