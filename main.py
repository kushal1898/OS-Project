"""
========================================================================================
[MAIN TUI DASHBOARD - OS BEHAVIORAL & ENCRYPTION ANALYZER]
SYLLABUS MAPPING: BCSE303L - Silberschatz "Operating System Concepts" (Modules 2 - 7)
========================================================================================

Dashboard Layout Architecture (4 Distinct Syllabus Panels):
  1. Panel 1: [MODULE 2 & 5] Process Control Block (PCB) & Working Set Virtual Memory
  2. Panel 2: [MODULE 4] Producer-Consumer IPC & Semaphore Synchronization
  3. Panel 3: [MODULE 6] File System Table & Write-Ahead Journal (WAL) Status
  4. Panel 4: [MODULE 7 & 3] Access Control Matrix & OS Mitigation Engine
========================================================================================
"""

import os
import sys
import time
import argparse
import threading
import subprocess
from pathlib import Path

# Configure utf-8 stdout if supported by OS terminal
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from rich.text import Text
from rich import box

from analyzer import OSAnalyzer, calculate_entropy


# ======================================================================================
# PANEL 1: [MODULE 2 & 5] PROCESS CONTROL BLOCK (PCB) & WORKING SET MEMORY
# ======================================================================================

def build_pcb_panel(analyzer: OSAnalyzer) -> Panel:
    """
    Renders Module 2 (Process Abstraction & System Calls) and Module 5 (Memory Management).
    Displays textbook PCB fields and Working Set Resident Set Size (RSS).
    All columns have strict no_wrap and ellipsis overflow to prevent layout bouncing.
    """
    pcb = analyzer.get_active_workload_pcb()
    table = Table(box=box.SIMPLE_HEAD, expand=True, show_header=True)
    table.add_column("PCB Attribute", style="cyan", width=22, no_wrap=True, overflow="ellipsis")
    table.add_column("OS Telemetry Value", style="white", no_wrap=True, overflow="ellipsis")

    # Textbook OS State Color Coding
    state = pcb.get("os_state", "READY/RUNNING")
    if "TERMINATED" in state:
        state_styled = f"[bold red]{state}[/bold red]"
    elif "STOPPED" in state or "WAITING" in state:
        state_styled = f"[bold yellow]{state}[/bold yellow]"
    else:
        state_styled = f"[bold green]{state}[/bold green]"

    # Priority Nice styling
    nice_val = pcb.get("priority_nice", 0)
    if nice_val in (64, 19, -1):  # IDLE_PRIORITY_CLASS or lowest nice
        nice_styled = f"[bold yellow]{nice_val} (THROTTLED/IDLE)[/bold yellow]"
    else:
        nice_styled = f"{nice_val} (NORMAL)"

    table.add_row("Target PID / PPID", f"{pcb.get('pid', '-')} / {pcb.get('ppid', '-')}")
    table.add_row("Process Name", f"{pcb.get('process_name', 'Unknown')}")
    table.add_row("Textbook State", state_styled)
    table.add_row("CPU Scheduling Nice", nice_styled)
    table.add_row("Process CPU Load", f"{pcb.get('cpu_percent', 0.0):.1f}%")
    table.add_row("Working Set RSS (MB)", f"{pcb.get('working_set_rss_mb', 0.0):.2f} MB")
    table.add_row("Page Faults (Mod 5)", f"{pcb.get('page_faults', 0):,}")
    table.add_row("I/O Read Syscalls", f"{pcb.get('io_read_syscalls', 0):,} ({pcb.get('io_read_bytes', 0) / 1024:.1f} KB)")
    table.add_row("I/O Write Syscalls", f"{pcb.get('io_write_syscalls', 0):,} ({pcb.get('io_write_bytes', 0) / 1024:.1f} KB)")
    table.add_row("Open Descriptors", f"{pcb.get('open_files_count', 0)}")

    return Panel(
        table,
        title="[bold cyan][MODULE 2 & 5] Process Control Block (PCB) & Working Set Memory[/bold cyan]",
        border_style="cyan"
    )


# ======================================================================================
# PANEL 2: [MODULE 4] PRODUCER-CONSUMER IPC & SEMAPHORE SYNCHRONIZATION
# ======================================================================================

def build_sync_panel(analyzer: OSAnalyzer) -> Panel:
    """
    Renders Module 4 (Threads & Concurrency / Process Synchronization).
    Displays the Bounded-Buffer state, Semaphore counters, and Mutex lock.
    Streamlined 2-column layout prevents crowding on smaller terminal windows.
    """
    sync = analyzer.get_sync_telemetry()
    table = Table(box=box.SIMPLE_HEAD, expand=True, show_header=True)
    table.add_column("Synchronization Primitive (IPC)", style="green", ratio=3, no_wrap=True, overflow="ellipsis")
    table.add_column("State / Telemetry", style="white", ratio=2, no_wrap=True, overflow="ellipsis")

    # Mutex lock state styling
    if sync.get("mutex_locked", False):
        mutex_styled = "[bold red]LOCKED [BUSY][/bold red]"
    else:
        mutex_styled = "[bold green]UNLOCKED [OK][/bold green]"

    # Buffer occupancy styling
    occ = sync.get("buffer_occupancy", "0/20")
    occ_styled = f"[bold yellow]{occ}[/bold yellow]"

    table.add_row("Producer Thread (Watchdog)", "[cyan]LISTENING[/cyan]")
    table.add_row("Consumer Thread (OS Engine)", "[cyan]ACTIVE[/cyan]")
    table.add_row("Bounded Buffer Queue", f"{occ_styled} (Capacity N=20)")
    table.add_row("empty_slots (Semaphore)", f"[cyan]{sync.get('empty_semaphore_val', 20)} vacant[/cyan]")
    table.add_row("filled_slots (Semaphore)", f"[magenta]{sync.get('full_semaphore_val', 0)} queued[/magenta]")
    table.add_row("mutex (Critical Section Lock)", mutex_styled)
    table.add_row("IPC Events Synchronized", f"Prod: {sync.get('total_produced', 0)} | Cons: {sync.get('total_consumed', 0)}")

    return Panel(
        table,
        title="[bold green][MODULE 4] Producer-Consumer IPC & Semaphore Synchronization[/bold green]",
        border_style="green"
    )


# ======================================================================================
# PANEL 3: [MODULE 6] FILE SYSTEM TABLE & WRITE-AHEAD JOURNAL (WAL) STATUS
# ======================================================================================

def build_journal_panel(analyzer: OSAnalyzer) -> Panel:
    """
    Renders Module 6 (Storage & File System Management).
    Displays Inodes, Shannon Entropy transitions, and Journal transaction status.
    Strictly capped to latest 5 items with no_wrap and overflow ellipsis to keep row height locked.
    """
    table = Table(box=box.SIMPLE_HEAD, expand=True, show_header=True)
    table.add_column("File Name", style="white", width=18, no_wrap=True, overflow="ellipsis")
    table.add_column("Inode", style="cyan", width=10, no_wrap=True, overflow="ellipsis")
    table.add_column("Shannon Entropy (H)", style="yellow", width=22, no_wrap=True, overflow="ellipsis")
    table.add_column("Write Rate", style="magenta", width=12, no_wrap=True, overflow="ellipsis")
    table.add_column("Journal Tx Status", style="white", no_wrap=True, overflow="ellipsis")

    journal_tbl = analyzer.journal_mgr.journal_table
    recent_events = list(analyzer.file_events)[-5:]

    if not recent_events:
        # Display latest 5 checkpointed files from journal
        for fname in list(journal_tbl.keys())[:5]:
            rec = journal_tbl[fname]
            table.add_row(
                fname,
                str(rec.get("inode", "-")),
                f"{rec.get('initial_entropy', 4.45):.2f} bits/byte",
                "0.0 KB/s",
                "[green]COMMITTED[/green]"
            )
    else:
        for ev in reversed(recent_events):
            fname = os.path.basename(ev.get("filepath", ""))
            rec = journal_tbl.get(fname, {})
            inode_str = str(rec.get("inode", "-"))
            base_ent = rec.get("initial_entropy", 4.45)
            curr_ent = ev.get("entropy", 0.0)
            w_rate = ev.get("write_rate", 0.0)

            # Highlight high entropy
            if curr_ent >= 7.2:
                ent_styled = f"[bold red]{base_ent:.2f} -> {curr_ent:.2f} [HIGH][/bold red]"
            elif curr_ent > 0:
                ent_styled = f"[green]{base_ent:.2f} -> {curr_ent:.2f}[/green]"
            else:
                ent_styled = f"{base_ent:.2f}"

            # Tx status styling
            status = rec.get("tx_status", "COMMITTED")
            if "RECOVERED" in status:
                status_styled = "[bold cyan]RECOVERED[/bold cyan]"
            elif "DIRTY" in status:
                status_styled = "[bold red]DIRTY / UNCOMMITTED[/bold red]"
            else:
                status_styled = "[green]COMMITTED[/green]"

            table.add_row(fname, inode_str, ent_styled, f"{w_rate:.1f} KB/s", status_styled)

    j_status = analyzer.get_journal_status()
    summary_line = (
        f"Inodes: {j_status['total_tracked']} | "
        f"Committed: [green]{j_status['committed']}[/green] | "
        f"Dirty: [red]{j_status['dirty']}[/red] | "
        f"Recovered: [cyan]{j_status['recovered']}[/cyan]"
    )

    return Panel(
        table,
        title="[bold yellow][MODULE 6] File System Table & Write-Ahead Journal (WAL)[/bold yellow]",
        subtitle=summary_line,
        border_style="yellow"
    )


# ======================================================================================
# PANEL 4: [MODULE 7 & 3] ACCESS CONTROL MATRIX & OS MITIGATION ENGINE
# ======================================================================================

def build_security_panel(analyzer: OSAnalyzer) -> Panel:
    """
    Renders Module 7 (System Protection & Access Matrix) and Module 3 (CPU Preemption).
    Displays the Access Matrix rights and strictly capped latest 5 chronological OS action logs.
    All table cells use no_wrap=True and overflow="ellipsis" for rock-solid stability.
    """
    # 1. Access Control Matrix Sub-Table (compact 3 rows)
    acm_table = Table(box=box.SIMPLE, expand=True, show_header=True, padding=(0, 1))
    acm_table.add_column("Domain / Subject", style="cyan", width=20, no_wrap=True, overflow="ellipsis")
    acm_table.add_column("test_monitor_dir/*", style="white", no_wrap=True, overflow="ellipsis")
    acm_table.add_column(".os_journal/*", style="white", no_wrap=True, overflow="ellipsis")

    matrix = analyzer.get_access_matrix()
    for subject, objs in matrix.items():
        dir_rights = objs.get("test_monitor_dir/*", "READ")
        jour_rights = objs.get(".os_journal/*", "NO_ACCESS")

        if "REVOKED" in dir_rights:
            dir_styled = f"[bold red]{dir_rights}[/bold red]"
        else:
            dir_styled = f"[green]{dir_rights}[/green]"

        jour_styled = f"[dim]{jour_rights}[/dim]" if "NO_ACCESS" in jour_rights else f"[cyan]{jour_rights}[/cyan]"
        acm_table.add_row(subject, dir_styled, jour_styled)

    # 2. Chronological OS Mechanism Action Log (Strictly latest 6 events)
    log_table = Table(box=box.SIMPLE, expand=True, show_header=True, padding=(0, 1))
    log_table.add_column("Time", style="dim cyan", width=8, no_wrap=True)
    log_table.add_column("OS Mechanism Enforced", style="white", no_wrap=True, overflow="ellipsis")

    recent_logs = list(analyzer.mitigation_logs)[-6:]
    if not recent_logs:
        log_table.add_row(
            time.strftime('%H:%M:%S'),
            "[green]Policy Status: NORMAL - System within acceptable Shannon Entropy thresholds.[/green]"
        )
    else:
        for entry in recent_logs:
            t_str = time.strftime('%H:%M:%S', time.localtime(entry.get("time", time.time())))
            msg = entry.get("message", "")
            if "[MODULE 3" in msg:
                styled_msg = f"[bold yellow]{msg}[/bold yellow]"
            elif "[MODULE 2" in msg:
                styled_msg = f"[bold red]{msg}[/bold red]"
            elif "[MODULE 7" in msg:
                styled_msg = f"[bold magenta]{msg}[/bold magenta]"
            elif "[MODULE 6" in msg:
                styled_msg = f"[bold cyan]{msg}[/bold cyan]"
            else:
                styled_msg = msg
            log_table.add_row(t_str, styled_msg)

    # Combine into a single vertical layout with compact ACM and expanded log space
    combined_layout = Layout()
    combined_layout.split_column(
        Layout(acm_table, size=5),
        Layout(log_table)
    )

    return Panel(
        combined_layout,
        title="[bold red][MODULE 7 & 3] Access Control Matrix & OS Mitigation Engine[/bold red]",
        border_style="red"
    )


# ======================================================================================
# MASTER LAYOUT COMPOSITION (LOCKED SIZES & RATIOS)
# ======================================================================================

def generate_layout(analyzer: OSAnalyzer, target_dir: str) -> Layout:
    """
    Composes the 4-panel syllabus layout with locked sizes and equal ratios.
    Includes a high-visibility dynamic System Status Banner across the top.
    """
    cpu_pct, mem_pct = analyzer.get_system_stats()
    banner_text, banner_style = analyzer.get_system_banner()

    root = Layout()
    root.split_column(
        Layout(name="header", size=4),
        Layout(name="upper", ratio=1),
        Layout(name="lower", ratio=1),
        Layout(name="footer", size=3)
    )

    # Header Bar with Integrated System Status Banner
    header_table = Table.grid(expand=True)
    header_table.add_column(ratio=1)

    line1 = Text.assemble(
        ("  OS-ANALYZER: REAL-TIME RESOURCE UTILIZATION & ENCRYPTION ANALYZER ", "bold white"),
        (" | Syllabus: BCSE303L (Modules 2 - 7) ", "dim white"),
        (f" | CPU: {cpu_pct:.1f}% ", "bold cyan"),
        (f" | RAM: {mem_pct:.1f}% ", "bold magenta"),
        (f" | Target: {os.path.basename(target_dir)} ", "yellow")
    )
    line2 = Text(f" {banner_text} ", style=banner_style)

    header_table.add_row(line1)
    header_table.add_row(line2)
    root["header"].update(Panel(header_table, style="white on dark_blue", box=box.SQUARE))

    # Upper & Lower Row Splitting
    root["upper"].split_row(
        Layout(name="m2_m5", ratio=1),
        Layout(name="m4", ratio=1)
    )
    root["lower"].split_row(
        Layout(name="m6", ratio=1),
        Layout(name="m7_m3", ratio=1)
    )

    # Populate Panels
    root["m2_m5"].update(build_pcb_panel(analyzer))
    root["m4"].update(build_sync_panel(analyzer))
    root["m6"].update(build_journal_panel(analyzer))
    root["m7_m3"].update(build_security_panel(analyzer))

    # Footer Bar
    footer_text = Text.assemble(
        ("  [Ctrl+C] Exit Dashboard  ", "bold white on red"),
        ("  Demo: python main.py --demo attack  ", "bold white on dark_green"),
        ("  Demo Normal: python main.py --demo normal  ", "bold white on dark_cyan"),
        ("  Reset: python mock_encryptor.py --reset  ", "dim white")
    )
    root["footer"].update(Panel(footer_text, box=box.SQUARE))

    return root


# ======================================================================================
# DEMO LAUNCHER HELPER (SILENCED SUBPROCESS)
# ======================================================================================

def launch_demo_workload(mode: str, target_dir: str):
    """
    Launches mock_encryptor.py in a background process after a brief 2-second pause.
    Paced with 1.2s delay per file so students and evaluators can clearly observe
    Stage 1 (Module 3 Throttle) -> Stage 2 (Module 2/7/6 SIGKILL & WAL Rollback).
    """
    time.sleep(2.0)
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "mock_encryptor.py"),
        "--mode", mode,
        "--delay", "1.2",
        "--dir", target_dir
    ]
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


# ======================================================================================
# APPLICATION ENTRY POINT
# ======================================================================================

def main():
    parser = argparse.ArgumentParser(
        description="OS-Project Real-Time Dashboard (BCSE303L Syllabus Mapped)"
    )
    parser.add_argument(
        "--demo", choices=["attack", "normal"], default=None,
        help="Runs an automated live demo: automatically resets/seeds files and launches workload"
    )
    parser.add_argument(
        "--dir", type=str, default="test_monitor_dir",
        help="Monitored target directory (default: test_monitor_dir)"
    )
    parser.add_argument(
        "--refresh", type=float, default=4.0,
        help="Dashboard refresh rate in Hz (default: 4.0)"
    )

    args = parser.parse_args()
    target_directory = os.path.abspath(args.dir)

    console = Console()

    # If --demo mode specified, reset environment first
    if args.demo:
        console.print(f"[bold cyan][DEMO MODE: {args.demo.upper()}][/bold cyan] Re-seeding baseline files in {target_directory}...")
        try:
            from mock_encryptor import reset_environment
            reset_environment(target_directory, count=25)
        except Exception as e:
            console.print(f"[yellow]Could not pre-reset: {e}[/yellow]")

    analyzer = OSAnalyzer(target_directory)
    analyzer.start()

    # Launch background workload if --demo was requested
    if args.demo:
        console.print(f"[bold green]Starting live dashboard. Launching {args.demo} workload in 2 seconds...[/bold green]")
        demo_thread = threading.Thread(
            target=launch_demo_workload,
            args=(args.demo, target_directory),
            daemon=True
        )
        demo_thread.start()

    try:
        # Alternate screen buffer with auto_refresh=False and redirect_stdout/stderr
        # to guarantee zero terminal cursor jumping, bouncing, or mid-frame tearing.
        with Live(
            generate_layout(analyzer, target_directory),
            screen=True,
            auto_refresh=False,
            redirect_stdout=True,
            redirect_stderr=True
        ) as live:
            while True:
                time.sleep(1.0 / args.refresh)
                live.update(generate_layout(analyzer, target_directory))
                live.refresh()
    except KeyboardInterrupt:
        pass
    finally:
        analyzer.stop()
        console.print("\n[bold red][OS ANALYZER STOPPED][/bold red] Telemetry observer and consumer terminated cleanly.\n")


if __name__ == "__main__":
    main()
