import time
import os
import threading
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console

from analyzer import OSAnalyzer

def generate_layout(analyzer):
    layout = Layout()
    layout.split_column(
        Layout(name="upper", size=10),
        Layout(name="lower")
    )
    layout["upper"].split_row(
        Layout(name="resources"),
        Layout(name="io")
    )
    layout["lower"].split_row(
        Layout(name="events", ratio=2),
        Layout(name="alerts", ratio=1)
    )

    # Resources Table
    cpu, mem = analyzer.get_system_stats()
    res_table = Table(title="System Resources", expand=True)
    res_table.add_column("Resource", style="cyan")
    res_table.add_column("Usage", style="magenta")
    res_table.add_row("CPU", f"{cpu}%")
    res_table.add_row("Memory", f"{mem}%")
    layout["resources"].update(Panel(res_table))

    # Top I/O Table
    io_table = Table(title="Top I/O Processes", expand=True)
    io_table.add_column("PID", style="cyan")
    io_table.add_column("Name", style="magenta")
    io_table.add_column("I/O Bytes", style="green")
    for pid, name, io_bytes in analyzer.get_top_io_processes():
        io_table.add_row(str(pid), name, str(io_bytes))
    layout["io"].update(Panel(io_table))

    # File Events Table
    events_table = Table(title="Recent File Events (Target Directory)", expand=True)
    events_table.add_column("Time", style="cyan")
    events_table.add_column("Type", style="magenta")
    events_table.add_column("File", style="green")
    events_table.add_column("Entropy", style="yellow")
    
    events_snapshot = list(analyzer.file_events)[-10:] # last 10
    for ev in events_snapshot:
        t_str = time.strftime('%H:%M:%S', time.localtime(ev["time"]))
        fname = os.path.basename(ev["filepath"])
        ent_str = f"{ev['entropy']:.2f}" if ev['entropy'] > 0 else "-"
        # Highlight high entropy
        if ev['entropy'] > 7.5:
            ent_str = f"[red]{ent_str}[/red]"
        events_table.add_row(t_str, ev["type"], fname, ent_str)
        
    layout["events"].update(Panel(events_table))

    # Alerts
    alerts_table = Table(title="Security Alerts", expand=True)
    alerts_table.add_column("Suspicious File", style="red")
    for sf in analyzer.suspicious_files[-10:]:
        alerts_table.add_row(os.path.basename(sf))
    layout["alerts"].update(Panel(alerts_table))

    return layout

if __name__ == "__main__":
    target_directory = os.path.join(os.getcwd(), "test_monitor_dir")
    analyzer = OSAnalyzer(target_directory)
    
    console = Console()
    console.print(f"[bold green]Starting OS Analyzer... Monitoring {target_directory}[/bold green]")
    
    analyzer.start()
    try:
        with Live(generate_layout(analyzer), refresh_per_second=2, screen=True) as live:
            while True:
                time.sleep(0.5)
                live.update(generate_layout(analyzer))
    except KeyboardInterrupt:
        pass
    finally:
        analyzer.stop()
        console.print("[bold red]Analyzer stopped.[/bold red]")
