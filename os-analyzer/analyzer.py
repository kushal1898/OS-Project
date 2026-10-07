import os
import time
import math
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            if not data:
                return 0.0
            entropy = 0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log2(p_x)
            return entropy
    except Exception:
        return 0.0

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def on_modified(self, event):
        if not event.is_directory:
            self.analyzer.record_file_event(event.src_path, "MODIFIED")

    def on_created(self, event):
        if not event.is_directory:
            self.analyzer.record_file_event(event.src_path, "CREATED")

    def on_deleted(self, event):
        if not event.is_directory:
            self.analyzer.record_file_event(event.src_path, "DELETED")


class OSAnalyzer:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.file_events = deque(maxlen=100)
        self.suspicious_files = []
        self.observer = Observer()
        self.handler = FileMonitorHandler(self)
        self.observer.schedule(self.handler, path=self.target_dir, recursive=True)

    def start(self):
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()

    def record_file_event(self, filepath, event_type):
        entropy = 0.0
        if event_type in ["MODIFIED", "CREATED"]:
            entropy = calculate_entropy(filepath)
            
        event_record = {
            "time": time.time(),
            "filepath": filepath,
            "type": event_type,
            "entropy": entropy
        }
        self.file_events.append(event_record)
        
        # Heuristics check
        if entropy > 7.5:
            if filepath not in self.suspicious_files:
                self.suspicious_files.append(filepath)

    def get_system_stats(self):
        if HAS_PSUTIL:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            return cpu, mem
        else:
            return 12.5, 45.0
        
    def get_top_io_processes(self, limit=3):
        if not HAS_PSUTIL:
            return [(999, "mock_process.exe", 102450)]
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'io_counters']):
            try:
                io = p.info['io_counters']
                if io:
                    read_write = io.read_bytes + io.write_bytes
                    if read_write > 0:
                        procs.append((p.info['pid'], p.info['name'], read_write))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by total IO bytes
        procs.sort(key=lambda x: x[2], reverse=True)
        return procs[:limit]

