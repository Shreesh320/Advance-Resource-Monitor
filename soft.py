import psutil
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import threading
from collections import defaultdict

class SystemMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Resource Monitor")
        self.root.state('zoomed')  # Full screen

        # Determine CPU count more robustly
        self.cpu_count = psutil.cpu_count(logical=False) or psutil.cpu_count(logical=True) or 1

        self.cpu_data = [[] for _ in range(self.cpu_count)]
        self.mem_data, self.net_data, self.disk_data = [], [], []

        self.last_net = psutil.net_io_counters()
        self.last_disk = psutil.disk_io_counters()

        self.cpu_threshold = tk.IntVar(value=95)
        self.mem_threshold = tk.IntVar(value=90)
        self.alert_cooldown = timedelta(seconds=10)
        self.last_alert_time = None

        # Automatic process killing attributes
        self.enable_auto_kill = tk.BooleanVar(value=False)
        self.violation_trigger = tk.IntVar(value=3)
        self.process_violation_counts = defaultdict(lambda: {'cpu': 0, 'mem': 0, 'last_violation': None})
        self.auto_killed_processes = set()
        self.kill_cooldown = timedelta(seconds=30)
        self.last_kill_time = defaultdict(lambda: None)
        self.suppress_warnings = set()

        # New for stable process list updates
        self.process_info_cache = {}
        self.process_update_interval_sec = 3
        self._process_update_thread = None
        self._stop_process_update_thread = threading.Event()
        self.last_fetched_processes_data = []

        # Priority-based killing attributes
        self.high_priority_processes = set()
        self.system_critical_processes = self.get_system_critical_processes()

        self.setup_style()
        self.setup_widgets()
        self.setup_plot()

        self.ani = FuncAnimation(self.fig, self.update_plot, interval=1000, cache_frame_data=False)

        self.start_process_update_thread()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self._stop_process_update_thread.set()
        if self._process_update_thread and self._process_update_thread.is_alive():
            self._process_update_thread.join(timeout=2)
        self.root.destroy()

    def get_system_critical_processes(self):
        critical_processes = set()
        if psutil.WINDOWS:
            critical_processes.update([
                "explorer.exe", "csrss.exe", "wininit.exe", "services.exe",
                "lsass.exe", "winlogon.exe", "smss.exe", "dwm.exe",
                "svchost.exe", "RuntimeBroker.exe", "conhost.exe"
            ])
        elif psutil.LINUX:
            critical_processes.update([
                "systemd", "init", "kthreadd", "cgroupfs-mount",
                "udevd", "dbus-daemon", "polkitd", "NetworkManager",
                "gnome-shell", "Xorg", "pulseaudio"
            ])
        return critical_processes

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#1e1e1e', foreground='white', font=('Segoe UI', 10))
        style.configure('TFrame', background='#1e1e1e')
        style.configure('Treeview', background='#2e2e2e', fieldbackground='#2e2e2e', foreground='white')
        style.configure('Treeview.Heading', background='#1e1e1e', foreground='white', font=('Segoe UI', 9, 'bold'))
        style.configure('TButton', background='#333333', foreground='white', font=('Segoe UI', 9), borderwidth=0)
        style.map('TButton', background=[('active', 'black')])
        style.configure('TEntry', fieldbackground='#2e2e2e', foreground='white', insertcolor='white')
        style.configure('TLabelframe', background='#1e1e1e', foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('TLabelframe.Label', foreground='white')
        style.configure('TCheckbutton', background='#1e1e1e', foreground='white', font=('Segoe UI', 9))
        style.configure('Black.TLabelframe', background='#1e1e1e', foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Black.TLabelframe.Label', background='black', foreground='white')
        style.configure('Black.TFrame', background='black')
        style.configure('Black.TLabel', background='black', foreground='white')


    def setup_widgets(self):
        self.info_frame = ttk.Frame(self.root)
        self.info_frame.pack(fill='x', pady=10)

        labels = ["CPU Usage:", "Memory Usage:", "Disk Usage:", "Network:", "Running Processes:", "System Uptime:", "Battery:"]
        self.info_labels = [ttk.Label(self.info_frame, text=text) for text in labels]

        for i, label in enumerate(self.info_labels):
            label.grid(row=0, column=i, padx=10)

        self.process_frame = ttk.LabelFrame(self.root, text="Top Processes", padding=0, style='Black.TLabelframe')
        frame = ttk.Frame(self.process_frame, style='Black.TFrame')
        self.process_frame.pack(fill='x', pady=0)
        

        self.cpu_tree = self.create_process_tree("Top CPU Usage")
        self.mem_tree = self.create_process_tree("Top Memory Usage")

        self.action_frame = ttk.Frame(self.root)
        self.action_frame.pack(fill='x', pady=0)

        ttk.Label(self.action_frame, text="Kill PID:").pack(side='left', padx=5)
        self.pid_entry = ttk.Entry(self.action_frame, width=10)
        self.pid_entry.pack(side='left')
        ttk.Button(self.action_frame, text="Terminate", command=self.kill_pid).pack(side='left', padx=5)
        ttk.Button(self.action_frame, text="Refresh Processes", command=self.force_process_info_update).pack(side='left', padx=20)

        ttk.Label(self.action_frame, text="Set High Priority PID:").pack(side='left', padx=5)
        self.high_priority_pid_entry = ttk.Entry(self.action_frame, width=10)
        self.high_priority_pid_entry.pack(side='left')
        ttk.Button(self.action_frame, text="Add to High Priority", command=self.add_to_high_priority).pack(side='left', padx=5)

        self.alert_config_frame = ttk.LabelFrame(self.root, text="Alert & Auto-Kill Configuration", padding=10, style='Black.TLabelframe')
        self.alert_config_frame.pack(fill='x', pady=10)

        ttk.Label(self.alert_config_frame, text="CPU Threshold (%):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(self.alert_config_frame, textvariable=self.cpu_threshold, width=5).grid(row=0, column=1, padx=5, pady=5, sticky='e')

        ttk.Label(self.alert_config_frame, text="Memory Threshold (%):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(self.alert_config_frame, textvariable=self.mem_threshold, width=5).grid(row=1, column=1, padx=5, pady=5, sticky='e')

        ttk.Checkbutton(self.alert_config_frame, text="Enable Auto-Kill", variable=self.enable_auto_kill).grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='w')

        ttk.Label(self.alert_config_frame, text="Kill after").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(self.alert_config_frame, textvariable=self.violation_trigger, width=3).grid(row=3, column=1, padx=5, pady=5, sticky='e')
        ttk.Label(self.alert_config_frame, text="consecutive violations").grid(row=3, column=2, padx=5, pady=5, sticky='w')

    def create_process_tree(self, label_text):
        frame = ttk.Frame(self.process_frame)
        frame.pack(side='left', fill='both', expand=True, padx=10)

        ttk.Label(frame, text=label_text, font=('Segoe UI', 9, 'bold')).pack(anchor='w')
        tree = ttk.Treeview(frame, columns=("PID", "Name", "Usage", "Priority"), show='headings', height=6)
        tree.heading("PID", text="PID")
        tree.heading("Name", text="Process")
        tree.heading("Usage", text="Usage")
        tree.heading("Priority", text="Priority")
        tree.column("PID", width=60)
        tree.column("Name", width=180)
        tree.column("Usage", width=100)
        tree.column("Priority", width=80)
        tree.pack(fill='x')
        return tree

    def setup_plot(self):
        plt.close('all')
        self.fig, self.ax = plt.subplots(2, 2, figsize=(12, 6))
        self.fig.patch.set_facecolor('#1e1e1e')
        plt.subplots_adjust(hspace=0.5)

        titles = ["CPU Usage (%)", "Memory Usage (%)", "Network (MB/s)", "Disk (MB/s)"]
        self.lines = []

        for i, axis in enumerate(self.ax.flat):
            axis.set_title(titles[i], color='white')
            axis.set_xlim(0, 60)
            axis.set_facecolor('#2e2e2e')
            axis.tick_params(axis='x', colors='white')
            axis.tick_params(axis='y', colors='white')
            axis.spines['top'].set_color('white')
            axis.spines['bottom'].set_color('white')
            axis.spines['left'].set_color('white')
            axis.spines['right'].set_color('white')
            axis.xaxis.label.set_color('white')
            axis.yaxis.label.set_color('white')

            if i == 0:  # CPU plot
                axis.set_ylim(0, 100)
                core_lines = [axis.plot([], [], label=f'Core {j}')[0] for j in range(self.cpu_count)]
                self.lines.append(core_lines)
                self.ax[0][0].legend(loc='upper right', facecolor='#2e2e2e', edgecolor='white', labelcolor='white', fontsize='small')
            elif i == 1:  # Memory plot
                axis.set_ylim(0, 100)
                line, = axis.plot([], [], color='cyan')
                self.lines.append([line])
            else:  # Network and Disk plots
                axis.set_ylim(0, 1)
                line, = axis.plot([], [], color='lime' if i == 2 else 'yellow')
                self.lines.append([line])

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

    def update_plot(self, _):
        try:
            cpu_perc = psutil.cpu_percent(percpu=True)
            mem = psutil.virtual_memory()
            net = psutil.net_io_counters()
            disk = psutil.disk_io_counters()

            net_mbps = (net.bytes_recv + net.bytes_sent - self.last_net.bytes_recv - self.last_net.bytes_sent) / (1024 * 1024)
            disk_mbps = (
                (disk.read_bytes + disk.write_bytes) -
                (self.last_disk.read_bytes + self.last_disk.write_bytes)
            ) / (1024 * 1024)

            self.last_net, self.last_disk = net, disk

            if len(cpu_perc) != self.cpu_count:
                self.cpu_count = len(cpu_perc)
                self.cpu_data = [[] for _ in range(self.cpu_count)]

            for i, cpu in enumerate(cpu_perc):
                if i < len(self.cpu_data):
                    self.cpu_data[i].append(cpu)
                    self.cpu_data[i] = self.cpu_data[i][-60:]

            self.mem_data.append(mem.percent)
            self.net_data.append(net_mbps)
            self.disk_data.append(disk_mbps)

            self.mem_data = self.mem_data[-60:]
            self.net_data = self.net_data[-60:]
            self.disk_data = self.disk_data[-60:]


            x_vals = list(range(len(self.mem_data)))

            max_cpu_val = max(max(cpu) for cpu in self.cpu_data if cpu) if self.cpu_data else 0
            for i, line in enumerate(self.lines[0]):
                if i < len(self.cpu_data):
                    line.set_data(x_vals, self.cpu_data[i])
            self.ax[0][0].set_ylim(0, max(100, max_cpu_val + 10))

            self.lines[1][0].set_data(x_vals, self.mem_data)
            self.ax[0][1].set_ylim(0, max(100, max(self.mem_data) + 10) if self.mem_data else 0)

            self.lines[2][0].set_data(x_vals, self.net_data)
            if self.net_data:
                net_max = max(self.net_data)
                self.ax[1][0].set_ylim(0, net_max * 1.5 if net_max > 1 else 1)  # minimum 1 MB/s range

            self.lines[3][0].set_data(x_vals, self.disk_data)
            if self.disk_data:
                disk_max = max(self.disk_data)
                self.ax[1][1].set_ylim(0, disk_max * 1.5 if disk_max > 1 else 1)  # minimum 1 MB/s range

            for ax in self.ax.flat:
                ax.set_xlim(0, 60)

            self.fig.canvas.draw_idle()

            avg_cpu = sum(cpu_perc) / len(cpu_perc) if cpu_perc else 0
            self.update_info_labels(cpu_perc, mem.percent, disk_mbps, net_mbps)
            self.check_alerts(avg_cpu, mem.percent)

        except Exception as e:
            print(f"Error in update_plot: {e}")

    def update_info_labels(self, cpu_perc, mem_percent, disk_mbps, net_mbps):
        try:
            cpu_text = f"CPU Usage: {sum(cpu_perc)/len(cpu_perc):.2f}%"
            mem_text = f"Memory Usage: {mem_percent:.2f}%"
            disk_text=f"Disk Usage: {disk_mbps:.2f} MB/s"
            net_text=f"Network: {net_mbps:.2f} MB/s"
            running_procs = f"Running Processes: {len(psutil.pids())}"
            uptime_seconds = (datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds()
            uptime_text = f"System Uptime: {int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m"
            battery = psutil.sensors_battery()
            if battery:
                battery_text = f"Battery: {battery.percent}% {'Charging' if battery.power_plugged else 'Not Charging'}"
            else:
                battery_text = "Battery: N/A"

            texts = [cpu_text, mem_text, disk_text, net_text, running_procs, uptime_text, battery_text]

            for label, text in zip(self.info_labels, texts):
                label.config(text=text)

        except Exception as e:
            print(f"Error updating info labels: {e}")

    def start_process_update_thread(self):
        if self._process_update_thread is None or not self._process_update_thread.is_alive():
            self._stop_process_update_thread.clear()
            self._process_update_thread = threading.Thread(target=self._update_processes_periodically, daemon=True)
            self._process_update_thread.start()

    def _update_processes_periodically(self):
        while not self._stop_process_update_thread.is_set():
            try:
                processes_data = []
                for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        p_info = p.info
                        if p_info['name'] and p_info['name'].lower() not in {'system idle process', 'system'}:
                            processes_data.append(p_info)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self.last_fetched_processes_data = processes_data
                self.root.after(0, self._apply_process_updates_to_ui)
                self.root.after(0, self.monitor_and_kill_processes)

            except Exception as e:
                print(f"Error in background process update thread: {e}")

            self._stop_process_update_thread.wait(self.process_update_interval_sec)

    def _apply_process_updates_to_ui(self):
        try:
            new_process_info_cache = {}
            for proc_info in self.last_fetched_processes_data:
                pid = proc_info['pid']
                name = proc_info['name']
                cpu_percent = proc_info['cpu_percent']
                mem_percent = proc_info['memory_percent']

                priority = "Normal"
                if pid in self.high_priority_processes:
                    priority = "High"
                elif name in self.system_critical_processes or pid == 0:
                    priority = "Critical (System)"

                new_process_info_cache[pid] = {
                    'name': name,
                    'cpu_percent': cpu_percent,
                    'mem_percent': mem_percent,
                    'priority': priority
                }

            self._update_treeview(self.cpu_tree, new_process_info_cache, 'cpu_percent')
            self._update_treeview(self.mem_tree, new_process_info_cache, 'mem_percent')

            self.process_info_cache = new_process_info_cache

        except Exception as e:
            print(f"Error applying process updates to UI: {e}")

    def _update_treeview(self, tree, current_process_data, sort_key):
        existing_items = {tree.item(item_id)['values'][0]: item_id for item_id in tree.get_children()}

        display_data = []
        for pid, p_info in current_process_data.items():
            display_data.append({
                'pid': pid,
                'name': p_info['name'],
                'cpu_percent': p_info['cpu_percent'],
                'mem_percent': p_info['mem_percent'],
                'priority': p_info['priority']
            })

        sorted_display_data = sorted(display_data, key=lambda x: x[sort_key], reverse=True)[:5]
        current_top_pids = {proc['pid'] for proc in sorted_display_data}

        for pid, item_id in list(existing_items.items()):
            if pid not in current_top_pids:
                tree.delete(item_id)
                existing_items.pop(pid, None)

        for proc in sorted_display_data:
            pid = proc['pid']
            name = proc['name']
            usage_str = f"{proc[sort_key]:.2f}%"
            priority = proc['priority']

            if pid in existing_items:
                tree.item(existing_items[pid], values=(pid, name, usage_str, priority))
            else:
                tree.insert('', 'end', values=(pid, name, usage_str, priority))

        self._sort_treeview(tree, sort_key)

    def _sort_treeview(self, tree, sort_key):
        l = [(tree.set(k, "Usage"), k) for k in tree.get_children('')]
        l.sort(key=lambda x: float(x[0].replace('%', '')), reverse=True)

        for index, (val, k) in enumerate(l):
            tree.move(k, '', index)

    def force_process_info_update(self):
        self._stop_process_update_thread.set()
        self._stop_process_update_thread.clear()

    def add_to_high_priority(self):
        pid_str = self.high_priority_pid_entry.get()
        if pid_str.isdigit():
            pid = int(pid_str)
            try:
                p = psutil.Process(pid)
                if p.name() in self.system_critical_processes or pid == 0:
                    messagebox.showerror("Error", f"Cannot add critical system process '{p.name()}' (PID {pid}) to high priority.")
                    return

                self.high_priority_processes.add(pid)
                messagebox.showinfo("Success", f"Process {pid} ({p.name()}) added to high priority. It will be less likely to be auto-killed.")
                self.force_process_info_update()
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", f"No process found with PID {pid}.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not add PID {pid} to high priority: {e}")
        else:
            messagebox.showwarning("Invalid PID", "Please enter a valid PID for high priority.")
        self.high_priority_pid_entry.delete(0, tk.END)

    def kill_pid(self):
        pid_str = self.pid_entry.get()
        if not pid_str.isdigit():
            messagebox.showwarning("Invalid PID", "Please enter a valid numeric PID.")
            self.pid_entry.delete(0, tk.END)
            return

        pid = int(pid_str)

        try:
            p = psutil.Process(pid)
            pname = p.name()

            # Kill child processes first (if any)
            children = p.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except Exception as e:
                    print(f"Error terminating child PID {child.pid}: {e}")

            # Terminate main process
            p.terminate()

            # Wait for clean shutdown
            gone, alive = psutil.wait_procs([p] + children, timeout=3)

            if alive:
                response = messagebox.askyesno("Force Kill?", f"Some processes didn't exit. Force kill '{pname}' (PID {pid}) and children?")
                if response:
                    for proc in alive:
                        try:
                            proc.kill()
                        except Exception as e:
                            print(f"Error force killing PID {proc.pid}: {e}")
                    psutil.wait_procs(alive, timeout=2)
                    messagebox.showinfo("Success", f"Force-killed '{pname}' (PID {pid}) and its children.")
                else:
                    messagebox.showinfo("Partial Termination", f"'{pname}' was not completely terminated.")

            else:
                messagebox.showinfo("Success", f"Successfully terminated '{pname}' (PID {pid}) and its children.")

            self.force_process_info_update()

        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"No process found with PID {pid}.")
        except psutil.AccessDenied:
            messagebox.showerror("Access Denied", f"Permission denied to terminate PID {pid}. Run as administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not terminate PID {pid}: {e}")

        self.pid_entry.delete(0, tk.END)

    def check_alerts(self, cpu_usage, mem_usage):
        now = datetime.now()
        if self.last_alert_time is None or (now - self.last_alert_time) > self.alert_cooldown:
            alert_triggered = False
            if cpu_usage > self.cpu_threshold.get():
                messagebox.showwarning("High CPU Usage", f"CPU usage is above {self.cpu_threshold.get()}%. Current usage: {cpu_usage:.2f}%")
                alert_triggered = True
            if mem_usage > self.mem_threshold.get():
                messagebox.showwarning("High Memory Usage", f"Memory usage is above {self.mem_threshold.get()}%. Current usage: {mem_usage:.2f}%")
                alert_triggered = True

            if alert_triggered:
                self.last_alert_time = now

    def monitor_and_kill_processes(self):
        if not self.enable_auto_kill.get():
            return

        now = datetime.now()
        candidate_processes = []

        for proc_info in self.last_fetched_processes_data:
            try:
                pid = proc_info['pid']
                name = proc_info['name']
                cpu_percent = proc_info['cpu_percent']
                mem_percent = proc_info['memory_percent']

                if pid in self.auto_killed_processes and (now - self.last_kill_time[pid]) < self.kill_cooldown:
                    continue
                if name in self.system_critical_processes or pid == 0:
                    continue
                if pid in self.high_priority_processes:
                    continue

                violation = False
                reason = ""

                if cpu_percent > self.cpu_threshold.get():
                    violation = True
                    reason = "CPU"
                elif mem_percent > self.mem_threshold.get():
                    violation = True
                    reason = "Memory"

                if violation:
                    self.process_violation_counts[pid][reason.lower()] += 1
                    self.process_violation_counts[pid]['last_violation'] = now

                    if self.process_violation_counts[pid][reason.lower()] >= self.violation_trigger.get():
                        candidate_processes.append({
                            'pid': pid,
                            'name': name,
                            'cpu_percent': cpu_percent,
                            'mem_percent': mem_percent,
                            'reason': reason
                        })
                else:
                    self.process_violation_counts[pid]['cpu'] = 0
                    self.process_violation_counts[pid]['mem'] = 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                if proc_info and proc_info['pid'] in self.process_violation_counts:
                    del self.process_violation_counts[proc_info['pid']]
                continue
            except Exception as e:
                print(f"Error processing a process in monitor_and_kill_processes loop: {e}")

        def get_kill_priority(proc_data):
            if proc_data['cpu_percent'] > self.cpu_threshold.get() and \
               proc_data['mem_percent'] > self.mem_threshold.get():
                return 0
            if proc_data['cpu_percent'] > self.cpu_threshold.get() + 10:
                return 1
            if proc_data['mem_percent'] > self.mem_threshold.get() + 10:
                return 2
            if proc_data['reason'] == "CPU":
                return 3
            elif proc_data['reason'] == "Memory":
                return 4
            return 5

        candidate_processes.sort(key=get_kill_priority)

        for proc_to_kill in candidate_processes:
            pid = proc_to_kill['pid']
            name = proc_to_kill['name']
            reason = proc_to_kill['reason']

            try:
                p = psutil.Process(pid)
                current_cpu = p.cpu_percent(interval=None)
                current_mem = p.memory_percent()

                if (reason == "CPU" and current_cpu <= self.cpu_threshold.get() * 0.95) or \
                   (reason == "Memory" and current_mem <= self.mem_threshold.get() * 0.95):
                    self.process_violation_counts[pid]['cpu'] = 0
                    self.process_violation_counts[pid]['mem'] = 0
                    continue

                if pid in self.auto_killed_processes and (now - self.last_kill_time[pid]) < self.kill_cooldown:
                    continue

                if name in self.system_critical_processes or pid == 0:
                    continue

                if pid in self.high_priority_processes:
                    continue

                p.terminate()
                self.auto_killed_processes.add(pid)
                self.last_kill_time[pid] = now
                if pid not in self.suppress_warnings:
                    messagebox.showwarning("Process Killed", f"Process '{name}' (PID {pid}) killed due to excessive {reason} usage and determined low priority.")
                    print(f"Process '{name}' (PID {pid}) killed due to excessive {reason} usage and determined low priority.")
                    self.suppress_warnings.add(pid)

                self.process_violation_counts[pid]['cpu'] = 0
                self.process_violation_counts[pid]['mem'] = 0

                current_total_cpu = psutil.cpu_percent()
                current_total_mem = psutil.virtual_memory().percent
                if current_total_cpu <= self.cpu_threshold.get() * 0.9 and current_total_mem <= self.mem_threshold.get() * 0.9:
                    print("System resources recovered after killing a process. Stopping further kills this cycle.")
                    break

            except psutil.NoSuchProcess:
                if pid in self.process_violation_counts:
                    del self.process_violation_counts[pid]
                continue
            except Exception as e:
                messagebox.showerror("Error", f"Failed to kill process '{name}' (PID {pid}): {e}")
                print(f"Failed to kill process '{name}' (PID {pid}): {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemMonitorApp(root)
    root.mainloop()