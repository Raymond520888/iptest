import sys
import os
import csv
import json
import time
import socket
import ipaddress
import threading
import subprocess
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

import requests
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from tkinter.scrolledtext import ScrolledText

# ========== 确定基础目录 ==========
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ========== 常量 ==========
PREFIX_DB_V4_PATH = os.path.join(BASE_DIR, "asn_prefixes_v4.json")
PREFIX_DB_V6_PATH = os.path.join(BASE_DIR, "asn_prefixes_v6.json")
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
TARGET_ASNS = ["AS4809", "AS4812", "AS9929", "AS58807", "AS58453"]
TRACE_TIMEOUT = 120
MAX_HOPS = 30
DEFAULT_THREADS = 128
MAX_CONCURRENT = 128
CSV_HEADERS = ["IP/域名", "端口", "归属运营商", "线路类型", "命中ASN", "延迟(ms)"]

ROUTE_RULES = [
    ("中国电信", "CN2 GIA/GT", ["AS4809"]),
    ("中国电信", "CN2", ["AS4812"]),
    ("中国联通", "CUII（A网）", ["AS9929"]),
    ("中国移动", "CMIN2", ["AS58807"]),
    ("中国移动", "CMI", ["AS58453"]),
]

# ========== 核心逻辑 ==========
def fetch_prefixes(asn, starttime, ip_version):
    resp = requests.get(
        RIPESTAT_URL,
        params={"resource": asn, "starttime": starttime},
        timeout=90,
    )
    resp.raise_for_status()
    prefixes = resp.json().get("data", {}).get("prefixes", [])
    cidrs = []
    for item in prefixes:
        prefix = item.get("prefix")
        if not prefix:
            continue
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if net.version == ip_version:
            cidrs.append(prefix)
    return cidrs

def update_prefix_db_all():
    today = datetime.now().date()
    yesterday = today - timedelta(days=1)
    result_v4 = {}
    result_v6 = {}
    for asn in TARGET_ASNS:
        # IPv4
        try:
            cidrs = fetch_prefixes(asn, today.strftime("%Y-%m-%d"), 4)
            if not cidrs:
                cidrs = fetch_prefixes(asn, yesterday.strftime("%Y-%m-%d"), 4)
        except requests.RequestException as e:
            print(f"[-] {asn} IPv4 拉取失败: {e}")
            cidrs = []
        result_v4[asn] = cidrs

        # IPv6
        try:
            cidrs = fetch_prefixes(asn, today.strftime("%Y-%m-%d"), 6)
            if not cidrs:
                cidrs = fetch_prefixes(asn, yesterday.strftime("%Y-%m-%d"), 6)
        except requests.RequestException as e:
            print(f"[-] {asn} IPv6 拉取失败: {e}")
            cidrs = []
        result_v6[asn] = cidrs

    with open(PREFIX_DB_V4_PATH, "w", encoding="utf-8") as f:
        json.dump(result_v4, f, ensure_ascii=False, indent=2)
    with open(PREFIX_DB_V6_PATH, "w", encoding="utf-8") as f:
        json.dump(result_v6, f, ensure_ascii=False, indent=2)
    return result_v4, result_v6

class ASNMatcher:
    def __init__(self, prefix_map):
        self._buckets = {4: {}, 6: {}}
        self._prefixlens = {4: set(), 6: set()}
        for asn, cidrs in prefix_map.items():
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                ver = net.version
                plen = net.prefixlen
                self._buckets[ver].setdefault(plen, {})[int(net.network_address)] = asn
                self._prefixlens[ver].add(plen)
        self._sorted_lens = {
            ver: sorted(lens, reverse=True) for ver, lens in self._prefixlens.items()
        }

    def match(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        ver = ip.version
        buckets = self._buckets[ver]
        ip_int = int(ip)
        maxbits = 32 if ver == 4 else 128
        for plen in self._sorted_lens[ver]:
            mask = (~0) << (maxbits - plen)
            network_int = ip_int & mask & ((1 << maxbits) - 1)
            asn = buckets[plen].get(network_int)
            if asn:
                return asn
        return None

def load_asn_matcher():
    prefix_map = {}
    loaded_any = False
    for file_path in [PREFIX_DB_V4_PATH, PREFIX_DB_V6_PATH]:
        if not os.path.isfile(file_path):
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue
            for asn, cidrs in data.items():
                if asn not in prefix_map:
                    prefix_map[asn] = []
                prefix_map[asn].extend(cidrs)
            loaded_any = True
        except (json.JSONDecodeError, OSError):
            continue
    if not loaded_any:
        return None
    return ASNMatcher(prefix_map)

def analyze_route(hit_asns):
    asn_set = set(hit_asns)
    asn_str = "/".join(hit_asns) if hit_asns else "无"
    matched = [(isp, line_type)
               for isp, line_type, keywords in ROUTE_RULES
               if any(kw in asn_set for kw in keywords)]
    if matched:
        return ("/".join(dict.fromkeys(m[0] for m in matched)),
                " / ".join(dict.fromkeys(m[1] for m in matched)),
                asn_str)
    return "非精品线路", "普通线路/骨干网", asn_str

def parse_target_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None, None
    country = ""
    if '#' in line:
        parts = line.split('#', 1)
        line = parts[0].strip()
        country = parts[1].strip()
    ip_part = line
    port = ""
    if ':' in ip_part:
        match = re.search(r'[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+|'
                          r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_part)
        if match:
            ip = match.group(0)
            rest = ip_part.replace(ip, '').strip()
            if rest.startswith(':'):
                port = rest[1:].strip()
                if not port.isdigit():
                    port = ""
        else:
            ip = ip_part
    else:
        ip = ip_part
    return ip, port, country

def extract_target(line):
    ip, _, _ = parse_target_line(line)
    return ip

# ========== ping 3 次取平均，返回整数 ==========
def measure_ping_delay(ip, timeout_sec=3):
    try:
        timeout_ms = int(timeout_sec * 1000)
        cmd = ["ping", "-n", "3", "-w", str(timeout_ms), ip]
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='gbk',
            errors='ignore',
            creationflags=creation_flags
        )
        stdout, stderr = proc.communicate(timeout=timeout_sec * 3 + 2)
        output = stdout + stderr
        matches = re.findall(r'[时间|time][=:]\s*([\d.]+)\s*ms', output, re.IGNORECASE)
        if matches:
            delays = [float(m) for m in matches]
            avg = sum(delays) / len(delays)
            return round(avg)
    except Exception:
        pass
    return None

# ========== GUI ==========
class NextTraceGUI:
    def __init__(self, root):
        self.root = root
        root.title("NextTrace 批量线路测试工具 - by Dehya&Raymond")
        root.geometry("900x760")          # 窗口宽度调整为 900
        root.resizable(True, True)

        self.themes = {
            'light': {
                'bg': '#e8f5e9',
                'fg': '#1a2e1a',
                'entry_bg': '#c8e6c9',
                'entry_fg': '#1a2e1a',
                'text_bg': '#c8e6c9',
                'text_fg': '#1a2e1a',
                'button_bg': '#a5d6a7',
                'button_fg': '#1a2e1a',
                'status_bg': '#e8f5e9',
                'status_fg': '#1a2e1a',
                'cursor': '#1a2e1a',
            },
            'dark': {
                'bg': '#2b2b2b',
                'fg': '#ffffff',
                'entry_bg': '#3c3c3c',
                'entry_fg': '#ffffff',
                'text_bg': '#1e1e1e',
                'text_fg': '#d4d4d4',
                'button_bg': '#3c3c3c',
                'button_fg': '#ffffff',
                'status_bg': '#2b2b2b',
                'status_fg': '#ffffff',
                'cursor': '#ffffff',
            }
        }
        self.current_theme = 'light'

        self.concurrent_var = tk.IntVar(value=DEFAULT_THREADS)
        self.enable_ping_var = tk.BooleanVar(value=False)
        self.is_running = False
        self.stop_flag = False
        self.executor = None
        self.futures = []
        self.results = []
        self.total_tasks = 0
        self.completed = 0
        self.running_processes = []
        self.process_lock = threading.Lock()
        self._stop_event = threading.Event()

        self.exe_path = self._get_exe_path()
        self.matcher = None

        self.create_widgets()
        self.apply_theme(self.current_theme)
        self.disable_all_buttons()
        self.after_init_check()

    def _get_exe_path(self):
        bundled = resource_path("nexttrace.exe")
        if os.path.isfile(bundled):
            return bundled
        local = os.path.join(BASE_DIR, "nexttrace.exe")
        if os.path.isfile(local):
            return local
        return ""

    def disable_all_buttons(self):
        self.btn_clear_targets.config(state=tk.DISABLED)
        self.btn_update_prefix.config(state=tk.DISABLED)
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.DISABLED)

    def enable_operation_buttons(self):
        self.btn_clear_targets.config(state=tk.NORMAL)
        self.btn_update_prefix.config(state=tk.NORMAL)
        self.btn_start.config(state=tk.NORMAL)

    def after_init_check(self):
        self.log("[+] 正在后台强制更新前缀表 (IPv4+IPv6)，请稍候...")
        self.matcher = load_asn_matcher()
        if self.matcher is None:
            self.log("[-] 当前无有效前缀表，更新完成后将自动加载")
        else:
            self.log("[+] 使用现有前缀表（更新完成后将自动切换）")

        def auto_update():
            try:
                result_v4, result_v6 = update_prefix_db_all()
                self.root.after(0, self._on_force_update_done, result_v4, result_v6)
            except Exception as e:
                self.root.after(0, self._on_force_update_error, str(e))
        threading.Thread(target=auto_update, daemon=True).start()

    def _on_force_update_done(self, result_v4, result_v6):
        self.matcher = load_asn_matcher()
        total_v4 = sum(len(v) for v in result_v4.values())
        total_v6 = sum(len(v) for v in result_v6.values())
        self.log(f"[+] 强制更新完成：IPv4 {total_v4} 条，IPv6 {total_v6} 条")
        if self.matcher is None:
            self.log("[-] 更新后加载失败，请手动点击'更新前缀表'修复。")
        else:
            self.log("[+] 前缀表已更新并加载成功")
        self.enable_operation_buttons()

    def _on_force_update_error(self, err):
        self.log(f"[-] 强制更新失败：{err}")
        self.matcher = load_asn_matcher()
        if self.matcher is None:
            self.log("[-] 无法加载任何前缀表，请检查网络或手动更新")
        else:
            self.log("[+] 使用已加载的前缀表（旧数据）")
        self.enable_operation_buttons()

    def create_widgets(self):
        self.main_frame = tk.Frame(self.root, padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.author_label = tk.Label(self.main_frame, text="by Dehya&Raymond",
                                     font=("Arial", 9, "italic"), anchor='e')
        self.author_label.grid(row=0, column=0, columnspan=6, sticky='e', pady=(0, 5))

        self.lbl_hint = tk.Label(self.main_frame, text="输入目标（每行一个，支持 IP:端口#国家，自动提取 IP/域名）",
                                 font=("Arial", 10))
        self.lbl_hint.grid(row=1, column=0, columnspan=6, sticky=tk.W, pady=5)

        self.target_text = ScrolledText(self.main_frame, height=12, wrap=tk.NONE, font=("Consolas", 9))
        self.target_text.grid(row=2, column=0, columnspan=6, padx=5, pady=5, sticky=tk.NSEW)

        self.control_frame = tk.Frame(self.main_frame)
        self.control_frame.grid(row=3, column=0, columnspan=6, pady=10, sticky=tk.EW)

        tk.Label(self.control_frame, text="并发:").pack(side=tk.LEFT, padx=5)
        self.spin_concurrent = ttk.Spinbox(self.control_frame, from_=1, to=MAX_CONCURRENT,
                                           textvariable=self.concurrent_var, width=6)
        self.spin_concurrent.pack(side=tk.LEFT, padx=5)

        self.chk_ping = tk.Checkbutton(self.control_frame, text="启用延迟测试",
                                       variable=self.enable_ping_var)
        self.chk_ping.pack(side=tk.LEFT, padx=10)

        self.btn_clear_targets = tk.Button(self.control_frame, text="清空目标",
                                           command=self.clear_targets, relief=tk.RAISED)
        self.btn_clear_targets.pack(side=tk.LEFT, padx=10)

        self.btn_update_prefix = tk.Button(self.control_frame, text="更新前缀表 (IPv4+IPv6)",
                                           command=self.update_prefix_table, relief=tk.RAISED)
        self.btn_update_prefix.pack(side=tk.LEFT, padx=10)

        self.btn_start = tk.Button(self.control_frame, text="开始测试",
                                   command=self.start_test, relief=tk.RAISED)
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.btn_stop = tk.Button(self.control_frame, text="终止测试",
                                  command=self.stop_test, state=tk.DISABLED, relief=tk.RAISED)
        self.btn_stop.pack(side=tk.LEFT, padx=10)

        # 固定宽度 10，使按钮大小一致
        self.btn_theme = tk.Button(self.control_frame, text="🌙 黑夜模式",
                                   command=self.toggle_theme, relief=tk.RAISED, width=10)
        self.btn_theme.pack(side=tk.LEFT, padx=10)

        self.status_label = tk.Label(self.control_frame, text="就绪")
        self.status_label.pack(side=tk.RIGHT, padx=10, expand=True)

        log_label_frame = tk.Frame(self.main_frame)
        log_label_frame.grid(row=4, column=0, columnspan=6, sticky=tk.W+tk.E, pady=5)
        tk.Label(log_label_frame, text="运行日志:").pack(side=tk.LEFT)
        self.btn_clear_log = tk.Button(log_label_frame, text="清空日志",
                                       command=self.clear_log, relief=tk.RAISED)
        self.btn_clear_log.pack(side=tk.RIGHT)

        self.log_text = ScrolledText(self.main_frame, height=18, wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.grid(row=5, column=0, columnspan=6, padx=5, pady=5, sticky=tk.NSEW)

        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(2, weight=1)
        self.main_frame.rowconfigure(5, weight=2)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def toggle_theme(self):
        new_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.current_theme = new_theme
        self.apply_theme(new_theme)
        self.btn_theme.config(text="☀️ 白天模式" if new_theme == 'dark' else "🌙 黑夜模式")

    def apply_theme(self, theme):
        colors = self.themes[theme]
        self.root.configure(bg=colors['bg'])
        self.main_frame.configure(bg=colors['bg'])
        self.control_frame.configure(bg=colors['bg'])
        self.author_label.configure(bg=colors['bg'], fg=colors['fg'])
        for widget in [self.lbl_hint, self.status_label]:
            widget.configure(bg=colors['bg'], fg=colors['fg'])
        self.chk_ping.configure(bg=colors['bg'], fg=colors['fg'],
                                selectcolor=colors['button_bg'])
        for child in self.main_frame.grid_slaves(row=4):
            if isinstance(child, tk.Frame):
                child.configure(bg=colors['bg'])
                for sub in child.winfo_children():
                    if isinstance(sub, tk.Label):
                        sub.configure(bg=colors['bg'], fg=colors['fg'])
                    elif isinstance(sub, tk.Button):
                        sub.configure(bg=colors['button_bg'], fg=colors['button_fg'],
                                      activebackground=colors['button_bg'],
                                      activeforeground=colors['button_fg'])
        for btn in [self.btn_clear_targets, self.btn_update_prefix, self.btn_start,
                    self.btn_stop, self.btn_clear_log, self.btn_theme]:
            btn.configure(bg=colors['button_bg'], fg=colors['button_fg'],
                          activebackground=colors['button_bg'],
                          activeforeground=colors['button_fg'])
        self.target_text.configure(bg=colors['entry_bg'], fg=colors['entry_fg'],
                                   insertbackground=colors['cursor'])
        self.log_text.configure(bg=colors['text_bg'], fg=colors['text_fg'],
                                insertbackground=colors['cursor'])

    def clear_targets(self):
        self.target_text.delete(1.0, tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def log(self, msg, end="\n"):
        self.log_text.insert(tk.END, msg + end)
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def update_status(self, text):
        self.status_label.config(text=text)

    def update_prefix_table(self):
        if self.is_running:
            messagebox.showinfo("提示", "测试正在进行，请先停止")
            return
        self.btn_update_prefix.config(state=tk.DISABLED)
        self.btn_clear_targets.config(state=tk.DISABLED)
        self.btn_start.config(state=tk.DISABLED)
        self.log("[+] 开始手动更新所有前缀表 (IPv4 + IPv6)...")
        def update_task():
            try:
                result_v4, result_v6 = update_prefix_db_all()
                self.root.after(0, self._on_manual_update_done, result_v4, result_v6)
            except Exception as e:
                self.root.after(0, self._on_manual_update_error, str(e))
        threading.Thread(target=update_task, daemon=True).start()

    def _on_manual_update_done(self, result_v4, result_v6):
        self.btn_update_prefix.config(state=tk.NORMAL)
        self.btn_clear_targets.config(state=tk.NORMAL)
        self.btn_start.config(state=tk.NORMAL)
        self.matcher = load_asn_matcher()
        total_v4 = sum(len(v) for v in result_v4.values())
        total_v6 = sum(len(v) for v in result_v6.values())
        self.log(f"[+] 手动更新完成：IPv4 {total_v4} 条，IPv6 {total_v6} 条")
        messagebox.showinfo(
            "完成",
            f"前缀表更新成功！\n"
            f"IPv4 条数：{total_v4}\n"
            f"IPv6 条数：{total_v6}\n\n"
            f"文件保存在：\n{PREFIX_DB_V4_PATH}\n{PREFIX_DB_V6_PATH}"
        )

    def _on_manual_update_error(self, err):
        self.btn_update_prefix.config(state=tk.NORMAL)
        self.btn_clear_targets.config(state=tk.NORMAL)
        self.btn_start.config(state=tk.NORMAL)
        self.log(f"[-] 手动更新失败: {err}")
        messagebox.showerror("错误", f"更新失败：{err}")

    def start_test(self):
        if self.is_running:
            messagebox.showinfo("提示", "测试正在进行中")
            return
        if not self.exe_path or not os.path.isfile(self.exe_path):
            messagebox.showerror("错误", "未找到 nexttrace.exe，请确保文件存在")
            return
        if self.matcher is None:
            messagebox.showerror("错误", "未加载任何前缀表，请先更新")
            return

        concurrent = self.concurrent_var.get()
        if concurrent > MAX_CONCURRENT:
            concurrent = MAX_CONCURRENT
            self.concurrent_var.set(concurrent)
            messagebox.showwarning("提示", f"并发数已自动调整为最大值 {MAX_CONCURRENT}")

        raw_text = self.target_text.get(1.0, tk.END)
        targets = []
        for line in raw_text.splitlines():
            ip, port, country = parse_target_line(line)
            if ip:
                targets.append((ip, port, country))
        if not targets:
            messagebox.showerror("错误", "未输入有效目标")
            return

        self.stop_flag = False
        self._stop_event.clear()
        self.results = []
        self.completed = 0
        self.total_tasks = len(targets)
        self.running_processes.clear()

        self.log_text.delete(1.0, tk.END)
        self.log(f"[+] 加载 {self.total_tasks} 个目标，并发数 {concurrent}")
        self.log(f"[+] 结果将自动保存为 result_时间戳.txt（表格样式，实线边框）")
        if self.enable_ping_var.get():
            self.log("[+] 延迟测试已开启（ping 3次取平均，整数）")
        else:
            self.log("[+] 延迟测试已关闭，将显示 '未开启测试'")

        self.btn_start.config(state=tk.DISABLED, text="测试中...")
        self.btn_stop.config(state=tk.NORMAL)
        self.is_running = True
        self.update_status(f"总任务: {self.total_tasks}，已完成: 0")

        threading.Thread(target=self.run_batch, args=(targets,), daemon=True).start()

    def stop_test(self):
        if not self.is_running:
            return
        self.log("[-] 用户终止测试，正在停止...")
        self.stop_flag = True
        self._stop_event.set()

        with self.process_lock:
            for proc in self.running_processes:
                try:
                    if proc.poll() is None:
                        proc.terminate()
                except Exception:
                    pass
            self.running_processes.clear()

        if self.executor:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                self.executor.shutdown(wait=False)

        self.btn_stop.config(state=tk.DISABLED)

    def run_batch(self, targets):
        max_workers = self.concurrent_var.get()
        if max_workers > MAX_CONCURRENT:
            max_workers = MAX_CONCURRENT
            self.concurrent_var.set(max_workers)

        completed = 0
        total = len(targets)
        self.futures = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            self.executor = executor
            for idx, (ip, port, country) in enumerate(targets, 1):
                if self.stop_flag:
                    break
                future = executor.submit(self.test_one, ip, port, country, idx)
                self.futures.append(future)

            while self.futures:
                if self.stop_flag:
                    for f in self.futures:
                        f.cancel()
                    with self.process_lock:
                        for proc in self.running_processes:
                            try:
                                if proc.poll() is None:
                                    proc.terminate()
                            except Exception:
                                pass
                    break

                done, self.futures = wait(self.futures, timeout=0.5, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        result = future.result(timeout=0.1)
                    except Exception:
                        continue
                    else:
                        if result is not None:
                            self.results.append(result)
                            completed += 1
                            self.root.after(0, self._update_log, result, completed, total)
                            self.root.after(0, self.update_status, f"总任务: {total}，已完成: {completed}")

            for future in self.futures:
                if future.done():
                    try:
                        result = future.result(timeout=0.1)
                    except Exception:
                        continue
                    else:
                        if result is not None:
                            self.results.append(result)
                            completed += 1
                            self.root.after(0, self._update_log, result, completed, total)
                            self.root.after(0, self.update_status, f"总任务: {total}，已完成: {completed}")

        self.root.after(0, self.finish_test)

    def test_one(self, ip, port, country, idx):
        if self.stop_flag:
            return None
        if self.enable_ping_var.get():
            ping_delay = measure_ping_delay(ip, timeout_sec=3)
            if ping_delay is not None:
                delay_str = str(ping_delay)
            else:
                delay_str = "N/A"
        else:
            delay_str = "未开启测试"

        try:
            cmd = [self.exe_path, "--raw", "-d", "disable-geoip", "-n", "-C",
                   "-q", "1", "-m", str(MAX_HOPS), ip]
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=creation_flags
            )
            with self.process_lock:
                self.running_processes.append(proc)

            hit_asns = []
            hit_seen = set()
            interrupted = False
            timed_out = False

            def timeout_killer():
                nonlocal timed_out
                timed_out = True
                proc.kill()
            timer = threading.Timer(TRACE_TIMEOUT, timeout_killer)
            timer.start()

            try:
                for line in proc.stdout:
                    parts = line.strip().split("|")
                    if len(parts) < 2 or not parts[0].isdigit():
                        continue
                    hop_ip = parts[1]
                    if hop_ip == "*" or not hop_ip:
                        continue
                    asn = self.matcher.match(hop_ip)
                    if asn and asn not in hit_seen:
                        hit_seen.add(asn)
                        hit_asns.append(asn)
                        interrupted = True
                        proc.kill()
                        break
            finally:
                timer.cancel()
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                with self.process_lock:
                    if proc in self.running_processes:
                        self.running_processes.remove(proc)

            if timed_out and not interrupted:
                raise subprocess.TimeoutExpired(cmd, TRACE_TIMEOUT)

            isp, line_type, asn_str = analyze_route(hit_asns)
            return (ip, port, country, isp, line_type, asn_str, delay_str)
        except subprocess.TimeoutExpired:
            return (ip, port, country, "测试超时", "未知", "", delay_str)
        except Exception as e:
            return (ip, port, country, "测试异常", "未知", "", delay_str)

    def _update_log(self, result, completed, total):
        ip, port, country, isp, line_type, asn_str, delay = result
        target_display = ip
        if port:
            target_display += f":{port}"
        if country:
            target_display += f"#{country}"
        try:
            float(delay)
            delay_display = f"{delay}ms"
        except ValueError:
            delay_display = delay
        self.log(f"[{completed}/{total}] {target_display} → {isp} / {line_type} (ASN: {asn_str}) 延迟: {delay_display}")

    def finish_test(self):
        self.is_running = False
        self.btn_start.config(state=tk.NORMAL, text="开始测试")
        self.btn_stop.config(state=tk.DISABLED)
        self.update_status("测试完成" if not self.stop_flag else "已终止")

        if self.results:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"result_{timestamp}.txt"
            try:
                headers = ["IP/域名", "端口", "归属运营商", "线路类型", "命中ASN", "延迟(ms)"]
                rows = []
                for row in self.results:
                    ip, port, country, isp, line_type, asn_str, delay = row
                    ip_display = ip
                    if country:
                        ip_display += f"#{country}"
                    rows.append([ip_display, str(port), isp, line_type, asn_str, str(delay)])
                
                col_widths = [len(h) for h in headers]
                for r in rows:
                    for i, cell in enumerate(r):
                        col_widths[i] = max(col_widths[i], len(cell))
                
                def make_separator(char='-'):
                    return '+' + '+'.join(char * (w + 2) for w in col_widths) + '+'
                
                def format_row(row, align='left'):
                    cells = []
                    for i, cell in enumerate(row):
                        if align == 'right' and i in (1, 5):
                            cells.append(cell.rjust(col_widths[i]))
                        else:
                            cells.append(cell.ljust(col_widths[i]))
                    return '| ' + ' | '.join(cells) + ' |'
                
                with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                    f.write(make_separator() + "\n")
                    f.write(format_row(headers) + "\n")
                    f.write(make_separator('=') + "\n")
                    for r in rows:
                        f.write(format_row(r, align='right') + "\n")
                    f.write(make_separator() + "\n")
                
                self.log(f"[+] 结果已保存至: {os.path.abspath(filename)} (实线表格)")
            except Exception as e:
                self.log(f"[-] 保存结果文件失败: {str(e)}")
        else:
            self.log("[-] 无有效结果")

        self.executor = None
        self.futures.clear()
        self.running_processes.clear()

    def on_closing(self):
        if self.is_running:
            if not messagebox.askokcancel("退出", "测试仍在进行，确定退出吗？"):
                return
            self.stop_flag = True
        self.root.destroy()

# ========== 主入口 ==========
if __name__ == "__main__":
    try:
        import requests
    except ImportError:
        print("错误: 缺少 requests 模块，请执行 pip install requests 安装")
        sys.exit(1)
    root = tk.Tk()
    app = NextTraceGUI(root)
    root.mainloop()