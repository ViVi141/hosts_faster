#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hosts optimization tool GUI version.

This module provides a graphical user interface for testing different IP addresses
of ar-gcp-cdn.bistudio.com and selecting the optimal IP to update the hosts file.
"""

import json
import os
import queue
import sys
import threading
import time
from typing import Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from hosts_optimizer import HostsOptimizer

try:
    from hosts_optimizer_true_parallel import TrueParallelOptimizerAdapter
    TRUE_PARALLEL_AVAILABLE = True
except ImportError:
    TRUE_PARALLEL_AVAILABLE = False
    print("警告: 并行模块不可用，请安装 aiohttp: pip install aiohttp")

# Check administrator privileges
try:
    from admin_check import check_admin_privileges
    check_admin_privileges()
except ImportError:
    print("警告: 无法导入管理员权限检查模块")
    print("程序可能无法修改hosts文件")


class HostsOptimizerGUI:
    """Hosts optimization tool GUI interface.
    
    This class provides a graphical user interface for the hosts optimization tool,
    allowing users to test different IP addresses and update their hosts file.
    """
    
    def __init__(self) -> None:
        """Initialize the GUI application."""
        self.root = tk.Tk()
        self.root.title("Arma Reforger 创意工坊修复工具 - ar-gcp-cdn.bistudio.com")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Set icon if available
        try:
            self.root.iconbitmap("favicon.ico")
        except (tk.TclError, OSError):
            pass
        
        # Initialize variables
        self.optimizer: Optional[HostsOptimizer] = None
        self.is_running: bool = False
        self.test_results: List[Dict] = []
        self.log_queue: queue.Queue = queue.Queue()
        
        # Progress tracking
        self.total_ips: int = 0
        self.tested_ips: int = 0
        self.current_phase: str = ""
        self.start_time: Optional[float] = None
        self.estimated_time: float = 0.0
        
        # Create interface
        self._create_widgets()
        self._setup_layout()
        
        # Start log updates
        self._update_log()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def _create_widgets(self) -> None:
        """Create GUI components."""
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        
        # Title labels
        self.title_label = ttk.Label(
            self.main_frame,
            text="Arma Reforger 创意工坊修复工具",
            font=("Arial", 16, "bold")
        )
        self.domain_label = ttk.Label(
            self.main_frame,
            text="目标域名: ar-gcp-cdn.bistudio.com",
            font=("Arial", 12)
        )
        
        # Control buttons frame
        self.control_frame = ttk.Frame(self.main_frame)
        
        # Buttons
        self.start_button = ttk.Button(
            self.control_frame,
            text="🚀 开始测试",
            command=self.start_test,
            style="Accent.TButton"
        )
        self.stop_button = ttk.Button(
            self.control_frame,
            text="停止测试",
            command=self.stop_test,
            state="disabled"
        )
        self.update_hosts_button = ttk.Button(
            self.control_frame,
            text="更新 Hosts",
            command=self.update_hosts,
            state="disabled"
        )
        self.config_button = ttk.Button(
            self.control_frame,
            text="配置",
            command=self.show_config
        )
        self.about_button = ttk.Button(
            self.control_frame,
            text="关于",
            command=self.show_about
        )
        
        # Progress bar
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_label = ttk.Label(self.progress_frame, text="就绪")
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            mode='determinate',
            length=400
        )
        self.progress_text = ttk.Label(self.progress_frame, text="", font=("Arial", 9))
        
        # Results frame
        self.results_frame = ttk.LabelFrame(self.main_frame, text="测试结果", padding="5")
        
        # Results statistics
        self.stats_frame = ttk.Frame(self.results_frame)
        self.stats_label = ttk.Label(self.stats_frame, text="", font=("Arial", 9))
        
        # Quick preview button
        self.preview_button = ttk.Button(
            self.stats_frame,
            text="快速预览",
            command=self.show_quick_preview,
            state="disabled"
        )
        
        # 结果树形视图
        self.results_tree = ttk.Treeview(
            self.results_frame,
            columns=("ip", "ping", "http", "https", "ssl", "stability", "health", "score"),
            show="headings",
            height=8
        )
        
        # 设置列标题
        self.results_tree.heading("ip", text="IP 地址")
        self.results_tree.heading("ping", text="Ping 延迟")
        self.results_tree.heading("http", text="HTTP 延迟")
        self.results_tree.heading("https", text="HTTPS 延迟")
        self.results_tree.heading("ssl", text="SSL 状态")
        self.results_tree.heading("stability", text="稳定性")
        self.results_tree.heading("health", text="健康等级")
        self.results_tree.heading("score", text="综合评分")
        
        # 设置列宽
        self.results_tree.column("ip", width=120)
        self.results_tree.column("ping", width=80)
        self.results_tree.column("http", width=80)
        self.results_tree.column("https", width=80)
        self.results_tree.column("ssl", width=80)
        self.results_tree.column("stability", width=80)
        self.results_tree.column("health", width=80)
        self.results_tree.column("score", width=100)
        
        # 结果滚动条
        self.results_scrollbar = ttk.Scrollbar(
            self.results_frame, 
            orient="vertical", 
            command=self.results_tree.yview
        )
        self.results_tree.configure(yscrollcommand=self.results_scrollbar.set)
        
        # 日志框架
        self.log_frame = ttk.LabelFrame(self.main_frame, text="运行日志", padding="5")
        
        # 日志类型选择
        self.log_type_frame = ttk.Frame(self.log_frame)
        self.log_type_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.log_type_var = tk.StringVar(value="simple")
        ttk.Radiobutton(self.log_type_frame, text="简易日志", variable=self.log_type_var, 
                       value="simple", command=self.switch_log_type).grid(row=0, column=0, padx=(0, 10))
        ttk.Radiobutton(self.log_type_frame, text="详细日志", variable=self.log_type_var, 
                       value="detailed", command=self.switch_log_type).grid(row=0, column=1, padx=(0, 10))
        
        # Log control buttons
        ttk.Button(self.log_type_frame, text="保存日志", command=self.save_log).grid(row=0, column=2, padx=(5, 0))
        ttk.Button(self.log_type_frame, text="清空日志", command=self.clear_log).grid(row=0, column=3, padx=(5, 0))
        
        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            height=12,
            wrap=tk.WORD,
            state="disabled"
        )
        
        # 日志数据存储
        self.simple_logs = []
        self.detailed_logs = []
        
        # 状态栏
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_label = ttk.Label(
            self.status_frame, 
            text="就绪", 
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        
        # 状态指示器
        self.status_indicator = ttk.Label(
            self.status_frame,
            text="●",
            foreground="green",
            font=("Arial", 12, "bold")
        )
        
        # Bind events
        self.results_tree.bind("<Double-1>", self.on_result_double_click)
    
    def _setup_layout(self) -> None:
        """Setup the GUI layout."""
        # Main frame
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title labels
        self.title_label.grid(row=0, column=0, columnspan=2, pady=(0, 5))
        self.domain_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # Control buttons
        self.control_frame.grid(row=2, column=0, columnspan=2, pady=(0, 10))
        self.start_button.grid(row=0, column=0, padx=(0, 5))
        self.stop_button.grid(row=0, column=1, padx=(0, 5))
        self.update_hosts_button.grid(row=0, column=2, padx=(0, 5))
        self.config_button.grid(row=0, column=3, padx=(0, 5))
        self.about_button.grid(row=0, column=4)
        
        # Progress bar
        self.progress_frame.grid(row=3, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E))
        self.progress_label.grid(row=0, column=0, sticky=tk.W)
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        self.progress_text.grid(row=2, column=0, sticky=tk.W, pady=(2, 0))
        
        # Results frame
        self.results_frame.grid(row=4, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E, tk.N, tk.S))
        self.stats_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        self.stats_label.grid(row=0, column=0, sticky=tk.W)
        self.preview_button.grid(row=0, column=1, padx=(10, 0))
        self.results_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.results_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Log frame
        self.log_frame.grid(row=5, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E))
        self.status_indicator.grid(row=0, column=0, padx=(0, 5))
        self.status_label.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(4, weight=1)
        self.main_frame.rowconfigure(5, weight=1)
        self.results_frame.columnconfigure(0, weight=1)
        self.results_frame.rowconfigure(0, weight=1)
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(1, weight=1)
        self.log_type_frame.columnconfigure(4, weight=1)
        self.progress_frame.columnconfigure(0, weight=1)
        self.status_frame.columnconfigure(0, weight=1)
    
    def log_message(self, message: str, level: str = "INFO") -> None:
        """Add simple log message - public interface."""
        self._log_message(message, level)
    
    def _log_message(self, message: str, level: str = "INFO") -> None:
        """Add simple log message."""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        self.simple_logs.append(log_entry)
        self.log_queue.put(log_entry + "\n")
    
    def log_detailed(self, message: str, level: str = "INFO", category: str = "GENERAL") -> None:
        """Add detailed log message - public interface."""
        self._log_detailed(message, level, category)
    
    def _log_detailed(self, message: str, level: str = "INFO", category: str = "GENERAL") -> None:
        """Add detailed log message."""
        # Use datetime for millisecond precision timestamp
        from datetime import datetime
        now = datetime.now()
        timestamp = now.strftime("%H:%M:%S.%f")[:-3]  # Include milliseconds
        log_entry = f"[{timestamp}] [{category}] {level}: {message}"
        self.detailed_logs.append(log_entry)
        # If currently displaying detailed logs, update immediately
        if self.log_type_var.get() == "detailed":
            self.log_queue.put(log_entry + "\n")
    
    def update_progress(self, phase: str, current: int = 0, total: int = 0, detail: str = "") -> None:
        """Update progress display - public interface."""
        self._update_progress(phase, current, total, detail)
    
    def _update_progress(self, phase: str, current: int = 0, total: int = 0, detail: str = "") -> None:
        """Update progress display."""
        self.current_phase = phase
        if total > 0:
            self.total_ips = total
            self.tested_ips = current
            progress = int((current / total) * 100)
            self.progress_bar['value'] = progress
            
            # Calculate time estimation
            time_info = ""
            if current > 0 and self.start_time:
                elapsed = time.time() - self.start_time
                if current < total:
                    estimated_total = elapsed * total / current
                    remaining = estimated_total - elapsed
                    time_info = f" | 剩余: {remaining:.0f}s"
                else:
                    time_info = f" | 用时: {elapsed:.0f}s"
            
            self.progress_text.config(text=f"{phase}: {current}/{total} ({progress}%){time_info} - {detail}")
        else:
            self.progress_bar['value'] = 0
            self.progress_text.config(text=f"{phase} - {detail}")
        
        # Update status label and indicator
        self.status_label.config(text=f"{phase} - {detail}")
        self._update_status_indicator(phase)
    
    def _update_status_indicator(self, phase: str) -> None:
        """Update status indicator."""
        if phase == "完成":
            self.status_indicator.config(text="●", foreground="green")
        elif phase == "失败":
            self.status_indicator.config(text="●", foreground="red")
        elif phase in ["IP测试", "DNS解析", "结果处理"]:
            self.status_indicator.config(text="●", foreground="orange")
        elif phase == "初始化":
            self.status_indicator.config(text="●", foreground="blue")
        else:
            self.status_indicator.config(text="●", foreground="gray")
    
    def switch_log_type(self) -> None:
        """Switch log type - public interface."""
        self._switch_log_type()
    
    def _switch_log_type(self) -> None:
        """Switch log type."""
        self._update_log_display()
    
    def _update_log_display(self) -> None:
        """Update log display."""
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        
        if self.log_type_var.get() == "simple":
            logs = self.simple_logs
        else:
            logs = self.detailed_logs
        
        for log in logs:
            self.log_text.insert(tk.END, log + "\n")
        
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)
    
    def clear_log(self) -> None:
        """Clear logs - public interface."""
        self._clear_log()
    
    def _clear_log(self) -> None:
        """Clear logs."""
        if self.log_type_var.get() == "simple":
            self.simple_logs.clear()
        else:
            self.detailed_logs.clear()
        self._update_log_display()
    
    def save_log(self) -> None:
        """Save logs to file - public interface."""
        self._save_log()
    
    def _save_log(self) -> None:
        """Save logs to file."""
        if self.log_type_var.get() == "simple":
            logs = self.simple_logs
            filename = f"hosts_optimizer_simple_{time.strftime('%Y%m%d_%H%M%S')}.log"
        else:
            logs = self.detailed_logs
            filename = f"hosts_optimizer_detailed_{time.strftime('%Y%m%d_%H%M%S')}.log"
        
        if not logs:
            messagebox.showwarning("警告", "没有日志内容可保存")
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for log in logs:
                    f.write(log + "\n")
            messagebox.showinfo("成功", f"日志已保存到: {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"保存日志失败: {str(e)}")
    
    def _update_log(self) -> None:
        """Update log display."""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
                self.log_text.config(state="disabled")
        except queue.Empty:
            pass
        
        # Update every 100ms
        self.root.after(100, self._update_log)
    
    def start_test(self) -> None:
        """Start testing - public interface."""
        self._start_test()
    
    def _start_test(self) -> None:
        """Start testing using true parallel processing."""
        if not TRUE_PARALLEL_AVAILABLE:
            messagebox.showerror("功能不可用", 
                "真正并行测试功能需要安装 aiohttp 库。\n\n"
                "请运行以下命令安装：\n"
                "pip install aiohttp")
            return
            
        if self.is_running:
            return
        
        self.is_running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.update_hosts_button.config(state="disabled")
        
        # Clear results
        self.test_results.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Clear logs
        self.simple_logs.clear()
        self.detailed_logs.clear()
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")
        
        # Initialize progress
        self.progress_bar['value'] = 0
        self.progress_label.config(text="🚀 并行测试中...")
        self.start_time = time.time()  # Record start time
        self._update_progress("初始化", 0, 0, "准备并行测试环境")
        
        # Log test start
        self._log_message("🚀 启动并行测试模式", "INFO")
        self._log_detailed("使用异步IO和协程实现并行处理", "INFO", "PARALLEL_TEST")
        self._log_detailed("清空历史数据和日志", "DEBUG", "CLEANUP")
        
        # Run parallel test in new thread
        self.test_thread = threading.Thread(target=self.run_true_parallel_test, daemon=True)
        self.test_thread.start()
    
    
    def stop_test(self) -> None:
        """Stop testing - public interface."""
        self._stop_test()
    
    def _stop_test(self) -> None:
        """Stop testing."""
        self.is_running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress_bar.stop()
        self.progress_label.config(text="已停止")
        self.status_label.config(text="测试已停止")
        self._log_message("用户停止了测试", "WARNING")
    
    def run_test(self):
        """运行测试（在后台线程中）"""
        try:
            self.log_message("开始 hosts 选优测试", "INFO")
            self.log_detailed("初始化测试环境", "INFO", "INIT")
            self.log_message("目标域名: ar-gcp-cdn.bistudio.com", "INFO")
            
            # 创建优化器实例
            self.update_progress("初始化", 0, 0, "创建优化器实例")
            self.log_detailed("创建 HostsOptimizer 实例", "DEBUG", "INIT")
            self.optimizer = HostsOptimizer("ar-gcp-cdn.bistudio.com")
            self.log_detailed("优化器实例创建完成", "DEBUG", "INIT")
            
            # 获取 IP 地址
            self.update_progress("DNS解析", 0, 0, "正在获取IP地址")
            self.log_detailed("开始获取域名 IP 地址", "INFO", "DNS_RESOLVE")
            domain_ips = self.optimizer.get_domain_ips()
            
            if not domain_ips:
                self.log_message("无法获取域名的 IP 地址", "ERROR")
                self.log_detailed("DNS 解析失败，无法获取任何 IP 地址", "ERROR", "DNS_RESOLVE")
                self.update_progress("失败", 0, 0, "无法获取IP地址")
                return
            
            self.log_message(f"找到 {len(domain_ips)} 个 IP 地址", "INFO")
            self.log_detailed(f"成功获取 {len(domain_ips)} 个 IP 地址: {', '.join(domain_ips[:5])}{'...' if len(domain_ips) > 5 else ''}", "INFO", "DNS_RESOLVE")
            
            # 测试 IP 地址
            self.update_progress("IP测试", 0, len(domain_ips), "开始并行测试")
            self.log_detailed("开始并行测试 IP 地址", "INFO", "IP_TEST")
            self.log_detailed(f"使用 {self.optimizer.config.get('max_workers', 10)} 个并发线程进行测试", "DEBUG", "IP_TEST")
            
            # 创建自定义的测试器来跟踪进度
            results = self.test_ips_with_progress(domain_ips)
            
            # 更新进度显示
            self.update_progress("结果处理", 0, 0, "处理测试结果")
            
            if not results:
                self.log_message("没有找到可用的 IP 地址", "ERROR")
                self.log_detailed("所有 IP 地址测试均失败", "ERROR", "IP_TEST")
                self.update_progress("失败", 0, 0, "所有IP测试失败")
                return
            
            # 分析结果
            available_count = len([r for r in results if r['http_available'] or r['https_available']])
            self.log_detailed(f"测试完成，共 {len(results)} 个 IP，其中 {available_count} 个可用", "INFO", "IP_TEST")
            
            # 更新结果
            self.update_progress("结果处理", 0, 0, "更新界面显示")
            self.test_results = results
            self.log_detailed("更新结果表格显示", "DEBUG", "UI_UPDATE")
            self.update_results_display()
            
            # 完成测试
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_hosts_button.config(state="normal")
            self.progress_bar['value'] = 100
            self.progress_label.config(text="测试完成")
            self.update_progress("完成", len(results), len(results), f"找到 {available_count} 个可用IP")
            
            self.log_message("测试完成", "INFO")
            self.log_detailed("测试流程完全结束", "INFO", "TEST_END")
            
        except Exception as e:
            self.log_message(f"测试过程中发生错误: {e}", "ERROR")
            self.log_detailed(f"测试异常: {type(e).__name__}: {str(e)}", "ERROR", "EXCEPTION")
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_bar['value'] = 0
            self.progress_label.config(text="测试失败")
            self.update_progress("失败", 0, 0, f"错误: {str(e)[:50]}")
    
    def run_true_parallel_test(self):
        """运行并行测试（在后台线程中）"""
        try:
            self.log_message("🚀 开始并行测试", "INFO")
            self.log_detailed("使用异步IO和协程实现并行处理", "INFO", "PARALLEL_INIT")
            self.log_message("目标域名: ar-gcp-cdn.bistudio.com", "INFO")
            
            # 创建HostsOptimizer实例用于DNS解析
            self.update_progress("初始化", 0, 0, "创建优化器实例")
            self.log_detailed("创建 HostsOptimizer 实例", "DEBUG", "PARALLEL_INIT")
            self.optimizer = HostsOptimizer("ar-gcp-cdn.bistudio.com")
            
            # 更新配置以支持并行处理
            self.optimizer.config.update({
                "max_concurrent_requests": 50,  # 降低并发数
                "max_per_host": 20,             # 降低每主机连接数
                "http_timeout": 15,             # 增加HTTP超时时间
                "connect_timeout": 8,           # 增加连接超时时间
                "read_timeout": 10,             # 增加读取超时时间
                "ping_timeout": 5,              # 增加ping超时时间
                "ssl_check_enabled": True,
                "multi_dimensional_health": True
            })
            
            # 创建并行优化器适配器
            self.update_progress("初始化", 0, 0, "创建并行优化器实例")
            self.log_detailed("创建 TrueParallelOptimizerAdapter 实例", "DEBUG", "PARALLEL_INIT")
            parallel_adapter = TrueParallelOptimizerAdapter(self.optimizer.config)
            
            # 获取域名IP地址
            self.update_progress("DNS解析", 0, 0, "获取域名IP地址")
            self.log_detailed("开始DNS解析", "INFO", "DNS_RESOLVE")
            
            domain_ips = self.optimizer.get_domain_ips()
            
            if not domain_ips:
                self.log_message("❌ 没有找到可用的 IP 地址", "ERROR")
                self.log_detailed("DNS解析失败，未找到任何IP地址", "ERROR", "DNS_RESOLVE")
                self.update_progress("失败", 0, 0, "DNS解析失败")
                return
            
            self.log_message(f"✅ 找到 {len(domain_ips)} 个IP地址", "SUCCESS")
            self.log_detailed(f"IP地址列表: {', '.join(domain_ips[:10])}{'...' if len(domain_ips) > 10 else ''}", "DEBUG", "DNS_RESOLVE")
            
            # 并行测试 IP 地址
            self.update_progress("IP测试", 0, len(domain_ips), "开始并行测试")
            self.log_detailed("开始并行测试 IP 地址", "INFO", "PARALLEL_TEST")
            self.log_detailed(f"使用 {self.optimizer.config.get('max_concurrent_requests', 100)} 个并发请求进行测试", "DEBUG", "PARALLEL_TEST")
            
            # 使用并行测试器
            results = parallel_adapter.test_ips_with_true_parallel(
                domain_ips, 
                "ar-gcp-cdn.bistudio.com", 
                progress_callback=self.true_parallel_progress_callback
            )
            
            # 更新进度显示
            self.update_progress("结果处理", 0, 0, "处理测试结果")
            
            if not results:
                self.log_message("❌ 没有找到可用的 IP 地址", "ERROR")
                self.log_detailed("所有 IP 地址测试均失败", "ERROR", "PARALLEL_TEST")
                self.update_progress("失败", 0, 0, "所有IP测试失败")
                return
            
            # 分析结果
            available_count = len([r for r in results if r['http_available'] or r['https_available']])
            self.log_message(f"✅ 测试完成！找到 {available_count}/{len(results)} 个可用IP", "SUCCESS")
            self.log_detailed(f"可用IP数量: {available_count}, 总测试IP数量: {len(results)}", "INFO", "PARALLEL_RESULT")
            
            # 显示最佳结果
            if results:
                best_result = results[0]
                self.log_message(f"🏆 最佳IP: {best_result['ip']} (评分: {best_result['overall_score']:.1f})", "SUCCESS")
                self.log_detailed(f"最佳IP详细信息: {best_result['ip']}, 评分: {best_result['overall_score']:.1f}, Ping: {best_result['ping_latency']:.3f}s", "INFO", "BEST_RESULT")
            
            # 保存结果
            self.test_results = results
            
            # 更新GUI显示
            self.root.after(0, self.update_results_display)
            
            # 完成测试 - 直接在主线程中处理
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_hosts_button.config(state="normal")
            self.progress_bar['value'] = 100
            self.progress_label.config(text="测试完成")
            self.update_progress("完成", len(results), len(results), f"找到 {available_count} 个可用IP")
            
            self.log_message("🚀 并行测试完成", "INFO")
            self.log_detailed("并行测试流程完全结束", "INFO", "PARALLEL_TEST_END")
            
        except Exception as e:
            self.log_message(f"❌ 并行测试失败: {str(e)}", "ERROR")
            self.log_detailed(f"并行测试异常: {str(e)}", "ERROR", "PARALLEL_ERROR")
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_bar['value'] = 0
            self.progress_label.config(text="测试失败")
            self.update_progress("失败", 0, 0, f"错误: {str(e)[:50]}")
    
    def true_parallel_progress_callback(self, completed: int, total: int, current_ip: str):
        """并行测试进度回调"""
        def update_progress():
            if self.is_running:
                progress = (completed / total) * 100
                self.progress_bar['value'] = progress
                self.progress_label.config(text=f"🚀 并行测试中... {completed}/{total} ({progress:.1f}%)")
                self.update_progress("IP测试", completed, total, f"正在测试: {current_ip}")
                
                # 实时日志
                self.log_detailed(f"完成测试: {current_ip} ({completed}/{total})", "DEBUG", "PARALLEL_PROGRESS")
        
        # 在主线程中更新GUI
        self.root.after(0, update_progress)
    
    def test_ips_with_progress(self, ips):
        """带进度跟踪的IP测试"""
        # 导入OptimizedTester类
        from hosts_optimizer import OptimizedTester
        
        # 使用优化器进行测试
        optimized_tester = OptimizedTester(self.optimizer.config)
        
        # 更新进度显示
        self.update_progress("IP测试", 0, len(ips), "开始批量测试")
        
        # 定义进度回调函数
        def progress_callback(current, total, detail):
            # 在主线程中更新进度
            self.root.after(0, lambda: self.update_progress("IP测试", current, total, detail))
        
        try:
            # 使用OptimizedTester的test_ips_optimized方法，传入进度回调
            results = optimized_tester.test_ips_optimized(ips, progress_callback)
            
            # 统计可用IP数量
            available_count = len([r for r in results if r.get('http_available', False) or r.get('https_available', False)])
            
            # 更新完成进度
            self.update_progress("IP测试", len(ips), len(ips), f"完成测试，找到 {available_count} 个可用IP")
            
            return results
        except Exception as e:
            self.log_detailed(f"批量测试失败: {str(e)}", "ERROR", "IP_TEST")
            self.update_progress("IP测试", 0, len(ips), f"测试失败: {str(e)[:50]}")
            return []
    
    def update_results_display(self):
        """更新结果显示"""
        self.log_detailed("开始更新结果表格", "DEBUG", "UI_UPDATE")
        
        # 清空现有结果
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # 筛选可用的结果
        available_results = [r for r in self.test_results if r['http_available'] or r['https_available']]
        self.log_detailed(f"筛选结果: 总共 {len(self.test_results)} 个，可用 {len(available_results)} 个", "DEBUG", "UI_UPDATE")
        
        # 计算统计信息
        total_ips = len(self.test_results)
        available_ips = len(available_results)
        https_available = len([r for r in self.test_results if r.get('https_available', False)])
        avg_ping = sum([r.get('ping_latency', 0) for r in self.test_results if r.get('ping_success', False)]) / max(1, len([r for r in self.test_results if r.get('ping_success', False)]))
        best_score = max([r.get('overall_score', 0) for r in self.test_results]) if self.test_results else 0
        
        # 更新统计信息显示
        stats_text = f"总计: {total_ips} | 可用: {available_ips} | HTTPS: {https_available} | 平均延迟: {avg_ping:.1f}ms | 最高分: {best_score:.1f}"
        self.stats_label.config(text=stats_text)
        
        if not available_results:
            self.log_message("所有 IP 地址都无法提供 HTTP/HTTPS 服务", "WARNING")
            self.log_detailed("没有可用的 IP 地址，无法显示结果", "WARNING", "UI_UPDATE")
            return
        
        # 按评分排序所有可用结果
        sorted_results = sorted(available_results, key=lambda x: x.get('overall_score', 0), reverse=True)
        
        # 添加所有可用结果到树形视图（不再限制为20个）
        for i, result in enumerate(sorted_results):
            # 准备显示数据
            ping_text = f"{result['ping_latency']:.1f}ms" if result['ping_success'] else "失败"
            http_text = f"{result['best_http_latency']:.1f}ms" if result['http_available'] else "不可用"
            https_text = f"{result['best_https_latency']:.1f}ms" if result['https_available'] else "不可用"
            
            # SSL状态显示
            ssl_text = "N/A"
            if result.get('https_available', False):
                # 检查SSL证书信息
                ssl_cert = result.get('ssl_certificate', {})
                if ssl_cert.get('ssl_available', False):
                    if ssl_cert.get('certificate_valid', False):
                        ssl_text = "✓ 有效"
                    else:
                        ssl_text = "⚠ 无效"
                else:
                    ssl_text = "✗ 无SSL"
            else:
                ssl_text = "✗ 无HTTPS"
            
            # HTTP/2支持已取消检测
            # 不再显示HTTP/2相关信息
            
            
            # 稳定性显示
            stability_text = "N/A"
            if result.get('health_info') and result['health_info'].get('stability'):
                stability_info = result['health_info']['stability']
                if stability_info.get('stability_score', 0) > 0:
                    stability = stability_info['stability_score']
                    if stability >= 0.9:
                        stability_text = "优秀"
                    elif stability >= 0.7:
                        stability_text = "良好"
                    elif stability >= 0.5:
                        stability_text = "一般"
                    else:
                        stability_text = "较差"
                else:
                    stability_text = "未测试"
            else:
                stability_text = "未测试"
            
            # 健康等级显示
            health_text = "N/A"
            if result.get('health_info') and result['health_info'].get('overall_health_score', 0) > 0:
                health_grade = result['health_info'].get('health_grade', 'F')
                health_score = result['health_info'].get('overall_health_score', 0)
                health_text = f"{health_grade} ({health_score:.0f})"
            
            # 评分显示（移到最后一列）
            score = result['overall_score']
            if score >= 200:
                score_text = f"★ {score:.1f}"
            elif score >= 150:
                score_text = f"● {score:.1f}"
            elif score >= 100:
                score_text = f"○ {score:.1f}"
            elif score >= 50:
                score_text = f"△ {score:.1f}"
            else:
                score_text = f"× {score:.1f}"
            
            # 插入行（移除带宽列）
            item = self.results_tree.insert("", "end", values=(
                result['ip'],           # IP 地址
                ping_text,             # Ping 延迟
                http_text,             # HTTP 延迟
                https_text,            # HTTPS 延迟
                ssl_text,              # SSL 状态
                stability_text,        # 稳定性
                health_text,           # 健康等级
                score_text             # 综合评分（最后一列）
            ))
            
            # 记录前几个结果的详细信息
            if i < 3:
                self.log_detailed(f"结果 {i+1}: {result['ip']} - 评分: {score}, 健康: {health_text}", "DEBUG", "UI_UPDATE")
        
        self.log_message(f"显示 {len(sorted_results)} 个可用 IP 地址", "INFO")
        self.log_detailed(f"结果表格更新完成，显示所有 {len(sorted_results)} 个可用结果", "INFO", "UI_UPDATE")
        
        # 启用快速预览按钮
        self.preview_button.config(state="normal")
    
    def show_quick_preview(self):
        """显示快速预览窗口"""
        if not self.test_results:
            messagebox.showinfo("提示", "没有测试结果可以预览")
            return
        
        preview_window = tk.Toplevel(self.root)
        preview_window.title("测试结果快速预览")
        preview_window.geometry("500x400")
        preview_window.resizable(True, True)
        
        # 创建文本框
        text_widget = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD, font=("Consolas", 10))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 生成预览内容
        preview_content = "=== Hosts Optimizer 测试结果预览 ===\n\n"
        
        # 统计信息
        total_ips = len(self.test_results)
        available_ips = len([r for r in self.test_results if r.get('http_available', False) or r.get('https_available', False)])
        https_available = len([r for r in self.test_results if r.get('https_available', False)])
        
        preview_content += f"📊 统计信息:\n"
        preview_content += f"   • 总IP数量: {total_ips}\n"
        preview_content += f"   • 可用IP数量: {available_ips}\n"
        preview_content += f"   • HTTPS可用: {https_available}\n"
        preview_content += f"   • 注：带宽测试仅用于网络质量评估\n\n"
        
        # 所有可用结果
        available_results = [r for r in self.test_results if r.get('http_available', False) or r.get('https_available', False)]
        sorted_results = sorted(available_results, key=lambda x: x.get('overall_score', 0), reverse=True)
        preview_content += f"🏆 所有可用结果 (共{len(sorted_results)}个):\n"
        
        # 显示前10个最佳结果
        for i, result in enumerate(sorted_results[:10]):
            ip = result.get('ip', 'N/A')
            score = result.get('overall_score', 0)
            ping = result.get('ping_latency', 0)
            http_ok = "✓" if result.get('http_available', False) else "✗"
            https_ok = "✓" if result.get('https_available', False) else "✗"
            ssl_ok = "✓" if result.get('ssl_valid', False) else "✗"
            
            preview_content += f"   {i+1}. {ip} | 评分: {score:.1f} | Ping: {ping:.1f}ms | HTTP: {http_ok} | HTTPS: {https_ok} | SSL: {ssl_ok}\n"
        
        preview_content += f"\n💡 建议:\n"
        if sorted_results:
            best_ip = sorted_results[0].get('ip', 'N/A')
            best_score = sorted_results[0].get('overall_score', 0)
            preview_content += f"   • 推荐使用: {best_ip} (评分: {best_score:.1f})\n"
            preview_content += f"   • 点击'更新Hosts'按钮应用最佳IP\n"
        else:
            preview_content += f"   • 没有找到可用的IP地址\n"
        
        # 插入内容
        text_widget.insert(tk.END, preview_content)
        text_widget.config(state="disabled")
    
    def on_result_double_click(self, event):
        """双击结果项时显示详细信息"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        ip = self.results_tree.item(item, "values")[0]
        
        # 查找对应的结果
        result = None
        for r in self.test_results:
            if r['ip'] == ip:
                result = r
                break
        
        if result:
            self.show_result_details(result)
    
    def show_result_details(self, result: Dict):
        """显示结果详细信息"""
        details_window = tk.Toplevel(self.root)
        details_window.title(f"IP 地址详细信息 - {result['ip']}")
        details_window.geometry("600x500")
        details_window.resizable(True, True)
        
        # 创建滚动文本框
        text_widget = scrolledtext.ScrolledText(details_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 添加详细信息
        details = f"IP 地址: {result['ip']}\n"
        details += f"Ping 延迟: {result['ping_latency']:.2f}ms ({'成功' if result['ping_success'] else '失败'})\n"
        details += f"HTTP 可用: {'是' if result['http_available'] else '否'}\n"
        details += f"HTTPS 可用: {'是' if result['https_available'] else '否'}\n"
        
        # 添加新的检测属性
        details += f"SSL 状态: {'有效' if result.get('ssl_valid', False) else '无效/无HTTPS'}\n"
        details += f"综合评分: {result['overall_score']:.1f}\n\n"
        
        # 健康检测信息
        if result.get('health_info') and result['health_info'].get('overall_health_score', 0) > 0:
            health_info = result['health_info']
            details += "=== 健康检测详情 ===\n"
            details += f"综合健康评分: {health_info.get('overall_health_score', 0):.1f} ({health_info.get('health_grade', 'F')})\n\n"
            
            # 稳定性信息
            if health_info.get('stability'):
                stability = health_info['stability']
                details += "连接稳定性:\n"
                details += f"  稳定性评分: {stability.get('stability_score', 0):.2f}\n"
                details += f"  成功率: {stability.get('success_rate', 0):.1%}\n"
                details += f"  平均延迟: {stability.get('avg_latency', 0):.1f}ms\n"
                details += f"  延迟标准差: {stability.get('latency_std', 0):.1f}ms\n\n"
            
            
            # SSL质量信息
            if health_info.get('ssl_quality'):
                ssl_quality = health_info['ssl_quality']
                if ssl_quality.get('cert_score', 0) > 0:
                    details += "SSL证书质量:\n"
                    details += f"  SSL质量评分: {ssl_quality.get('cert_score', 0):.1f} ({ssl_quality.get('ssl_grade', 'F')})\n"
                    details += f"  证书有效期: {ssl_quality.get('cert_validity_days', 0)} 天\n"
                    details += f"  证书颁发者: {ssl_quality.get('cert_issuer', 'Unknown')}\n"
                    details += f"  加密算法: {ssl_quality.get('cert_algorithm', 'Unknown')}\n"
                    details += f"  加密强度: {ssl_quality.get('cert_strength', 'Unknown')} bits\n\n"
            
            # 协议支持信息
            if health_info.get('protocol_support'):
                protocol = health_info['protocol_support']
                details += "协议支持:\n"
                details += f"  协议支持评分: {protocol.get('protocol_score', 0):.1f}\n"
                details += f"  HTTP支持: {'✓' if protocol.get('http_support') else '✗'}\n"
                details += f"  HTTPS支持: {'✓' if protocol.get('https_support') else '✗'}\n\n"
            
            # 地理位置信息
            if health_info.get('geographic'):
                geo = health_info['geographic']
                details += "地理位置:\n"
                details += f"  地理位置评分: {geo.get('geo_score', 0):.2f}\n"
                details += f"  网络区域: {geo.get('region', 'Unknown')}\n"
                details += f"  服务提供商: {geo.get('provider', 'Unknown')}\n\n"
        
        # HTTP 状态码详情
        if result['http_status']:
            details += "HTTP 状态码详情:\n"
            for path, status in result['http_status'].items():
                if status['success']:
                    details += f"  {path}: {status['status_code']} ({status['latency']:.1f}ms)\n"
                else:
                    error_msg = status.get('error', '连接失败')
                    details += f"  {path}: 失败 - {error_msg}\n"
            details += "\n"
        
        # HTTPS 状态码详情
        if result['https_status']:
            details += "HTTPS 状态码详情:\n"
            for path, status in result['https_status'].items():
                if status['success']:
                    details += f"  {path}: {status['status_code']} ({status['latency']:.1f}ms)\n"
                else:
                    error_msg = status.get('error', '连接失败')
                    details += f"  {path}: 失败 - {error_msg}\n"
        
        text_widget.insert(tk.END, details)
        text_widget.config(state="disabled")
    
    def update_hosts(self):
        """更新 hosts 文件"""
        self.log_detailed("用户请求更新 hosts 文件", "INFO", "HOSTS_UPDATE")
        
        if not self.test_results:
            self.log_detailed("没有测试结果，无法更新 hosts", "WARNING", "HOSTS_UPDATE")
            messagebox.showwarning("警告", "请先运行测试")
            return
        
        # 获取最优结果
        available_results = [r for r in self.test_results if r['http_available'] or r['https_available']]
        if not available_results:
            self.log_detailed("没有可用的 IP 地址", "ERROR", "HOSTS_UPDATE")
            messagebox.showerror("错误", "没有可用的 IP 地址")
            return
        
        best_result = available_results[0]
        best_ip = best_result['ip']
        self.log_detailed(f"选择最优 IP: {best_ip} (评分: {best_result['overall_score']})", "INFO", "HOSTS_UPDATE")
        
        # 准备确认对话框信息
        confirm_text = f"是否将最优 IP 地址 {best_ip} 更新到 hosts 文件？\n\n"
        confirm_text += f"评分: {best_result['overall_score']}\n"
        confirm_text += f"Ping 延迟: {best_result['ping_latency']:.1f}ms\n"
        confirm_text += f"HTTP 延迟: {best_result['best_http_latency']:.1f}ms\n"
        confirm_text += f"HTTPS 延迟: {best_result['best_https_latency']:.1f}ms\n"
        
        # 添加健康检测信息
        if best_result.get('health_info') and best_result['health_info'].get('overall_health_score', 0) > 0:
            health_info = best_result['health_info']
            confirm_text += f"健康等级: {health_info.get('health_grade', 'F')} ({health_info.get('overall_health_score', 0):.0f})\n"
        
        # 确认对话框
        result = messagebox.askyesno("确认更新", confirm_text)
        
        if result:
            try:
                self.log_detailed("用户确认更新 hosts 文件", "INFO", "HOSTS_UPDATE")
                
                # 备份 hosts 文件
                self.log_detailed("开始备份原始 hosts 文件", "INFO", "HOSTS_UPDATE")
                self.optimizer.backup_hosts()
                self.log_detailed("hosts 文件备份完成", "INFO", "HOSTS_UPDATE")
                
                # 更新 hosts 文件
                self.log_detailed(f"开始更新 hosts 文件，使用 IP: {best_ip}", "INFO", "HOSTS_UPDATE")
                self.optimizer.update_hosts(best_ip)
                self.log_detailed("hosts 文件更新完成", "INFO", "HOSTS_UPDATE")
                
                # 询问是否刷新 DNS
                self.log_detailed("询问用户是否刷新 DNS 缓存", "DEBUG", "HOSTS_UPDATE")
                flush_result = messagebox.askyesno(
                    "刷新 DNS",
                    "是否刷新 DNS 缓存？"
                )
                
                if flush_result:
                    self.log_detailed("用户选择刷新 DNS 缓存", "INFO", "HOSTS_UPDATE")
                    self.optimizer.flush_dns()
                    self.log_detailed("DNS 缓存刷新完成", "INFO", "HOSTS_UPDATE")
                else:
                    self.log_detailed("用户选择不刷新 DNS 缓存", "INFO", "HOSTS_UPDATE")
                
                messagebox.showinfo("成功", "Hosts 文件更新成功！")
                self.log_message(f"已更新 hosts 文件: {best_ip}", "INFO")
                self.log_detailed("hosts 文件更新流程完全完成", "INFO", "HOSTS_UPDATE")
                
            except PermissionError as e:
                self.log_detailed(f"权限不足: {str(e)}", "ERROR", "HOSTS_UPDATE")
                messagebox.showerror("权限不足", 
                    "无法修改 hosts 文件，权限不足。\n\n"
                    "请以管理员身份运行此程序，然后重试。\n\n"
                    "Windows: 右键点击程序图标，选择'以管理员身份运行'")
                self.log_message("权限不足，无法修改 hosts 文件", "ERROR")
            except Exception as e:
                self.log_detailed(f"hosts 更新异常: {type(e).__name__}: {str(e)}", "ERROR", "HOSTS_UPDATE")
                messagebox.showerror("错误", f"更新 hosts 文件失败: {e}")
                self.log_message(f"更新 hosts 文件失败: {e}", "ERROR")
        else:
            self.log_detailed("用户取消 hosts 文件更新", "INFO", "HOSTS_UPDATE")
    
    def show_config(self):
        """显示配置窗口"""
        # 如果optimizer还没有初始化，先创建一个临时实例来获取默认配置
        if self.optimizer is None:
            temp_optimizer = HostsOptimizer("ar-gcp-cdn.bistudio.com")
            config = temp_optimizer.config
        else:
            config = self.optimizer.config
            
        config_window = tk.Toplevel(self.root)
        config_window.title("配置")
        config_window.geometry("500x400")
        config_window.resizable(False, False)
        
        # 创建配置界面
        config_frame = ttk.Frame(config_window, padding="10")
        config_frame.pack(fill=tk.BOTH, expand=True)
        
        # 配置项
        ttk.Label(config_frame, text="测试超时时间 (秒):").grid(row=0, column=0, sticky=tk.W, pady=5)
        timeout_var = tk.StringVar(value=str(config.get("test_timeout", 5)))
        ttk.Entry(config_frame, textvariable=timeout_var, width=10).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="HTTP 超时时间 (秒):").grid(row=1, column=0, sticky=tk.W, pady=5)
        http_timeout_var = tk.StringVar(value=str(config.get("http_timeout", 10)))
        ttk.Entry(config_frame, textvariable=http_timeout_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="最大工作线程数:").grid(row=2, column=0, sticky=tk.W, pady=5)
        max_workers_var = tk.StringVar(value=str(config.get("max_workers", 10)))
        ttk.Entry(config_frame, textvariable=max_workers_var, width=10).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # 复选框
        test_http_var = tk.BooleanVar(value=config.get("test_http", True))
        ttk.Checkbutton(config_frame, text="测试 HTTP", variable=test_http_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        test_https_var = tk.BooleanVar(value=config.get("test_https", True))
        ttk.Checkbutton(config_frame, text="测试 HTTPS", variable=test_https_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        show_details_var = tk.BooleanVar(value=config.get("show_detailed_results", True))
        ttk.Checkbutton(config_frame, text="显示详细结果", variable=show_details_var).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        backup_hosts_var = tk.BooleanVar(value=config.get("backup_hosts", True))
        ttk.Checkbutton(config_frame, text="自动备份 hosts 文件", variable=backup_hosts_var).grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # 多维度健康检测配置
        ttk.Separator(config_frame, orient='horizontal').grid(row=7, column=0, columnspan=2, sticky='ew', pady=10)
        ttk.Label(config_frame, text="多维度健康检测配置", font=("Arial", 10, "bold")).grid(row=8, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        multi_health_var = tk.BooleanVar(value=config.get("multi_dimensional_health", True))
        ttk.Checkbutton(config_frame, text="启用多维度健康检测", variable=multi_health_var).grid(row=9, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="健康检测测试次数:").grid(row=11, column=0, sticky=tk.W, pady=5)
        health_iterations_var = tk.StringVar(value=str(config.get("health_test_iterations", 3)))
        ttk.Entry(config_frame, textvariable=health_iterations_var, width=10).grid(row=11, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="稳定性阈值:").grid(row=12, column=0, sticky=tk.W, pady=5)
        stability_threshold_var = tk.StringVar(value=str(config.get("stability_threshold", 0.8)))
        ttk.Entry(config_frame, textvariable=stability_threshold_var, width=10).grid(row=12, column=1, sticky=tk.W, pady=5)
        
        # 按钮
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=13, column=0, columnspan=2, pady=20)
        
        def save_config():
            try:
                # 如果optimizer还没有初始化，先创建一个实例
                if self.optimizer is None:
                    self.optimizer = HostsOptimizer("ar-gcp-cdn.bistudio.com")
                
                self.optimizer.config["test_timeout"] = int(timeout_var.get())
                self.optimizer.config["http_timeout"] = int(http_timeout_var.get())
                self.optimizer.config["max_workers"] = int(max_workers_var.get())
                self.optimizer.config["test_http"] = test_http_var.get()
                self.optimizer.config["test_https"] = test_https_var.get()
                self.optimizer.config["show_detailed_results"] = show_details_var.get()
                self.optimizer.config["backup_hosts"] = backup_hosts_var.get()
                
                # 多维度健康检测配置
                self.optimizer.config["multi_dimensional_health"] = multi_health_var.get()
                self.optimizer.config["health_test_iterations"] = int(health_iterations_var.get())
                self.optimizer.config["stability_threshold"] = float(stability_threshold_var.get())
                
                self.optimizer.save_config()
                messagebox.showinfo("成功", "配置已保存")
                config_window.destroy()
            except ValueError:
                messagebox.showerror("错误", "请输入有效的数值")
        
        ttk.Button(button_frame, text="保存", command=save_config).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="取消", command=config_window.destroy).grid(row=0, column=1, padx=5)
    
    def show_about(self):
        """显示关于对话框"""
        about_text = """Arma Reforger 创意工坊修复工具

版本: 2.0.0
目标域名: ar-gcp-cdn.bistudio.com

功能特点:
• 修复 DNS 污染和劫持问题
• 自动获取域名的真实 IP 地址
• 并行测试多个 IP 地址的延迟
• HTTP/HTTPS 状态码检测
• 多维度健康检测系统
• 连接稳定性检测
• SSL证书质量评估
• 协议支持检测
• 地理位置性能分析
• 智能评分和排序
• 一键更新 hosts 文件
• 解决创意工坊下载问题

作者: ViVi141
邮箱: 747384120@qq.com
许可证: 仅供学习和个人使用"""
        
        messagebox.showinfo("关于", about_text)
    
    def on_closing(self):
        """关闭窗口时的处理"""
        if self.is_running:
            if messagebox.askokcancel("退出", "测试正在运行，确定要退出吗？"):
                self.is_running = False
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self) -> None:
        """Run the GUI application."""
        self.root.mainloop()


def main() -> None:
    """Main function."""
    try:
        app = HostsOptimizerGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("错误", f"启动应用程序失败: {e}")


if __name__ == "__main__":
    main()
