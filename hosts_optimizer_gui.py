#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hosts 选优工具 GUI 版本
用于测试 ar-gcp-cdn.bistudio.com 的不同 IP 地址延迟，并选择最优的 IP 更新到 hosts 文件
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
import os
import sys
from typing import List, Dict
import json
from hosts_optimizer import HostsOptimizer


class HostsOptimizerGUI:
    """Hosts 选优工具 GUI 界面"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Arma Reforger 创意工坊修复工具 - ar-gcp-cdn.bistudio.com")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # 设置图标（如果有的话）
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        # 初始化变量
        self.optimizer = None
        self.is_running = False
        self.test_results = []
        self.log_queue = queue.Queue()
        
        # 创建界面
        self.create_widgets()
        self.setup_layout()
        
        # 启动日志更新
        self.update_log()
        
        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        """创建界面组件"""
        # 主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        
        # 标题
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
        
        # 控制按钮框架
        self.control_frame = ttk.Frame(self.main_frame)
        
        # 按钮
        self.start_button = ttk.Button(
            self.control_frame, 
            text="开始测试", 
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
        
        # 进度条
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_label = ttk.Label(self.progress_frame, text="就绪")
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, 
            mode='indeterminate',
            length=400
        )
        
        # 结果框架
        self.results_frame = ttk.LabelFrame(self.main_frame, text="测试结果", padding="5")
        
        # 结果树形视图
        self.results_tree = ttk.Treeview(
            self.results_frame,
            columns=("ip", "ping", "http", "https", "score"),
            show="headings",
            height=8
        )
        
        # 设置列标题
        self.results_tree.heading("ip", text="IP 地址")
        self.results_tree.heading("ping", text="Ping 延迟")
        self.results_tree.heading("http", text="HTTP 状态")
        self.results_tree.heading("https", text="HTTPS 状态")
        self.results_tree.heading("score", text="评分")
        
        # 设置列宽
        self.results_tree.column("ip", width=120)
        self.results_tree.column("ping", width=100)
        self.results_tree.column("http", width=100)
        self.results_tree.column("https", width=100)
        self.results_tree.column("score", width=80)
        
        # 结果滚动条
        self.results_scrollbar = ttk.Scrollbar(
            self.results_frame, 
            orient="vertical", 
            command=self.results_tree.yview
        )
        self.results_tree.configure(yscrollcommand=self.results_scrollbar.set)
        
        # 日志框架
        self.log_frame = ttk.LabelFrame(self.main_frame, text="运行日志", padding="5")
        
        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            height=12,
            wrap=tk.WORD,
            state="disabled"
        )
        
        # 状态栏
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_label = ttk.Label(
            self.status_frame, 
            text="就绪", 
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        
        # 绑定事件
        self.results_tree.bind("<Double-1>", self.on_result_double_click)
    
    def setup_layout(self):
        """设置布局"""
        # 主框架
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        self.title_label.grid(row=0, column=0, columnspan=2, pady=(0, 5))
        self.domain_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # 控制按钮
        self.control_frame.grid(row=2, column=0, columnspan=2, pady=(0, 10))
        self.start_button.grid(row=0, column=0, padx=(0, 5))
        self.stop_button.grid(row=0, column=1, padx=(0, 5))
        self.update_hosts_button.grid(row=0, column=2, padx=(0, 5))
        self.config_button.grid(row=0, column=3, padx=(0, 5))
        self.about_button.grid(row=0, column=4)
        
        # 进度条
        self.progress_frame.grid(row=3, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E))
        self.progress_label.grid(row=0, column=0, sticky=tk.W)
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # 结果框架
        self.results_frame.grid(row=4, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E, tk.N, tk.S))
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.results_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # 日志框架
        self.log_frame.grid(row=5, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 状态栏
        self.status_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E))
        self.status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(4, weight=1)
        self.main_frame.rowconfigure(5, weight=1)
        self.results_frame.columnconfigure(0, weight=1)
        self.results_frame.rowconfigure(0, weight=1)
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        self.progress_frame.columnconfigure(0, weight=1)
        self.status_frame.columnconfigure(0, weight=1)
    
    def log_message(self, message: str, level: str = "INFO"):
        """添加日志消息"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        self.log_queue.put(log_entry)
    
    def update_log(self):
        """更新日志显示"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
                self.log_text.config(state="disabled")
        except queue.Empty:
            pass
        
        # 每100ms更新一次
        self.root.after(100, self.update_log)
    
    def start_test(self):
        """开始测试"""
        if self.is_running:
            return
        
        self.is_running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.update_hosts_button.config(state="disabled")
        
        # 清空结果
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # 清空日志
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")
        
        # 启动进度条
        self.progress_bar.start()
        self.progress_label.config(text="正在测试...")
        self.status_label.config(text="正在获取 IP 地址...")
        
        # 在新线程中运行测试
        self.test_thread = threading.Thread(target=self.run_test, daemon=True)
        self.test_thread.start()
    
    def stop_test(self):
        """停止测试"""
        self.is_running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress_bar.stop()
        self.progress_label.config(text="已停止")
        self.status_label.config(text="测试已停止")
        self.log_message("用户停止了测试", "WARNING")
    
    def run_test(self):
        """运行测试（在后台线程中）"""
        try:
            self.log_message("开始 hosts 选优测试", "INFO")
            self.log_message("目标域名: ar-gcp-cdn.bistudio.com", "INFO")
            
            # 创建优化器实例
            self.optimizer = HostsOptimizer("ar-gcp-cdn.bistudio.com")
            
            # 获取 IP 地址
            self.status_label.config(text="正在获取 IP 地址...")
            domain_ips = self.optimizer.get_domain_ips()
            
            if not domain_ips:
                self.log_message("无法获取域名的 IP 地址", "ERROR")
                return
            
            self.log_message(f"找到 {len(domain_ips)} 个 IP 地址", "INFO")
            
            # 测试 IP 地址
            self.status_label.config(text="正在测试 IP 地址...")
            results = self.optimizer.test_ips_parallel(domain_ips)
            
            if not results:
                self.log_message("没有找到可用的 IP 地址", "ERROR")
                return
            
            # 更新结果
            self.test_results = results
            self.update_results_display()
            
            # 完成测试
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_hosts_button.config(state="normal")
            self.progress_bar.stop()
            self.progress_label.config(text="测试完成")
            self.status_label.config(text="测试完成")
            
            self.log_message("测试完成", "INFO")
            
        except Exception as e:
            self.log_message(f"测试过程中发生错误: {e}", "ERROR")
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_bar.stop()
            self.progress_label.config(text="测试失败")
            self.status_label.config(text="测试失败")
    
    def update_results_display(self):
        """更新结果显示"""
        # 清空现有结果
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # 筛选可用的结果
        available_results = [r for r in self.test_results if r['http_available'] or r['https_available']]
        
        if not available_results:
            self.log_message("所有 IP 地址都无法提供 HTTP/HTTPS 服务", "WARNING")
            return
        
        # 添加结果到树形视图
        for i, result in enumerate(available_results[:20]):  # 只显示前20个
            # 准备显示数据
            ping_text = f"{result['ping_latency']:.1f}ms" if result['ping_success'] else "失败"
            http_text = f"{result['best_http_latency']:.1f}ms" if result['http_available'] else "不可用"
            https_text = f"{result['best_https_latency']:.1f}ms" if result['https_available'] else "不可用"
            score_text = str(result['overall_score'])
            
            # 插入行
            item = self.results_tree.insert("", "end", values=(
                result['ip'],
                ping_text,
                http_text,
                https_text,
                score_text
            ))
            
            # 根据评分设置颜色
            if result['overall_score'] >= 20:
                self.results_tree.set(item, "score", f"★ {score_text}")
            elif result['overall_score'] >= 10:
                self.results_tree.set(item, "score", f"● {score_text}")
        
        self.log_message(f"显示 {len(available_results)} 个可用 IP 地址", "INFO")
    
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
        details += f"综合评分: {result['overall_score']}\n\n"
        
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
        if not self.test_results:
            messagebox.showwarning("警告", "请先运行测试")
            return
        
        # 获取最优结果
        available_results = [r for r in self.test_results if r['http_available'] or r['https_available']]
        if not available_results:
            messagebox.showerror("错误", "没有可用的 IP 地址")
            return
        
        best_result = available_results[0]
        best_ip = best_result['ip']
        
        # 确认对话框
        result = messagebox.askyesno(
            "确认更新",
            f"是否将最优 IP 地址 {best_ip} 更新到 hosts 文件？\n\n"
            f"评分: {best_result['overall_score']}\n"
            f"Ping 延迟: {best_result['ping_latency']:.1f}ms\n"
            f"HTTP 延迟: {best_result['best_http_latency']:.1f}ms\n"
            f"HTTPS 延迟: {best_result['best_https_latency']:.1f}ms"
        )
        
        if result:
            try:
                # 备份 hosts 文件
                self.optimizer.backup_hosts()
                
                # 更新 hosts 文件
                self.optimizer.update_hosts(best_ip)
                
                # 询问是否刷新 DNS
                flush_result = messagebox.askyesno(
                    "刷新 DNS",
                    "是否刷新 DNS 缓存？"
                )
                
                if flush_result:
                    self.optimizer.flush_dns()
                
                messagebox.showinfo("成功", "Hosts 文件更新成功！")
                self.log_message(f"已更新 hosts 文件: {best_ip}", "INFO")
                
            except Exception as e:
                messagebox.showerror("错误", f"更新 hosts 文件失败: {e}")
                self.log_message(f"更新 hosts 文件失败: {e}", "ERROR")
    
    def show_config(self):
        """显示配置窗口"""
        config_window = tk.Toplevel(self.root)
        config_window.title("配置")
        config_window.geometry("500x400")
        config_window.resizable(False, False)
        
        # 创建配置界面
        config_frame = ttk.Frame(config_window, padding="10")
        config_frame.pack(fill=tk.BOTH, expand=True)
        
        # 配置项
        ttk.Label(config_frame, text="测试超时时间 (秒):").grid(row=0, column=0, sticky=tk.W, pady=5)
        timeout_var = tk.StringVar(value=str(self.optimizer.config.get("test_timeout", 5)))
        ttk.Entry(config_frame, textvariable=timeout_var, width=10).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="HTTP 超时时间 (秒):").grid(row=1, column=0, sticky=tk.W, pady=5)
        http_timeout_var = tk.StringVar(value=str(self.optimizer.config.get("http_timeout", 10)))
        ttk.Entry(config_frame, textvariable=http_timeout_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="最大工作线程数:").grid(row=2, column=0, sticky=tk.W, pady=5)
        max_workers_var = tk.StringVar(value=str(self.optimizer.config.get("max_workers", 10)))
        ttk.Entry(config_frame, textvariable=max_workers_var, width=10).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # 复选框
        test_http_var = tk.BooleanVar(value=self.optimizer.config.get("test_http", True))
        ttk.Checkbutton(config_frame, text="测试 HTTP", variable=test_http_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        test_https_var = tk.BooleanVar(value=self.optimizer.config.get("test_https", True))
        ttk.Checkbutton(config_frame, text="测试 HTTPS", variable=test_https_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        show_details_var = tk.BooleanVar(value=self.optimizer.config.get("show_detailed_results", True))
        ttk.Checkbutton(config_frame, text="显示详细结果", variable=show_details_var).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        backup_hosts_var = tk.BooleanVar(value=self.optimizer.config.get("backup_hosts", True))
        ttk.Checkbutton(config_frame, text="自动备份 hosts 文件", variable=backup_hosts_var).grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # 按钮
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=20)
        
        def save_config():
            try:
                self.optimizer.config["test_timeout"] = int(timeout_var.get())
                self.optimizer.config["http_timeout"] = int(http_timeout_var.get())
                self.optimizer.config["max_workers"] = int(max_workers_var.get())
                self.optimizer.config["test_http"] = test_http_var.get()
                self.optimizer.config["test_https"] = test_https_var.get()
                self.optimizer.config["show_detailed_results"] = show_details_var.get()
                self.optimizer.config["backup_hosts"] = backup_hosts_var.get()
                
                self.optimizer.save_config()
                messagebox.showinfo("成功", "配置已保存")
                config_window.destroy()
            except ValueError:
                messagebox.showerror("错误", "请输入有效的数值")
        
        ttk.Button(button_frame, text="保存", command=save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=config_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def show_about(self):
        """显示关于对话框"""
        about_text = """Arma Reforger 创意工坊修复工具

版本: 1.0.0
目标域名: ar-gcp-cdn.bistudio.com

功能特点:
• 修复 DNS 污染和劫持问题
• 自动获取域名的真实 IP 地址
• 并行测试多个 IP 地址的延迟
• HTTP/HTTPS 状态码检测
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
    
    def run(self):
        """运行 GUI"""
        self.root.mainloop()


def main():
    """主函数"""
    try:
        app = HostsOptimizerGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("错误", f"启动应用程序失败: {e}")


if __name__ == "__main__":
    main()
