#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hosts 选优脚本
用于测试 ar-gcp-cdn.bistudio.com 的不同 IP 地址延迟，并选择最优的 IP 更新到 hosts 文件
"""

import socket
import time
import subprocess
import platform
import os
import sys
import json
from typing import List, Dict, Tuple
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import requests
from urllib.parse import urlparse
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HostsOptimizer:
    """Hosts 选优器"""
    
    def __init__(self, domain: str = "ar-gcp-cdn.bistudio.com"):
        self.domain = domain
        self.hosts_file = self._get_hosts_file_path()
        self.test_results = []
        self.config_file = "hosts_config.json"
        self.test_urls = [
            f"http://{domain}/",
            f"https://{domain}/",
            f"http://{domain}/api/health",
            f"https://{domain}/api/health"
        ]
        
        # 禁用 SSL 警告
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # 创建 requests session 配置
        self.session = requests.Session()
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.load_config()
    
    def _get_hosts_file_path(self) -> str:
        """获取系统 hosts 文件路径"""
        system = platform.system().lower()
        if system == "windows":
            return r"C:\Windows\System32\drivers\etc\hosts"
        elif system == "darwin":  # macOS
            return "/etc/hosts"
        else:  # Linux
            return "/etc/hosts"
    
    def load_config(self):
        """加载配置文件"""
        default_config = {
            "test_ips": [],  # 将自动获取真实IP
            "test_timeout": 5,
            "test_count": 3,
            "backup_hosts": True,
            "dns_servers": [
                "8.8.8.8",      # Google DNS
                "1.1.1.1",      # Cloudflare DNS
                "208.67.222.222", # OpenDNS
                "114.114.114.114" # 114 DNS
            ],
            "test_http": True,
            "test_https": True,
            "http_timeout": 10,
            "verify_ssl": False,
            "test_paths": [
                "/",
                "/api/health",
                "/status",
                "/ping"
            ],
            "show_detailed_results": True,
            "max_workers": 10
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            except:
                self.config = default_config
        else:
            self.config = default_config
            self.save_config()
    
    def save_config(self):
        """保存配置文件"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
    
    def get_domain_ips(self) -> List[str]:
        """获取域名的所有 IP 地址"""
        ips = set()
        
        print(f"正在获取 {self.domain} 的 IP 地址...")
        
        # 方法1: 使用系统 DNS 解析
        try:
            result = socket.getaddrinfo(self.domain, None)
            for item in result:
                ip = item[4][0]
                if ip not in ips:
                    ips.add(ip)
                    print(f"✓ 系统DNS: {ip}")
        except Exception as e:
            print(f"⚠️ 系统DNS解析失败: {e}")
        
        # 方法2: 使用多个公共DNS服务器
        for dns_server in self.config["dns_servers"]:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3
                resolver.lifetime = 3
                
                answers = resolver.resolve(self.domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    if ip not in ips:
                        ips.add(ip)
                        print(f"✓ {dns_server}: {ip}")
            except Exception as e:
                print(f"⚠️ DNS服务器 {dns_server} 解析失败: {e}")
        
        # 方法3: 使用 nslookup 命令
        try:
            # Windows 和 Unix 系统的 nslookup 输出格式略有不同
            result = subprocess.run(['nslookup', self.domain], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    # 处理不同系统的 nslookup 输出格式
                    if 'Address:' in line and not line.startswith('#'):
                        ip = line.split('Address:')[-1].strip()
                        if self._is_valid_ip(ip) and ip not in ips:
                            ips.add(ip)
                            print(f"✓ nslookup: {ip}")
                    # 处理 Windows 系统的输出格式
                    elif line and self._is_valid_ip(line) and line not in ips:
                        ips.add(line)
                        print(f"✓ nslookup: {line}")
        except Exception as e:
            print(f"⚠️ nslookup 失败: {e}")
        
        # 方法4: 使用 dig 命令 (如果可用，主要用于 Linux/macOS)
        if platform.system().lower() != "windows":
            try:
                result = subprocess.run(['dig', '+short', self.domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        ip = line.strip()
                        if self._is_valid_ip(ip) and ip not in ips:
                            ips.add(ip)
                            print(f"✓ dig: {ip}")
            except Exception as e:
                print(f"⚠️ dig 命令不可用: {e}")
        else:
            print("ℹ️ Windows 系统跳过 dig 命令（通常不可用）")
        
        # 方法5: 使用 PowerShell (Windows 特有)
        if platform.system().lower() == "windows":
            try:
                ps_command = f"Resolve-DnsName -Name {self.domain} -Type A | Select-Object -ExpandProperty IPAddress"
                result = subprocess.run(['powershell', '-Command', ps_command], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        ip = line.strip()
                        if self._is_valid_ip(ip) and ip not in ips:
                            ips.add(ip)
                            print(f"✓ PowerShell: {ip}")
            except Exception as e:
                print(f"⚠️ PowerShell DNS 解析失败: {e}")
        
        ip_list = list(ips)
        if not ip_list:
            print("❌ 无法获取域名的 IP 地址")
            return []
        
        print(f"\n找到 {len(ip_list)} 个 IP 地址:")
        for i, ip in enumerate(ip_list, 1):
            print(f"{i:2d}. {ip}")
        
        return ip_list
    
    def _is_valid_ip(self, ip: str) -> bool:
        """检查是否为有效的 IP 地址"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _get_status_description(self, status_code: int) -> str:
        """获取 HTTP 状态码的描述"""
        descriptions = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            303: "See Other",
            304: "Not Modified",
            307: "Temporary Redirect",
            308: "Permanent Redirect",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden (需要认证)",
            404: "Not Found",
            405: "Method Not Allowed",
            429: "Too Many Requests",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout"
        }
        return descriptions.get(status_code, "Unknown")
    
    def ping_ip(self, ip: str) -> Tuple[str, float, bool]:
        """测试单个 IP 的延迟"""
        try:
            # 使用 socket 连接测试延迟
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config["test_timeout"])
            result = sock.connect_ex((ip, 80))
            end_time = time.time()
            sock.close()
            
            if result == 0:
                latency = (end_time - start_time) * 1000  # 转换为毫秒
                return ip, latency, True
            else:
                return ip, float('inf'), False
        except Exception as e:
            return ip, float('inf'), False
    
    def test_http_status(self, ip: str) -> Tuple[str, Dict]:
        """测试 IP 的 HTTP 状态码"""
        results = {
            'ip': ip,
            'http_status': {},
            'https_status': {},
            'best_http_latency': float('inf'),
            'best_https_latency': float('inf'),
            'http_available': False,
            'https_available': False,
            'overall_score': 0
        }
        
        # 测试 HTTP
        if self.config.get("test_http", True):
            for path in self.config.get("test_paths", ["/"]):
                url = f"http://{ip}{path}"
                try:
                    start_time = time.time()
                    response = self.session.get(
                        url, 
                        timeout=self.config.get("http_timeout", 10),
                        headers={'Host': self.domain, 'User-Agent': 'HostsOptimizer/1.0'},
                        allow_redirects=True,
                        stream=False
                    )
                    end_time = time.time()
                    latency = (end_time - start_time) * 1000
                    
                    status_code = response.status_code
                    # 403 未授权是正常的，说明服务器可用但需要认证
                    # 301/302 重定向可能表示配置问题
                    is_success = (200 <= status_code < 300) or (status_code == 403)
                    is_redirect = 300 <= status_code < 400
                    
                    results['http_status'][path] = {
                        'status_code': status_code,
                        'latency': latency,
                        'success': is_success,
                        'is_redirect': is_redirect,
                        'response_size': len(response.content) if response.content else 0
                    }
                    
                    if is_success and latency < results['best_http_latency']:
                        results['best_http_latency'] = latency
                        results['http_available'] = True
                        
                except requests.exceptions.Timeout:
                    results['http_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': '请求超时'
                    }
                except requests.exceptions.ConnectionError:
                    results['http_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': '连接错误'
                    }
                except Exception as e:
                    results['http_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': str(e)[:100]  # 限制错误信息长度
                    }
        
        # 测试 HTTPS
        if self.config.get("test_https", True):
            for path in self.config.get("test_paths", ["/"]):
                url = f"https://{ip}{path}"
                try:
                    start_time = time.time()
                    response = self.session.get(
                        url, 
                        timeout=self.config.get("http_timeout", 10),
                        headers={'Host': self.domain, 'User-Agent': 'HostsOptimizer/1.0'},
                        allow_redirects=True,
                        verify=self.config.get("verify_ssl", False),
                        stream=False
                    )
                    end_time = time.time()
                    latency = (end_time - start_time) * 1000
                    
                    status_code = response.status_code
                    # 403 未授权是正常的，说明服务器可用但需要认证
                    # 301/302 重定向可能表示配置问题
                    is_success = (200 <= status_code < 300) or (status_code == 403)
                    is_redirect = 300 <= status_code < 400
                    
                    results['https_status'][path] = {
                        'status_code': status_code,
                        'latency': latency,
                        'success': is_success,
                        'is_redirect': is_redirect,
                        'response_size': len(response.content) if response.content else 0
                    }
                    
                    if is_success and latency < results['best_https_latency']:
                        results['best_https_latency'] = latency
                        results['https_available'] = True
                        
                except requests.exceptions.Timeout:
                    results['https_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': '请求超时'
                    }
                except requests.exceptions.SSLError:
                    results['https_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': 'SSL证书错误'
                    }
                except requests.exceptions.ConnectionError:
                    results['https_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': '连接错误'
                    }
                except Exception as e:
                    results['https_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': str(e)[:100]  # 限制错误信息长度
                    }
        
        # 计算综合评分
        score = 0
        redirect_penalty = 0
        
        # 检查是否有重定向
        for path, status in results['http_status'].items():
            if status.get('is_redirect', False):
                redirect_penalty += 2  # 重定向扣分
        for path, status in results['https_status'].items():
            if status.get('is_redirect', False):
                redirect_penalty += 2  # 重定向扣分
        
        if results['http_available']:
            score += 10
            if results['best_http_latency'] < 100:
                score += 5
            elif results['best_http_latency'] < 200:
                score += 3
            elif results['best_http_latency'] < 500:
                score += 1
                
        if results['https_available']:
            score += 15  # HTTPS 权重更高
            if results['best_https_latency'] < 100:
                score += 5
            elif results['best_https_latency'] < 200:
                score += 3
            elif results['best_https_latency'] < 500:
                score += 1
        
        # 应用重定向惩罚
        score = max(0, score - redirect_penalty)
        results['overall_score'] = score
        results['redirect_penalty'] = redirect_penalty
        return ip, results
    
    def test_ips_parallel(self, ips: List[str] = None) -> List[Dict]:
        """并行测试所有 IP 地址"""
        if ips is None:
            ips = self.config['test_ips']
        
        if not ips:
            print("❌ 没有可测试的 IP 地址")
            return []
        
        print(f"开始测试 {len(ips)} 个 IP 地址...")
        print("测试项目: Ping延迟 + HTTP状态码")
        print()
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.get("max_workers", 10)) as executor:
            # 提交所有测试任务
            futures = {}
            for ip in ips:
                # 同时提交 ping 和 HTTP 测试
                ping_future = executor.submit(self.ping_ip, ip)
                http_future = executor.submit(self.test_http_status, ip)
                futures[ip] = (ping_future, http_future)
            
            # 收集结果
            for ip, (ping_future, http_future) in futures.items():
                try:
                    # 获取 ping 结果
                    _, ping_latency, ping_success = ping_future.result()
                    
                    # 获取 HTTP 测试结果
                    _, http_results = http_future.result()
                    
                    # 合并结果
                    result = {
                        'ip': ip,
                        'ping_latency': ping_latency,
                        'ping_success': ping_success,
                        'http_available': http_results['http_available'],
                        'https_available': http_results['https_available'],
                        'best_http_latency': http_results['best_http_latency'],
                        'best_https_latency': http_results['best_https_latency'],
                        'overall_score': http_results['overall_score'],
                        'http_status': http_results['http_status'],
                        'https_status': http_results['https_status']
                    }
                    
                    results.append(result)
                    
                    # 显示测试结果
                    status_parts = []
                    if ping_success:
                        status_parts.append(f"Ping: {ping_latency:.1f}ms")
                    else:
                        status_parts.append("Ping: 失败")
                    
                    if http_results['http_available']:
                        status_parts.append(f"HTTP: {http_results['best_http_latency']:.1f}ms")
                    else:
                        status_parts.append("HTTP: 不可用")
                    
                    if http_results['https_available']:
                        status_parts.append(f"HTTPS: {http_results['best_https_latency']:.1f}ms")
                    else:
                        status_parts.append("HTTPS: 不可用")
                    
                    status_parts.append(f"评分: {http_results['overall_score']}")
                    
                    print(f"✓ {ip:15s} - {' | '.join(status_parts)}")
                    
                except Exception as e:
                    print(f"✗ {ip:15s} - 测试异常: {e}")
                    results.append({
                        'ip': ip,
                        'ping_latency': float('inf'),
                        'ping_success': False,
                        'http_available': False,
                        'https_available': False,
                        'best_http_latency': float('inf'),
                        'best_https_latency': float('inf'),
                        'overall_score': 0,
                        'http_status': {},
                        'https_status': {}
                    })
        
        # 按综合评分排序，评分相同时按延迟排序
        results.sort(key=lambda x: (-x['overall_score'], x['best_https_latency'], x['best_http_latency'], x['ping_latency']))
        self.test_results = results
        return results
    
    def backup_hosts(self):
        """备份 hosts 文件"""
        if not self.config["backup_hosts"]:
            return
            
        backup_path = f"{self.hosts_file}.backup.{int(time.time())}"
        try:
            with open(self.hosts_file, 'r', encoding='utf-8') as src:
                with open(backup_path, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
            print(f"Hosts 文件已备份到: {backup_path}")
        except Exception as e:
            print(f"备份 hosts 文件失败: {e}")
    
    def update_hosts(self, best_ip: str):
        """更新 hosts 文件"""
        try:
            # 读取当前 hosts 文件
            with open(self.hosts_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # 移除旧的域名记录
            new_lines = []
            for line in lines:
                if self.domain not in line:
                    new_lines.append(line)
            
            # 添加新的记录
            new_lines.append(f"{best_ip} {self.domain}\n")
            
            # 写入新内容
            with open(self.hosts_file, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            
            print(f"✓ Hosts 文件已更新: {best_ip} {self.domain}")
            
        except PermissionError:
            print("❌ 权限不足，无法修改 hosts 文件")
            print("请以管理员身份运行此脚本")
        except Exception as e:
            print(f"❌ 更新 hosts 文件失败: {e}")
    
    def flush_dns(self):
        """刷新 DNS 缓存"""
        system = platform.system().lower()
        try:
            if system == "windows":
                subprocess.run(["ipconfig", "/flushdns"], check=True, capture_output=True)
                print("✓ DNS 缓存已刷新")
            elif system == "darwin":  # macOS
                subprocess.run(["sudo", "dscacheutil", "-flushcache"], check=True, capture_output=True)
                print("✓ DNS 缓存已刷新")
            else:  # Linux
                subprocess.run(["sudo", "systemctl", "restart", "systemd-resolved"], check=True, capture_output=True)
                print("✓ DNS 缓存已刷新")
        except Exception as e:
            print(f"⚠️ 刷新 DNS 缓存失败: {e}")
    
    def run_optimization(self):
        """运行完整的优化流程"""
        print(f"=== Hosts 选优工具 ===")
        print(f"目标域名: {self.domain}")
        print(f"Hosts 文件: {self.hosts_file}")
        print()
        
        # 获取域名的真实 IP 地址
        domain_ips = self.get_domain_ips()
        
        if not domain_ips:
            print("❌ 无法获取域名的 IP 地址，请检查网络连接或域名是否正确")
            return
        
        # 测试获取到的 IP 地址
        results = self.test_ips_parallel(domain_ips)
        
        if not results:
            print("❌ 没有找到可用的 IP 地址")
            return
        
        # 显示结果
        print(f"\n=== 测试结果 ===")
        
        # 筛选可用的结果（有 HTTP 或 HTTPS 可用）
        available_results = [r for r in results if r['http_available'] or r['https_available']]
        
        if not available_results:
            print("❌ 所有 IP 地址都无法提供 HTTP/HTTPS 服务")
            return
        
        print(f"找到 {len(available_results)} 个可用的 IP 地址:")
        print()
        
        for i, result in enumerate(available_results[:10], 1):  # 只显示前10个
            status_info = []
            if result['ping_success']:
                status_info.append(f"Ping: {result['ping_latency']:.1f}ms")
            else:
                status_info.append("Ping: 失败")
            
            if result['http_available']:
                status_info.append(f"HTTP: {result['best_http_latency']:.1f}ms")
            if result['https_available']:
                status_info.append(f"HTTPS: {result['best_https_latency']:.1f}ms")
            
            status_info.append(f"评分: {result['overall_score']}")
            
            print(f"{i:2d}. {result['ip']:15s} - {' | '.join(status_info)}")
            
            # 显示详细的 HTTP 状态码信息（如果启用）
            if self.config.get("show_detailed_results", True):
                if result['http_status']:
                    print(f"    HTTP 状态码:")
                    for path, status in result['http_status'].items():
                        if status['success']:
                            size_info = f" ({status.get('response_size', 0)} bytes)" if status.get('response_size', 0) > 0 else ""
                            status_desc = self._get_status_description(status['status_code'])
                            print(f"      {path}: {status['status_code']} {status_desc} ({status['latency']:.1f}ms){size_info}")
                        elif status.get('is_redirect', False):
                            print(f"      {path}: {status['status_code']} 重定向 (可能配置问题)")
                        else:
                            error_msg = status.get('error', '连接失败')
                            print(f"      {path}: 失败 - {error_msg}")
                
                if result['https_status']:
                    print(f"    HTTPS 状态码:")
                    for path, status in result['https_status'].items():
                        if status['success']:
                            size_info = f" ({status.get('response_size', 0)} bytes)" if status.get('response_size', 0) > 0 else ""
                            status_desc = self._get_status_description(status['status_code'])
                            print(f"      {path}: {status['status_code']} {status_desc} ({status['latency']:.1f}ms){size_info}")
                        elif status.get('is_redirect', False):
                            print(f"      {path}: {status['status_code']} 重定向 (可能配置问题)")
                        else:
                            error_msg = status.get('error', '连接失败')
                            print(f"      {path}: 失败 - {error_msg}")
            print()
        
        best_result = available_results[0]
        print(f"最优 IP: {best_result['ip']}")
        if best_result['https_available']:
            print(f"  HTTPS 延迟: {best_result['best_https_latency']:.2f}ms")
        if best_result['http_available']:
            print(f"  HTTP 延迟: {best_result['best_http_latency']:.2f}ms")
        if best_result['ping_success']:
            print(f"  Ping 延迟: {best_result['ping_latency']:.2f}ms")
        print(f"  综合评分: {best_result['overall_score']}")
        
        # 显示重定向惩罚信息
        if best_result.get('redirect_penalty', 0) > 0:
            print(f"  重定向惩罚: -{best_result['redirect_penalty']} 分")
        
        # 询问是否更新
        while True:
            choice = input(f"\n是否更新 hosts 文件? (y/n): ").lower().strip()
            if choice in ['y', 'yes', '是']:
                break
            elif choice in ['n', 'no', '否']:
                print("已取消更新")
                return
            else:
                print("请输入 y 或 n")
        
        # 备份并更新
        self.backup_hosts()
        self.update_hosts(best_result['ip'])
        
        # 刷新 DNS
        flush_choice = input("是否刷新 DNS 缓存? (y/n): ").lower().strip()
        if flush_choice in ['y', 'yes', '是']:
            self.flush_dns()
        
        print("\n✓ 优化完成!")


def main():
    """主函数"""
    try:
        optimizer = HostsOptimizer()
        optimizer.run_optimization()
    except KeyboardInterrupt:
        print("\n\n用户中断操作")
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
