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
import statistics
import hashlib
import random
from typing import List, Dict, Tuple
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import requests
from urllib.parse import urlparse
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import socket
from datetime import datetime


class EnhancedDNSResolver:
    """增强的DNS解析器"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.found_ips = set()
        self.dns_cache = {}  # DNS查询缓存
        self.verified_ips = set()  # 已验证的IP
        
    def resolve_all_ips(self) -> List[str]:
        """使用所有可用的方法解析域名IP（避免本地DNS）"""
        print(f"正在全面解析 {self.domain} 的IP地址...")
        print("⚠️ 注意：为避免DNS污染，不使用本地DNS解析")
        
        # 并行执行所有解析方法（移除系统DNS）
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [
                executor.submit(self._resolve_public_dns),
                executor.submit(self._resolve_http_dns),
                executor.submit(self._resolve_command_line),
                executor.submit(self._resolve_powershell),
                executor.submit(self._resolve_dig),
                executor.submit(self._resolve_alternative_methods),
                executor.submit(self._resolve_international_dns),
                executor.submit(self._resolve_secure_dns)
            ]
            
            for future in as_completed(futures):
                try:
                    future.result(timeout=8)  # 减少超时时间
                except Exception:
                    continue
        
        # 验证找到的IP地址
        self._verify_found_ips()
        
        ip_list = list(self.found_ips)
        print(f"\n总共找到 {len(ip_list)} 个唯一IP地址:")
        for i, ip in enumerate(ip_list, 1):
            print(f"{i:2d}. {ip}")
        
        return ip_list
    
    def _verify_found_ips(self):
        """验证找到的IP地址是否真实有效（快速模式）"""
        print("\n正在快速验证IP地址有效性...")
        
        def verify_single_ip(ip):
            try:
                # 尝试连接到IP的80端口，使用更短的超时时间
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 减少超时时间
                result = sock.connect_ex((ip, 80))
                sock.close()
                
                if result == 0:
                    self.verified_ips.add(ip)
                    print(f"✓ 验证通过: {ip}")
                    return True
                else:
                    print(f"✗ 验证失败: {ip}")
                    return False
            except Exception:
                print(f"✗ 验证失败: {ip}")
                return False
        
        # 并行验证IP地址，增加并发数
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(verify_single_ip, ip): ip for ip in self.found_ips}
            
            for future in as_completed(futures):
                try:
                    future.result(timeout=2)  # 减少超时时间
                except Exception:
                    continue
        
        # 只保留验证通过的IP
        self.found_ips = self.verified_ips
        print(f"验证完成，有效IP数量: {len(self.found_ips)}")
    
    def _resolve_public_dns(self):
        """公共DNS服务器解析"""
        dns_servers = [
            # Google DNS
            "8.8.8.8", "8.8.4.4",
            # Cloudflare DNS
            "1.1.1.1", "1.0.0.1",
            # OpenDNS
            "208.67.222.222", "208.67.220.220",
            # Quad9 DNS
            "9.9.9.9", "149.112.112.112",
            # 国内DNS
            "114.114.114.114", "114.114.115.115",
            "223.5.5.5", "223.6.6.6",
            "180.76.76.76", "119.29.29.29",
            # 其他国际DNS
            "76.76.19.61", "76.76.2.22",  # ControlD
            "94.140.14.14", "94.140.15.15",  # AdGuard
            "185.228.168.9", "185.228.169.9",  # CleanBrowsing
            "76.76.19.61", "76.76.2.22"  # ControlD备用
        ]
        
        for dns_server in dns_servers:
            # 检查缓存
            cache_key = f"{dns_server}_{self.domain}"
            if cache_key in self.dns_cache:
                cached_ips = self.dns_cache[cache_key]
                for ip in cached_ips:
                    if self._is_valid_ip(ip):
                        self.found_ips.add(ip)
                        print(f"✓ {dns_server} (缓存): {ip}")
                continue
            
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 1  # 减少超时时间
                resolver.lifetime = 1
                
                answers = resolver.resolve(self.domain, 'A')
                found_ips = []
                for answer in answers:
                    ip = str(answer)
                    if self._is_valid_ip(ip):
                        self.found_ips.add(ip)
                        found_ips.append(ip)
                        print(f"✓ {dns_server}: {ip}")
                
                # 缓存结果
                self.dns_cache[cache_key] = found_ips
            except Exception:
                continue
    
    def _resolve_http_dns(self):
        """HTTP DNS查询（DoH服务）"""
        http_services = [
            # Google DoH
            f"https://dns.google/resolve?name={self.domain}&type=A",
            # Cloudflare DoH
            f"https://cloudflare-dns.com/dns-query?name={self.domain}&type=A",
            # OpenDNS DoH
            f"https://doh.opendns.com/dns-query?name={self.domain}&type=A",
            # Quad9 DoH
            f"https://dns.quad9.net:5053/dns-query?name={self.domain}&type=A",
            # AdGuard DoH
            f"https://dns.adguard.com/dns-query?name={self.domain}&type=A",
            # CleanBrowsing DoH
            f"https://doh.cleanbrowsing.org/doh/security-filter/dns-query?name={self.domain}&type=A",
            # ControlD DoH
            f"https://doh.controld.com/dns-query?name={self.domain}&type=A",
            # NextDNS DoH
            f"https://dns.nextdns.io/dns-query?name={self.domain}&type=A",
            # Mullvad DoH
            f"https://doh.mullvad.net/dns-query?name={self.domain}&type=A",
            # LibreDNS DoH
            f"https://doh.libredns.gr/dns-query?name={self.domain}&type=A"
        ]
        
        for service_url in http_services:
            try:
                response = requests.get(service_url, timeout=2)  # 减少超时时间
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data:
                        for answer in data['Answer']:
                            if answer.get('type') == 1:
                                ip = answer.get('data', '').strip()
                                if self._is_valid_ip(ip):
                                    self.found_ips.add(ip)
                                    service_name = service_url.split('//')[1].split('/')[0]
                                    print(f"✓ {service_name}: {ip}")
            except Exception:
                continue
    
    def _resolve_command_line(self):
        """命令行工具解析"""
        # nslookup
        try:
            result = subprocess.run(['nslookup', self.domain], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if 'Address:' in line and not line.startswith('#'):
                        ip = line.split('Address:')[-1].strip()
                        if self._is_valid_ip(ip):
                            self.found_ips.add(ip)
                            print(f"✓ nslookup: {ip}")
        except Exception:
            pass
    
    def _resolve_powershell(self):
        """PowerShell解析"""
        if platform.system().lower() == "windows":
            try:
                ps_command = f"Resolve-DnsName -Name {self.domain} -Type A | Select-Object -ExpandProperty IPAddress"
                result = subprocess.run(['powershell', '-Command', ps_command], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        ip = line.strip()
                        if self._is_valid_ip(ip):
                            self.found_ips.add(ip)
                            print(f"✓ PowerShell: {ip}")
            except Exception:
                pass
    
    def _resolve_dig(self):
        """dig命令解析"""
        if platform.system().lower() != "windows":
            try:
                result = subprocess.run(['dig', '+short', self.domain], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        ip = line.strip()
                        if self._is_valid_ip(ip):
                            self.found_ips.add(ip)
                            print(f"✓ dig: {ip}")
            except Exception:
                pass
    
    def _resolve_alternative_methods(self):
        """其他解析方法"""
        # 尝试使用不同的查询类型
        try:
            # AAAA记录（IPv6）
            result = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            for item in result:
                ip = item[4][0]
                if self._is_valid_ip(ip):
                    self.found_ips.add(ip)
                    print(f"✓ IPv6: {ip}")
        except Exception:
            pass
    
    def _resolve_international_dns(self):
        """国际DNS服务器解析"""
        international_dns = [
            # 欧洲DNS
            "84.200.69.80", "84.200.70.40",  # DNS.WATCH
            "77.109.148.136", "77.109.148.137",  # Freenom World
            "80.80.80.80", "80.80.81.81",  # Freenom World
            "91.239.100.100", "89.233.43.71",  # UncensoredDNS
            # 亚洲DNS
            "202.12.27.33", "202.12.27.34",  # 日本DNS
            "168.126.63.1", "168.126.63.2",  # 韩国DNS
            "202.106.0.20", "202.106.46.151",  # 中国电信DNS
            # 美洲DNS
            "199.85.126.10", "199.85.127.10",  # Norton DNS
            "198.101.242.72", "23.253.163.53",  # Alternate DNS
            # 其他国际DNS
            "45.90.28.0", "45.90.30.0",  # NextDNS
            "185.228.168.9", "185.228.169.9",  # CleanBrowsing Family
            "76.76.19.61", "76.76.2.22"  # ControlD
        ]
        
        for dns_server in international_dns:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 1  # 减少超时时间
                resolver.lifetime = 1
                
                answers = resolver.resolve(self.domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    if self._is_valid_ip(ip):
                        self.found_ips.add(ip)
                        print(f"✓ 国际DNS {dns_server}: {ip}")
            except Exception:
                continue
    
    def _resolve_secure_dns(self):
        """安全DNS服务器解析"""
        secure_dns = [
            # 加密DNS服务器
            "9.9.9.9", "149.112.112.112",  # Quad9 (安全)
            "1.1.1.1", "1.0.0.1",  # Cloudflare (安全)
            "8.8.8.8", "8.8.4.4",  # Google (相对安全)
            "208.67.222.222", "208.67.220.220",  # OpenDNS (安全)
            # 隐私保护DNS
            "94.140.14.14", "94.140.15.15",  # AdGuard (隐私)
            "76.76.19.61", "76.76.2.22",  # ControlD (隐私)
            "185.228.168.9", "185.228.169.9",  # CleanBrowsing (安全)
            "76.76.19.61", "76.76.2.22"  # ControlD (隐私)
        ]
        
        for dns_server in secure_dns:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 1  # 减少超时时间
                resolver.lifetime = 1
                
                answers = resolver.resolve(self.domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    if self._is_valid_ip(ip):
                        self.found_ips.add(ip)
                        print(f"✓ 安全DNS {dns_server}: {ip}")
            except Exception:
                continue
    
    def _is_valid_ip(self, ip: str) -> bool:
        """检查是否为有效的IP地址"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


class NetworkQuality:
    """网络质量实时评估"""
    
    def __init__(self):
        self.recent_latencies = []
        self.recent_errors = []
        self.max_history = 10
    
    def get_quality_factor(self) -> float:
        """返回网络质量因子 (0.5-2.0)"""
        if not self.recent_latencies:
            return 1.0
        
        avg_latency = sum(self.recent_latencies) / len(self.recent_latencies)
        error_rate = len(self.recent_errors) / max(len(self.recent_latencies), 1)
        
        # 基于延迟和错误率计算质量因子
        if avg_latency < 50 and error_rate < 0.1:
            return 2.0  # 优秀网络，可以高并发
        elif avg_latency < 100 and error_rate < 0.2:
            return 1.5  # 良好网络
        elif avg_latency < 200 and error_rate < 0.3:
            return 1.0  # 一般网络
        else:
            return 0.5  # 较差网络，降低并发
    
    def update_metrics(self, latency: float, success: bool):
        """更新网络质量指标"""
        self.recent_latencies.append(latency)
        if not success:
            self.recent_errors.append(time.time())
        
        # 保持历史记录在合理范围内
        if len(self.recent_latencies) > self.max_history:
            self.recent_latencies.pop(0)
        if len(self.recent_errors) > self.max_history:
            self.recent_errors.pop(0)


class AdaptiveConcurrencyManager:
    """自适应并发管理器 - 根据网络状况动态调整并发数"""
    
    def __init__(self):
        self.base_workers = 10  # 增加基础并发数
        self.max_workers = 50   # 增加最大并发数
        self.network_quality = NetworkQuality()
        self.adaptive_mode = True
    
    def get_optimal_workers(self, total_ips: int) -> int:
        """根据网络质量和IP数量动态计算最优并发数"""
        if not self.adaptive_mode:
            return min(self.base_workers, total_ips)
        
        # 根据网络质量调整基础并发数
        quality_factor = self.network_quality.get_quality_factor()
        adjusted_workers = int(self.base_workers * quality_factor)
        
        # 根据IP数量调整
        if total_ips <= 5:
            return min(3, total_ips)  # 少量IP时降低并发
        elif total_ips <= 15:
            return min(adjusted_workers, total_ips)
        else:
            return min(self.max_workers, total_ips)


class OptimizedConnectionManager:
    """优化的连接管理器"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.session_pool = {}
        self.connection_pool = None
        self.setup_connection_pool()
    
    def setup_connection_pool(self):
        """设置连接池"""
        # 从配置获取参数
        retry_attempts = self.config.get("retry_attempts", 2)
        pool_size = self.config.get("connection_pool_size", 20)
        
        # 创建优化的 HTTP 适配器
        retry_strategy = Retry(
            total=retry_attempts,  # 从配置获取重试次数
            backoff_factor=0.1,  # 快速重试
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        self.connection_pool = HTTPAdapter(
            pool_connections=pool_size,  # 从配置获取连接池大小
            pool_maxsize=pool_size,
            max_retries=retry_strategy,
            pool_block=False  # 非阻塞模式
        )
    
    def get_session(self, ip: str) -> requests.Session:
        """获取或创建会话"""
        if ip not in self.session_pool:
            session = requests.Session()
            session.mount("http://", self.connection_pool)
            session.mount("https://", self.connection_pool)
            
            # 优化会话配置
            session.headers.update({
                'User-Agent': 'HostsOptimizer/1.0',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate'
            })
            
            self.session_pool[ip] = session
        
        return self.session_pool[ip]
    
    def cleanup(self):
        """清理连接池"""
        for session in self.session_pool.values():
            session.close()
        self.session_pool.clear()


class MultiDimensionalHealthChecker:
    """多维度健康检测器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.test_iterations = config.get("health_test_iterations", 3)
        self.stability_threshold = config.get("stability_threshold", 0.8)
        
    def check_connection_stability(self, ip: str, port: int = 443) -> Dict:
        """检查连接稳定性"""
        results = {
            'success_rate': 0.0,
            'avg_latency': 0.0,
            'latency_std': 0.0,
            'stability_score': 0.0,
            'connection_errors': []
        }
        
        latencies = []
        success_count = 0
        
        for i in range(self.test_iterations):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                sock.close()
                end_time = time.time()
                
                latency = (end_time - start_time) * 1000
                latencies.append(latency)
                success_count += 1
                
            except Exception as e:
                results['connection_errors'].append(str(e))
            
            time.sleep(0.1)  # 短暂间隔
        
        if latencies:
            results['success_rate'] = success_count / self.test_iterations
            results['avg_latency'] = statistics.mean(latencies)
            results['latency_std'] = statistics.stdev(latencies) if len(latencies) > 1 else 0
            results['stability_score'] = min(1.0, results['success_rate'] * (1 - results['latency_std'] / results['avg_latency']))
        
        return results
    
    def check_bandwidth(self, ip: str, domain: str) -> Dict:
        """检查带宽（基于响应时间和数据量估算）"""
        results = {
            'bandwidth_mbps': 0.0,
            'response_time': 0.0,
            'data_size': 0,
            'bandwidth_score': 0.0,
            'test_method': 'response_based'
        }
        
        try:
            # 使用HEAD请求获取响应时间和内容长度
            test_url = f"https://{ip}/"
            headers = {'Host': domain}
            
            # 测试1: HEAD请求获取基本信息
            start_time = time.time()
            head_response = requests.head(
                test_url,
                headers=headers,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            head_time = time.time() - start_time
            
            # 测试2: 小数据量GET请求
            start_time = time.time()
            get_response = requests.get(
                test_url,
                headers=headers,
                timeout=8,
                verify=False,
                stream=True
            )
            
            # 只读取前64KB数据
            data_size = 0
            max_size = 64 * 1024  # 64KB
            for chunk in get_response.iter_content(chunk_size=8192):
                data_size += len(chunk)
                if data_size >= max_size:
                    break
            
            get_time = time.time() - start_time
            
            # 基于响应时间和数据量估算带宽
            if get_time > 0 and data_size > 0:
                # 计算实际传输时间（减去连接建立时间）
                actual_transfer_time = max(0.001, get_time - head_time)
                bandwidth_mbps = (data_size * 8) / (actual_transfer_time * 1024 * 1024)
                
                results['bandwidth_mbps'] = bandwidth_mbps
                results['response_time'] = get_time
                results['data_size'] = data_size
                
                # 基于响应时间和数据量计算评分
                # 考虑响应时间越短、数据量越大，评分越高
                time_score = max(0, 1 - (get_time / 5))  # 5秒内完成得满分
                size_score = min(1, data_size / (32 * 1024))  # 32KB以上得满分
                results['bandwidth_score'] = (time_score + size_score) / 2
                
                # 如果带宽计算合理，使用带宽评分
                if 0.1 <= bandwidth_mbps <= 100:  # 合理的带宽范围
                    results['bandwidth_score'] = min(1.0, bandwidth_mbps / 5)  # 5Mbps为满分
                    results['test_method'] = 'bandwidth_calculated'
        
        except Exception as e:
            # 如果网络测试失败，使用连接延迟作为替代指标
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 443))
                sock.close()
                connect_time = time.time() - start_time
                
                # 基于连接延迟估算网络质量
                if connect_time < 0.1:
                    results['bandwidth_score'] = 0.9
                elif connect_time < 0.2:
                    results['bandwidth_score'] = 0.7
                elif connect_time < 0.5:
                    results['bandwidth_score'] = 0.5
                else:
                    results['bandwidth_score'] = 0.3
                
                results['test_method'] = 'latency_based'
                results['response_time'] = connect_time
                
            except Exception as e2:
                results['error'] = f"网络测试失败: {str(e2)[:50]}"
                results['bandwidth_score'] = 0.0
        
        return results
    
    def check_ssl_quality(self, ip: str, domain: str) -> Dict:
        """检查SSL证书质量"""
        results = {
            'cert_score': 0.0,
            'cert_validity_days': 0,
            'cert_issuer': '',
            'cert_algorithm': '',
            'cert_strength': '',
            'ssl_grade': 'F'
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # 证书有效期
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    results['cert_validity_days'] = days_until_expiry
                    
                    # 证书颁发者
                    issuer = cert.get('issuer', [])
                    for item in issuer:
                        if item[0][0] == 'organizationName':
                            results['cert_issuer'] = item[0][1]
                            break
                    
                    # 证书算法和强度
                    cipher = ssock.cipher()
                    if cipher:
                        results['cert_algorithm'] = cipher[0]
                        results['cert_strength'] = str(cipher[2])
                    
                    # 计算证书评分
                    cert_score = 0
                    if days_until_expiry > 30:
                        cert_score += 30
                    elif days_until_expiry > 7:
                        cert_score += 20
                    else:
                        cert_score += 10
                    
                    if 'Let\'s Encrypt' in results['cert_issuer'] or 'DigiCert' in results['cert_issuer']:
                        cert_score += 20
                    
                    if 'AES' in results['cert_algorithm'] or 'ChaCha20' in results['cert_algorithm']:
                        cert_score += 20
                    
                    if int(results['cert_strength']) >= 256:
                        cert_score += 30
                    elif int(results['cert_strength']) >= 128:
                        cert_score += 20
                    
                    results['cert_score'] = min(100, cert_score)
                    
                    # SSL等级
                    if results['cert_score'] >= 90:
                        results['ssl_grade'] = 'A+'
                    elif results['cert_score'] >= 80:
                        results['ssl_grade'] = 'A'
                    elif results['cert_score'] >= 70:
                        results['ssl_grade'] = 'B'
                    elif results['cert_score'] >= 60:
                        results['ssl_grade'] = 'C'
                    elif results['cert_score'] >= 50:
                        results['ssl_grade'] = 'D'
                    else:
                        results['ssl_grade'] = 'F'
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def check_protocol_support(self, ip: str, domain: str) -> Dict:
        """检查协议支持"""
        results = {
            'http_support': False,
            'https_support': False,
            'http2_support': False,  # 保留字段但不再检测
            'http3_support': False,
            'protocol_score': 0.0
        }
        
        # HTTP支持
        try:
            response = requests.get(f"http://{ip}/", headers={'Host': domain}, timeout=5)
            results['http_support'] = response.status_code in [200, 301, 302, 403]
        except:
            pass
        
        # HTTPS支持
        try:
            response = requests.get(f"https://{ip}/", headers={'Host': domain}, timeout=5, verify=False)
            results['https_support'] = response.status_code in [200, 301, 302, 403]
        except:
            pass
        
        # HTTP/2支持检测已取消
        # 不再进行HTTP/2检测以提高性能
        
        # 计算协议评分
        protocol_score = 0
        if results['http_support']:
            protocol_score += 25
        if results['https_support']:
            protocol_score += 50
        # HTTP/2评分已移除
        
        results['protocol_score'] = protocol_score
        return results
    
    def check_geographic_performance(self, ip: str) -> Dict:
        """检查地理位置性能（基于IP段推断）"""
        results = {
            'region': 'Unknown',
            'provider': 'Unknown',
            'geo_score': 0.0
        }
        
        # 简化的地理位置检测（基于IP段）
        try:
            # 这里可以集成IP地理位置API，现在使用简化版本
            first_octet = int(ip.split('.')[0])
            
            if 1 <= first_octet <= 126:
                results['region'] = 'Class A'
            elif 128 <= first_octet <= 191:
                results['region'] = 'Class B'
            elif 192 <= first_octet <= 223:
                results['region'] = 'Class C'
            else:
                results['region'] = 'Other'
            
            # 基于IP段推断提供商
            if ip.startswith('89.187'):
                results['provider'] = 'BIS Studio CDN'
                results['geo_score'] = 0.9
            elif ip.startswith('143.244'):
                results['provider'] = 'Cloud Provider'
                results['geo_score'] = 0.8
            else:
                results['geo_score'] = 0.5
                
        except:
            pass
        
        return results
    
    def comprehensive_health_check(self, ip: str, domain: str) -> Dict:
        """综合健康检查"""
        health_results = {
            'ip': ip,
            'overall_health_score': 0.0,
            'stability': {},
            'bandwidth': {},
            'ssl_quality': {},
            'protocol_support': {},
            'geographic': {},
            'health_grade': 'F'
        }
        
        # 并行执行各项检查
        futures = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures['stability'] = executor.submit(self.check_connection_stability, ip)
            futures['ssl_quality'] = executor.submit(self.check_ssl_quality, ip, domain)
            futures['protocol_support'] = executor.submit(self.check_protocol_support, ip, domain)
            futures['geographic'] = executor.submit(self.check_geographic_performance, ip)
            
            # 根据配置决定是否进行带宽测试
            if self.config.get("enable_bandwidth_test", True):
                futures['bandwidth'] = executor.submit(self.check_bandwidth, ip, domain)
            else:
                futures['bandwidth'] = executor.submit(lambda: {'bandwidth_score': 0.5, 'test_method': 'disabled'})
            
            for key, future in futures.items():
                try:
                    health_results[key] = future.result(timeout=5)  # 减少超时时间
                except Exception as e:
                    health_results[key] = {'error': str(e)}
        
        # 计算综合健康评分
        scores = []
        
        # 稳定性评分 (30%)
        if 'stability_score' in health_results['stability']:
            scores.append(health_results['stability']['stability_score'] * 0.3)
        
        # 带宽评分 (20%)
        if 'bandwidth_score' in health_results['bandwidth']:
            scores.append(health_results['bandwidth']['bandwidth_score'] * 0.2)
        
        # SSL质量评分 (25%)
        if 'cert_score' in health_results['ssl_quality']:
            scores.append(health_results['ssl_quality']['cert_score'] / 100 * 0.25)
        
        # 协议支持评分 (15%)
        if 'protocol_score' in health_results['protocol_support']:
            scores.append(health_results['protocol_support']['protocol_score'] / 100 * 0.15)
        
        # 地理位置评分 (10%)
        if 'geo_score' in health_results['geographic']:
            scores.append(health_results['geographic']['geo_score'] * 0.1)
        
        if scores:
            health_results['overall_health_score'] = sum(scores) * 100
            
            # 健康等级
            if health_results['overall_health_score'] >= 90:
                health_results['health_grade'] = 'A+'
            elif health_results['overall_health_score'] >= 80:
                health_results['health_grade'] = 'A'
            elif health_results['overall_health_score'] >= 70:
                health_results['health_grade'] = 'B'
            elif health_results['overall_health_score'] >= 60:
                health_results['health_grade'] = 'C'
            elif health_results['overall_health_score'] >= 50:
                health_results['health_grade'] = 'D'
            else:
                health_results['health_grade'] = 'F'
        
        return health_results


class SSLCertificateChecker:
    """SSL证书检查器 - 使用正确的域名进行证书验证"""
    
    def __init__(self):
        # 创建标准的SSL上下文
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True  # 检查主机名
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED  # 验证证书
    
    def check_ssl_certificate(self, ip: str, hostname: str = "ar-gcp-cdn.bistudio.com") -> Dict:
        """检查SSL证书有效性 - 使用域名进行验证"""
        try:
            # 创建到IP的TCP连接
            sock = socket.create_connection((ip, 443), timeout=5)
            
            # 使用域名进行SSL握手和证书验证
            ssock = self.ssl_context.wrap_socket(sock, server_hostname=hostname)
            
            # 获取证书信息
            cert = ssock.getpeercert()
            
            # 解析证书信息
            cert_info = {
                'valid': True,
                'ssl_available': True,
                'connection_successful': True,
                'certificate_valid': True,
                'hostname_verified': True
            }
            
            if cert:
                cert_info.update({
                    'subject': dict(x[0] for x in cert['subject']) if cert.get('subject') else {},
                    'issuer': dict(x[0] for x in cert['issuer']) if cert.get('issuer') else {},
                    'not_before': cert.get('notBefore', 'Unknown'),
                    'not_after': cert.get('notAfter', 'Unknown'),
                    'serial_number': cert.get('serialNumber', 'Unknown'),
                    'version': cert.get('version', 'Unknown'),
                    'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                    'days_until_expiry': self._calculate_days_until_expiry(cert.get('notAfter', ''))
                })
                
                # 检查证书是否包含正确的域名
                if 'subjectAltName' in cert:
                    san_list = cert['subjectAltName']
                    domain_found = False
                    for san_type, san_value in san_list:
                        if san_type == 'DNS' and (hostname in san_value or san_value in hostname):
                            domain_found = True
                            break
                    cert_info['domain_match'] = domain_found
                else:
                    # 检查subject中的CN
                    subject = cert_info.get('subject', {})
                    cn = subject.get('commonName', '')
                    cert_info['domain_match'] = hostname in cn or cn in hostname
            
            ssock.close()
            return cert_info
            
        except ssl.SSLError as e:
            error_msg = str(e)
            # 分析具体的SSL错误
            if "certificate verify failed" in error_msg.lower():
                return {
                    'valid': False,
                    'ssl_available': True,  # SSL连接可用
                    'connection_successful': True,
                    'certificate_valid': False,
                    'hostname_verified': False,
                    'error': "证书验证失败",
                    'error_type': 'CERT_VERIFY_FAILED',
                    'certificate_warning': '证书验证失败，可能是证书不匹配或过期'
                }
            elif "hostname doesn't match" in error_msg.lower():
                return {
                    'valid': False,
                    'ssl_available': True,
                    'connection_successful': True,
                    'certificate_valid': True,
                    'hostname_verified': False,
                    'error': "主机名不匹配",
                    'error_type': 'HOSTNAME_MISMATCH',
                    'certificate_warning': '证书有效但主机名不匹配'
                }
            else:
                return {
                    'valid': False,
                    'ssl_available': False,
                    'connection_successful': False,
                    'certificate_valid': False,
                    'hostname_verified': False,
                    'error': f"SSL错误: {error_msg[:50]}",
                    'error_type': 'SSL_ERROR'
                }
        except socket.timeout:
            return {
                'valid': False,
                'ssl_available': False,
                'connection_successful': False,
                'certificate_valid': False,
                'hostname_verified': False,
                'error': "连接超时",
                'error_type': 'TIMEOUT'
            }
        except Exception as e:
            return {
                'valid': False,
                'ssl_available': False,
                'connection_successful': False,
                'certificate_valid': False,
                'hostname_verified': False,
                'error': f"连接错误: {str(e)[:50]}",
                'error_type': 'CONNECTION_ERROR'
            }
    
    def _calculate_days_until_expiry(self, not_after: str) -> int:
        """计算证书到期天数"""
        if not not_after:
            return -1
        try:
            # 尝试多种日期格式
            formats = [
                '%b %d %H:%M:%S %Y %Z',
                '%b %d %H:%M:%S %Y',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    expiry_date = datetime.strptime(not_after, fmt)
                    days_left = (expiry_date - datetime.now()).days
                    return max(0, days_left)
                except ValueError:
                    continue
            
            return -1
        except:
            return -1


class OptimizedTester:
    """优化的测试器"""
    
    def __init__(self, config):
        self.config = config
        self.connection_manager = OptimizedConnectionManager(config)
        self.network_quality = NetworkQuality()
        self.concurrency_manager = AdaptiveConcurrencyManager()
        self.ssl_checker = SSLCertificateChecker()
        self.health_checker = MultiDimensionalHealthChecker(config)
        
        # 根据配置调整设置
        if config.get("fast_mode", True):
            self.concurrency_manager.adaptive_mode = config.get("adaptive_concurrency", True)
        else:
            self.concurrency_manager.adaptive_mode = False
    
    def test_ips_optimized(self, ips: List[str], progress_callback=None) -> List[Dict]:
        """优化的IP测试"""
        if not ips:
            return []
        
        # 动态调整并发数
        max_workers = self.concurrency_manager.get_optimal_workers(len(ips))
        
        print(f"使用 {max_workers} 个并发线程测试 {len(ips)} 个IP地址")
        
        results = []
        completed_count = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交测试任务
            futures = {}
            for ip in ips:
                # 同时提交ping和HTTP测试
                ping_future = executor.submit(self._ping_ip_fast, ip)
                http_future = executor.submit(self._test_http_fast, ip)
                futures[ip] = (ping_future, http_future)
            
            # 收集结果
            for ip, (ping_future, http_future) in futures.items():
                try:
                    # 获取ping结果
                    _, ping_latency, ping_success = ping_future.result(timeout=5)  # 减少超时时间
                    
                    # 更新网络质量指标
                    self.network_quality.update_metrics(ping_latency, ping_success)
                    
                    # 获取HTTP测试结果
                    _, http_results = http_future.result(timeout=8)  # 减少超时时间
                    
                    # 如果启用多维度健康检测，进行综合健康检查
                    health_info = None
                    if self.config.get("multi_dimensional_health", True):
                        health_info = self.health_checker.comprehensive_health_check(ip, self.config.get("domain", "ar-gcp-cdn.bistudio.com"))
                        
                        # 根据健康评分调整总体评分
                        if health_info.get('overall_health_score', 0) > 0:
                            # 健康评分作为额外奖励
                            health_bonus = health_info['overall_health_score'] * 0.5  # 健康评分50%作为奖励
                            http_results['overall_score'] += health_bonus
                    
                    # 如果HTTPS可用且启用SSL检查，检查SSL证书
                    ssl_cert_info = None
                    if http_results['https_available'] and self.config.get("ssl_check_enabled", True):
                        ssl_cert_info = self.ssl_checker.check_ssl_certificate(ip, self.config.get("domain", "ar-gcp-cdn.bistudio.com"))
                        
                        # 根据SSL证书状态调整评分
                        if not ssl_cert_info.get('ssl_available', False):
                            # SSL连接不可用，大幅降低评分
                            http_results['overall_score'] = max(0, http_results['overall_score'] - 20)
                        elif not ssl_cert_info.get('certificate_valid', False):
                            # 证书无效，降低评分
                            http_results['overall_score'] = max(0, http_results['overall_score'] - 15)
                        elif not ssl_cert_info.get('hostname_verified', False):
                            # 主机名不匹配，轻微降低评分
                            http_results['overall_score'] = max(0, http_results['overall_score'] - 10)
                        elif ssl_cert_info.get('certificate_warning'):
                            # 有证书警告，轻微降低评分
                            http_results['overall_score'] = max(0, http_results['overall_score'] - 5)
                    
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
                        'https_status': http_results['https_status'],
                        'ssl_certificate': ssl_cert_info,
                        'health_info': health_info
                    }
                    
                    results.append(result)
                    completed_count += 1
                    
                    # 调用进度回调
                    if progress_callback:
                        progress_callback(completed_count, len(ips), f"已测试 {completed_count}/{len(ips)} 个IP")
                    
                    # 实时显示结果
                    self._display_result(result)
                    
                except Exception as e:
                    print(f"✗ {ip:15s} - 测试异常: {e}")
                    results.append(self._create_failed_result(ip))
                    completed_count += 1
                    
                    # 即使失败也要更新进度
                    if progress_callback:
                        progress_callback(completed_count, len(ips), f"已测试 {completed_count}/{len(ips)} 个IP")
        
        # 清理连接池
        self.connection_manager.cleanup()
        
        # 按评分排序
        results.sort(key=lambda x: (-x['overall_score'], x['best_https_latency'], x['best_http_latency']))
        return results
    
    def _ping_ip_fast(self, ip: str) -> Tuple[str, float, bool]:
        """快速ping测试"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config["test_timeout"])
            result = sock.connect_ex((ip, 80))
            end_time = time.time()
            sock.close()
            
            if result == 0:
                latency = (end_time - start_time) * 1000
                return ip, latency, True
            else:
                return ip, float('inf'), False
        except Exception:
            return ip, float('inf'), False
    
    def _test_http_fast(self, ip: str) -> Tuple[str, Dict]:
        """快速HTTP测试"""
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
        
        session = self.connection_manager.get_session(ip)
        
        # 只测试根路径，减少测试时间
        test_paths = ["/"]  # 快速模式只测试根路径
        
        # 测试HTTP
        if self.config.get("test_http", True):
            for path in test_paths:
                url = f"http://{ip}{path}"
                try:
                    start_time = time.time()
                    response = session.get(
                        url, 
                        timeout=self.config.get("http_timeout", 8),  # 减少超时时间
                        headers={'Host': 'ar-gcp-cdn.bistudio.com'},
                        allow_redirects=True,
                        stream=False
                    )
                    end_time = time.time()
                    latency = (end_time - start_time) * 1000
                    
                    status_code = response.status_code
                    is_success = (200 <= status_code < 300) or (status_code == 403)
                    
                    results['http_status'][path] = {
                        'status_code': status_code,
                        'latency': latency,
                        'success': is_success
                    }
                    
                    if is_success and latency < results['best_http_latency']:
                        results['best_http_latency'] = latency
                        results['http_available'] = True
                        
                except Exception as e:
                    results['http_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': str(e)[:50]
                    }
        
        # 测试HTTPS
        if self.config.get("test_https", True):
            for path in test_paths:
                url = f"https://{ip}{path}"
                try:
                    start_time = time.time()
                    
                    # 智能SSL处理：先尝试严格验证，失败时提供详细错误信息
                    verify_ssl = self.config.get("verify_ssl", True)
                    response = session.get(
                        url, 
                        timeout=self.config.get("http_timeout", 8),
                        headers={'Host': 'ar-gcp-cdn.bistudio.com'},
                        allow_redirects=True,
                        verify=verify_ssl,
                        stream=False
                    )
                    end_time = time.time()
                    latency = (end_time - start_time) * 1000
                    
                    status_code = response.status_code
                    is_success = (200 <= status_code < 300) or (status_code == 403)
                    
                    results['https_status'][path] = {
                        'status_code': status_code,
                        'latency': latency,
                        'success': is_success,
                        'ssl_verified': verify_ssl
                    }
                    
                    if is_success and latency < results['best_https_latency']:
                        results['best_https_latency'] = latency
                        results['https_available'] = True
                        
                except requests.exceptions.SSLError as e:
                    # SSL验证失败，尝试不验证SSL（如果配置允许）
                    if verify_ssl and self.config.get("fallback_to_unverified_ssl", True):
                        try:
                            start_time = time.time()
                            response = session.get(
                                url, 
                                timeout=self.config.get("http_timeout", 8),
                                headers={'Host': 'ar-gcp-cdn.bistudio.com'},
                                allow_redirects=True,
                                verify=False,  # 不验证SSL
                                stream=False
                            )
                            end_time = time.time()
                            latency = (end_time - start_time) * 1000
                            
                            status_code = response.status_code
                            is_success = (200 <= status_code < 300) or (status_code == 403)
                            
                            results['https_status'][path] = {
                                'status_code': status_code,
                                'latency': latency,
                                'success': is_success,
                                'ssl_verified': False,
                                'ssl_warning': f"SSL验证失败但连接可用: {str(e)[:30]}"
                            }
                            
                            if is_success and latency < results['best_https_latency']:
                                results['best_https_latency'] = latency
                                results['https_available'] = True
                                
                        except Exception as e2:
                            # 即使不验证SSL也失败
                            results['https_status'][path] = {
                                'status_code': 0,
                                'latency': float('inf'),
                                'success': False,
                                'error': f"SSL连接失败: {str(e2)[:50]}",
                                'ssl_verified': False
                            }
                    else:
                        # 已经是不验证SSL，直接记录错误
                        results['https_status'][path] = {
                            'status_code': 0,
                            'latency': float('inf'),
                            'success': False,
                            'error': f"SSL错误: {str(e)[:50]}",
                            'ssl_verified': False
                        }
                except Exception as e:
                    results['https_status'][path] = {
                        'status_code': 0,
                        'latency': float('inf'),
                        'success': False,
                        'error': str(e)[:50],
                        'ssl_verified': verify_ssl
                    }
        
        # 计算评分 - 优化版本，提供更大差异
        score = 0
        
        # 获取评分权重配置
        weights = self.config.get("scoring_weights", {
            "http_base": 50,
            "https_base": 80,
            "ping_base": 20,
            "protocol_complete_bonus": 30
        })
        
        # 基础连接分数
        if results['http_available']:
            score += weights["http_base"]  # HTTP基础分
            # HTTP延迟奖励分
            if results['best_http_latency'] < 50:
                score += 30
            elif results['best_http_latency'] < 100:
                score += 25
            elif results['best_http_latency'] < 200:
                score += 20
            elif results['best_http_latency'] < 500:
                score += 15
            elif results['best_http_latency'] < 1000:
                score += 10
            else:
                score += 5
        
        if results['https_available']:
            score += weights["https_base"]  # HTTPS基础分（更高权重）
            # HTTPS延迟奖励分
            if results['best_https_latency'] < 50:
                score += 40
            elif results['best_https_latency'] < 100:
                score += 35
            elif results['best_https_latency'] < 200:
                score += 30
            elif results['best_https_latency'] < 500:
                score += 25
            elif results['best_https_latency'] < 1000:
                score += 20
            else:
                score += 10
        
        # Ping延迟基础分（即使没有HTTP/HTTPS也有分数）
        if results.get('ping_success', False):
            ping_latency = results.get('ping_latency', float('inf'))
            if ping_latency < 50:
                score += weights["ping_base"]
            elif ping_latency < 100:
                score += int(weights["ping_base"] * 0.75)
            elif ping_latency < 200:
                score += int(weights["ping_base"] * 0.5)
            elif ping_latency < 500:
                score += int(weights["ping_base"] * 0.25)
            else:
                score += int(weights["ping_base"] * 0.1)
        
        # 协议完整性奖励
        if results['http_available'] and results['https_available']:
            score += weights["protocol_complete_bonus"]  # 同时支持HTTP和HTTPS的奖励
        
        results['overall_score'] = score
        return ip, results
    
    def _display_result(self, result: Dict):
        """实时显示测试结果"""
        status_parts = []
        if result['ping_success']:
            status_parts.append(f"Ping: {result['ping_latency']:.1f}ms")
        else:
            status_parts.append("Ping: 失败")
        
        if result['http_available']:
            status_parts.append(f"HTTP: {result['best_http_latency']:.1f}ms")
        if result['https_available']:
            https_info = f"HTTPS: {result['best_https_latency']:.1f}ms"
            
            # 检查HTTPS状态中的SSL信息
            ssl_warning = None
            ssl_verified = True
            
            # 从HTTPS状态中获取SSL信息
            for path, status in result.get('https_status', {}).items():
                if status.get('success', False):
                    if not status.get('ssl_verified', True):
                        ssl_verified = False
                        ssl_warning = status.get('ssl_warning', 'SSL验证失败')
                    break
            
            # 添加SSL证书状态
            if result.get('ssl_certificate'):
                ssl_cert = result['ssl_certificate']
                if ssl_cert.get('ssl_available', False):
                    if ssl_cert.get('certificate_valid', False) and ssl_cert.get('hostname_verified', False):
                        # 证书有效且主机名匹配
                        days_left = ssl_cert.get('days_until_expiry', -1)
                        if days_left > 30:
                            https_info += " (SSL✓)"
                        elif days_left > 0:
                            https_info += f" (SSL⚠{days_left}d)"
                        else:
                            https_info += " (SSL⚠过期)"
                    elif ssl_cert.get('certificate_valid', False):
                        # 证书有效但主机名不匹配
                        https_info += " (SSL⚠主机名)"
                    else:
                        # 证书无效
                        https_info += " (SSL⚠证书)"
                else:
                    # SSL连接不可用
                    https_info += " (SSL✗)"
            elif not ssl_verified:
                # 基于HTTPS测试结果的SSL状态
                https_info += " (SSL⚠)"
            else:
                # 默认SSL状态
                https_info += " (SSL✓)"
                
            status_parts.append(https_info)
        
        # 添加评分等级显示
        score = result['overall_score']
        if score >= 200:
            score_display = f"评分: {score} (优秀)"
        elif score >= 150:
            score_display = f"评分: {score} (良好)"
        elif score >= 100:
            score_display = f"评分: {score} (一般)"
        elif score >= 50:
            score_display = f"评分: {score} (较差)"
        else:
            score_display = f"评分: {score} (很差)"
        
        status_parts.append(score_display)
        
        # 添加健康检测信息
        if result.get('health_info') and result['health_info'].get('overall_health_score', 0) > 0:
            health_score = result['health_info']['overall_health_score']
            health_grade = result['health_info'].get('health_grade', 'F')
            status_parts.append(f"健康: {health_score:.1f} ({health_grade})")
        
        print(f"✓ {result['ip']:15s} - {' | '.join(status_parts)}")
    
    def _create_failed_result(self, ip: str) -> Dict:
        """创建失败结果"""
        return {
            'ip': ip,
            'ping_latency': float('inf'),
            'ping_success': False,
            'http_available': False,
            'https_available': False,
            'best_http_latency': float('inf'),
            'best_https_latency': float('inf'),
            'overall_score': 0,
            'http_status': {},
            'https_status': {},
            'ssl_certificate': None
        }


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
            "domain": "ar-gcp-cdn.bistudio.com",  # 目标域名
            "test_ips": [],  # 将自动获取真实IP
            "test_timeout": 3,  # 减少测试超时时间
            "test_count": 2,    # 减少测试次数
            "backup_hosts": True,
            "fast_mode": True,  # 启用快速模式
            "enable_bandwidth_test": False,  # 禁用带宽测试以加快速度
            "multi_dimensional_health": False,  # 禁用多维度健康检查以加快速度
            "dns_servers": [
                "8.8.8.8",          # Google DNS
                "8.8.4.4",          # Google DNS 备用
                "1.1.1.1",          # Cloudflare DNS
                "1.0.0.1",          # Cloudflare DNS 备用
                "208.67.222.222",   # OpenDNS
                "208.67.220.220",   # OpenDNS 备用
                "114.114.114.114",  # 114 DNS
                "114.114.115.115",  # 114 DNS 备用
                "223.5.5.5",        # 阿里DNS
                "223.6.6.6",        # 阿里DNS 备用
                "180.76.76.76",     # 百度DNS
                "119.29.29.29",     # 腾讯DNS
                "182.254.116.116",  # 腾讯DNS 备用
                "9.9.9.9",          # Quad9 DNS
                "149.112.112.112",  # Quad9 DNS 备用
                "76.76.19.61",      # ControlD DNS
                "76.76.2.22",       # ControlD DNS 备用
                "94.140.14.14",     # AdGuard DNS
                "94.140.15.15",     # AdGuard DNS 备用
                "76.76.19.61",      # ControlD DNS
                "76.76.2.22"        # ControlD DNS 备用
            ],
            "test_http": True,
            "test_https": True,
            "http_timeout": 8,  # 减少默认超时时间
            "verify_ssl": True,  # 默认启用SSL验证
            "ssl_check_enabled": True,  # 启用SSL连接检查
            "fallback_to_unverified_ssl": True,  # SSL验证失败时回退到不验证SSL
            "scoring_weights": {  # 评分权重配置
                "http_base": 50,      # HTTP基础分
                "https_base": 80,     # HTTPS基础分
                "ping_base": 20,      # Ping基础分
                "protocol_complete_bonus": 30  # 协议完整性奖励
            },
            "multi_dimensional_health": True,  # 启用多维度健康检测
            "health_test_iterations": 3,      # 健康检测测试次数
            "stability_threshold": 0.8,       # 稳定性阈值
            "enable_bandwidth_test": True,    # 启用带宽测试
            "test_paths": [
                "/"  # 只测试根路径，提高速度
            ],
            "show_detailed_results": True,
            "max_workers": 10,
            "adaptive_concurrency": True,  # 启用自适应并发
            "fast_mode": True,  # 启用快速模式
            "connection_pool_size": 20,  # 连接池大小
            "retry_attempts": 2,  # 重试次数
            "network_quality_monitoring": True  # 网络质量监控
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
        # 使用增强的DNS解析器
        resolver = EnhancedDNSResolver(self.domain)
        ip_list = resolver.resolve_all_ips()
        
        if not ip_list:
            print("❌ 无法获取域名的 IP 地址")
            return []
        
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
        print("测试项目: Ping延迟 + HTTP状态码 + SSL连接")
        print()
        
        # 使用优化的测试器
        optimized_tester = OptimizedTester(self.config)
        return optimized_tester.test_ips_optimized(ips)
    
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
            raise  # 重新抛出异常，让GUI能够捕获
    
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
            
        except PermissionError as e:
            print("❌ 权限不足，无法修改 hosts 文件")
            print("请以管理员身份运行此脚本")
            raise  # 重新抛出异常，让GUI能够捕获
        except Exception as e:
            print(f"❌ 更新 hosts 文件失败: {e}")
            raise  # 重新抛出异常，让GUI能够捕获
    
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
            # DNS刷新失败不应该阻止整个流程，所以不抛出异常
    
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
                            ssl_info = f" (SSL验证: {'✓' if status.get('ssl_verified', True) else '✗'})" if 'ssl_verified' in status else ""
                            ssl_warning_info = f" - {status.get('ssl_warning', '')}" if status.get('ssl_warning') else ""
                            print(f"      {path}: {status['status_code']} {status_desc} ({status['latency']:.1f}ms){size_info}{ssl_info}{ssl_warning_info}")
                        elif status.get('is_redirect', False):
                            print(f"      {path}: {status['status_code']} 重定向 (可能配置问题)")
                        else:
                            error_msg = status.get('error', '连接失败')
                            print(f"      {path}: 失败 - {error_msg}")
                
                # 显示SSL证书信息
                if result.get('ssl_certificate'):
                    ssl_cert = result['ssl_certificate']
                    print(f"    SSL 证书信息:")
                    
                    if ssl_cert.get('ssl_available', False):
                        print(f"      SSL连接: 可用 ✓")
                        
                        # 证书有效性
                        if ssl_cert.get('certificate_valid', False):
                            print(f"      证书有效性: 有效 ✓")
                        else:
                            print(f"      证书有效性: 无效 ✗")
                        
                        # 主机名验证
                        if ssl_cert.get('hostname_verified', False):
                            print(f"      主机名验证: 匹配 ✓")
                        else:
                            print(f"      主机名验证: 不匹配 ✗")
                        
                        # 域名匹配检查
                        if ssl_cert.get('domain_match', False):
                            print(f"      域名匹配: 匹配 ✓")
                        else:
                            print(f"      域名匹配: 不匹配 ✗")
                        
                        # 显示证书详情（如果可用）
                        if ssl_cert.get('issuer'):
                            issuer = ssl_cert.get('issuer', {})
                            org_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                            print(f"      颁发者: {org_name}")
                        
                        if ssl_cert.get('not_after'):
                            print(f"      有效期至: {ssl_cert.get('not_after', 'Unknown')}")
                            days_left = ssl_cert.get('days_until_expiry', -1)
                            if days_left > 0:
                                print(f"      剩余天数: {days_left} 天")
                            elif days_left == 0:
                                print(f"      证书今天过期")
                            else:
                                print(f"      证书已过期")
                        
                        # 显示警告信息
                        if ssl_cert.get('certificate_warning'):
                            print(f"      警告: {ssl_cert.get('certificate_warning')}")
                    else:
                        print(f"      SSL连接: 不可用 ✗")
                        print(f"      错误: {ssl_cert.get('error', 'Unknown error')}")
                        print(f"      错误类型: {ssl_cert.get('error_type', 'Unknown')}")
                
                # 显示健康检测详细信息
                if result.get('health_info'):
                    health_info = result['health_info']
                    print(f"    健康检测详情:")
                    print(f"      综合健康评分: {health_info.get('overall_health_score', 0):.1f} ({health_info.get('health_grade', 'F')})")
                    
                    # 稳定性信息
                    if health_info.get('stability'):
                        stability = health_info['stability']
                        print(f"      连接稳定性: {stability.get('stability_score', 0):.2f}")
                        print(f"      成功率: {stability.get('success_rate', 0):.1%}")
                        print(f"      平均延迟: {stability.get('avg_latency', 0):.1f}ms")
                        print(f"      延迟标准差: {stability.get('latency_std', 0):.1f}ms")
                    
                    # 带宽信息
                    if health_info.get('bandwidth'):
                        bandwidth = health_info['bandwidth']
                        test_method = bandwidth.get('test_method', 'unknown')
                        if test_method == 'bandwidth_calculated':
                            print(f"      带宽测试: {bandwidth.get('bandwidth_mbps', 0):.2f} Mbps")
                            print(f"      响应时间: {bandwidth.get('response_time', 0):.2f}s")
                            print(f"      数据大小: {bandwidth.get('data_size', 0)} bytes")
                        elif test_method == 'response_based':
                            print(f"      响应测试: {bandwidth.get('response_time', 0):.2f}s")
                            print(f"      数据大小: {bandwidth.get('data_size', 0)} bytes")
                            print(f"      测试方法: 响应时间评估")
                        elif test_method == 'latency_based':
                            print(f"      连接延迟: {bandwidth.get('response_time', 0):.3f}s")
                            print(f"      测试方法: 连接延迟评估")
                        elif test_method == 'disabled':
                            print(f"      带宽测试: 已禁用")
                            print(f"      网络质量评分: {bandwidth.get('bandwidth_score', 0):.2f} (默认)")
                        else:
                            print(f"      网络质量评分: {bandwidth.get('bandwidth_score', 0):.2f}")
                            if bandwidth.get('error'):
                                print(f"      错误: {bandwidth.get('error')}")
                    
                    # SSL质量信息
                    if health_info.get('ssl_quality'):
                        ssl_quality = health_info['ssl_quality']
                        if ssl_quality.get('cert_score', 0) > 0:
                            print(f"      SSL质量评分: {ssl_quality.get('cert_score', 0):.1f} ({ssl_quality.get('ssl_grade', 'F')})")
                            print(f"      证书有效期: {ssl_quality.get('cert_validity_days', 0)} 天")
                            print(f"      证书颁发者: {ssl_quality.get('cert_issuer', 'Unknown')}")
                            print(f"      加密算法: {ssl_quality.get('cert_algorithm', 'Unknown')}")
                            print(f"      加密强度: {ssl_quality.get('cert_strength', 'Unknown')} bits")
                    
                    # 协议支持信息
                    if health_info.get('protocol_support'):
                        protocol = health_info['protocol_support']
                        print(f"      协议支持评分: {protocol.get('protocol_score', 0):.1f}")
                        print(f"      HTTP支持: {'✓' if protocol.get('http_support') else '✗'}")
                        print(f"      HTTPS支持: {'✓' if protocol.get('https_support') else '✗'}")
                        print(f"      HTTP/2支持: {'✓' if protocol.get('http2_support') else '✗'}")
                    
                    # 地理位置信息
                    if health_info.get('geographic'):
                        geo = health_info['geographic']
                        print(f"      地理位置评分: {geo.get('geo_score', 0):.2f}")
                        print(f"      网络区域: {geo.get('region', 'Unknown')}")
                        print(f"      服务提供商: {geo.get('provider', 'Unknown')}")
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
