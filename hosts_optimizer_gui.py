#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hosts optimization tool GUI version.

This module provides a graphical user interface for testing different IP addresses
of ar-gcp-cdn.bistudio.com and selecting the optimal IP to update the hosts file.
"""

import json
import platform
import queue
import socket
import statistics
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import dns.resolver
import requests
import ssl
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

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


class EnhancedDNSResolver:
    """Enhanced DNS resolver.
    
    This class provides advanced DNS resolution capabilities with caching
    and verification to avoid DNS pollution and get accurate IP addresses.
    """
    
    def __init__(self, domain: str) -> None:
        """Initialize the DNS resolver.
        
        Args:
            domain: The domain name to resolve.
        """
        self.domain = domain
        self.found_ips: set = set()
        self.dns_cache: Dict = {}  # DNS query cache
        self.verified_ips: set = set()  # Verified IPs
        self.dns_servers: set = set()  # DNS服务器IP集合，用于过滤
        
    def resolve_all_ips(self) -> List[str]:
        """Resolve domain IPs using true parallel mode (avoiding local DNS).
        
        Returns:
            List of unique IP addresses found.
        """
        print(f"正在全面解析 {self.domain} 的IP地址...")
        print("⚠️ 注意：为避免DNS污染，优先使用权威DNS服务器")
        print("🚀 使用并行模式，所有DNS服务器同时查询...")
        
        # Collect all DNS servers
        all_dns_servers = self._collect_all_dns_servers()
        self.dns_servers = set(all_dns_servers)  # 保存DNS服务器IP用于过滤
        print(f"📡 共收集到 {len(all_dns_servers)} 个权威DNS服务器")
        
        # Track statistics
        successful_queries = 0
        failed_queries = 0
        error_details = []
        
        # Query all DNS servers in parallel
        with ThreadPoolExecutor(max_workers=min(50, len(all_dns_servers))) as executor:
            futures = {
                executor.submit(self._query_single_dns, dns_server): dns_server 
                for dns_server in all_dns_servers
            }
            
            completed = 0
            try:
                for future in as_completed(futures, timeout=30):  # 增加超时时间到30秒
                    try:
                        result = future.result(timeout=5)
                        if result:
                            successful_queries += 1
                        else:
                            failed_queries += 1
                        completed += 1
                        if completed % 10 == 0:  # Show progress every 10 completions
                            print(f"📊 DNS查询进度: {completed}/{len(all_dns_servers)} (成功: {successful_queries}, 失败: {failed_queries})")
                    except Exception as e:
                        failed_queries += 1
                        completed += 1
                        error_details.append(str(e)[:50])
                        if len(error_details) <= 5:  # 只记录前5个错误
                            print(f"⚠️ DNS查询异常: {str(e)[:100]}")
            except Exception as e:
                print(f"⚠️ DNS查询超时或异常: {str(e)[:100]}")
        
        print(f"📊 DNS查询完成: 成功 {successful_queries} 个, 失败 {failed_queries} 个")
        
        # 如果通过权威DNS没有找到IP，尝试使用本地DNS作为回退
        if len(self.found_ips) == 0:
            print("⚠️ 所有权威DNS服务器查询失败，尝试使用本地DNS作为回退...")
            try:
                # 使用系统默认DNS
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                answers = resolver.resolve(self.domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    should_filter, reason = self._should_filter_ip(ip)
                    if not should_filter:
                        self.found_ips.add(ip)
                        print(f"✓ 本地DNS: {ip}")
                    else:
                        print(f"⚠️ 本地DNS (已过滤): {ip} - {reason}")
            except Exception as e:
                print(f"⚠️ 本地DNS查询也失败: {str(e)[:100]}")
        
        # 如果仍然没有找到IP，尝试使用socket.gethostbyname作为最后回退
        if len(self.found_ips) == 0:
            print("⚠️ 尝试使用系统默认解析作为最后回退...")
            try:
                ip = socket.gethostbyname(self.domain)
                should_filter, reason = self._should_filter_ip(ip)
                if not should_filter:
                    self.found_ips.add(ip)
                    print(f"✓ 系统解析: {ip}")
                else:
                    print(f"⚠️ 系统解析 (已过滤): {ip} - {reason}")
            except Exception as e:
                print(f"⚠️ 系统解析也失败: {str(e)[:100]}")
        
        # 如果找到IP，进行验证（但不强制要求验证通过）
        if len(self.found_ips) > 0:
            print(f"\n找到 {len(self.found_ips)} 个IP地址，开始验证...")
            self._verify_found_ips()
        else:
            print("❌ 所有DNS解析方法都失败，无法获取IP地址")
            print("💡 请检查:")
            print("   1. 网络连接是否正常")
            print("   2. 防火墙是否阻止了DNS查询")
            print("   3. 是否使用了VPN或代理")
            print("   4. DNS服务器是否可访问")
        
        # 最终过滤：确保所有返回的IP都是有效的
        final_ips = []
        final_filtered_count = 0
        for ip in self.found_ips:
            should_filter, reason = self._should_filter_ip(ip)
            if not should_filter:
                final_ips.append(ip)
            else:
                final_filtered_count += 1
                print(f"⚠️ 最终过滤: {ip} - {reason}")
        
        if final_filtered_count > 0:
            print(f"📊 最终过滤掉 {final_filtered_count} 个无效IP地址")
        
        print(f"\n总共找到 {len(final_ips)} 个有效IP地址:")
        for i, ip in enumerate(final_ips, 1):
            print(f"{i:2d}. {ip}")
        
        return final_ips
    
    def _collect_all_dns_servers(self) -> List[str]:
        """Collect all available DNS servers.
        
        Returns:
            List of DNS server IP addresses.
        """
        all_servers = []
        
        # Major public DNS servers
        all_servers.extend([
            "8.8.8.8", "8.8.4.4",  # Google DNS
            "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
            "208.67.222.222", "208.67.220.220",  # OpenDNS
            "9.9.9.9", "149.112.112.112",  # Quad9 DNS
        ])
        
        # Chinese major DNS servers
        all_servers.extend([
            "114.114.114.114", "114.114.115.115",  # 114 DNS
            "223.5.5.5", "223.6.6.6",  # 阿里DNS
            "180.76.76.76",  # 百度DNS
            "119.29.29.29", "182.254.116.116",  # 腾讯DNS
            "117.50.10.10", "52.80.52.52",  # 腾讯DNS备用
            "123.125.81.6", "123.125.81.7",  # 百度DNS备用
        ])
        
        # International authoritative DNS servers
        all_servers.extend([
            "76.76.19.61", "76.76.2.22",  # ControlD
            "94.140.14.14", "94.140.15.15",  # AdGuard DNS
            "185.228.168.9", "185.228.169.9",  # CleanBrowsing
            "84.200.69.80", "84.200.70.40",  # DNS.WATCH
            "8.26.56.26", "8.20.247.20",  # Comodo Secure DNS
            "195.46.39.39", "195.46.39.40",  # SafeDNS
            "77.88.8.8", "77.88.8.1",  # Yandex DNS
            "45.90.28.0", "45.90.30.0",  # NextDNS
            "9.9.9.10", "149.112.112.10",  # Quad9 (过滤)
            "1.1.1.2", "1.0.0.2",  # Cloudflare (过滤)
            "1.1.1.3", "1.0.0.3",  # Cloudflare (恶意软件过滤)
        ])
        
        # CDN and cloud service provider DNS
        all_servers.extend([
            "199.85.126.10", "199.85.127.10",  # Norton ConnectSafe
            "156.154.70.1", "156.154.71.1",  # Neustar DNS
            "64.6.64.6", "64.6.65.6",  # Verisign DNS
            "205.251.198.6", "205.251.198.7",  # AWS DNS
            "205.251.199.6", "205.251.199.7",  # AWS DNS备用
            "168.63.129.16",  # Azure DNS
            "40.74.0.1", "40.74.0.2",  # Azure公共DNS
        ])
        
        # Regional specific DNS servers
        all_servers.extend([
            "168.126.63.1", "168.126.63.2",  # 韩国DNS
            "202.106.0.20", "202.106.46.151",  # 中国电信DNS
            "202.96.209.5", "202.96.209.133",  # 中国联通DNS
        ])
        
        # Remove duplicates and return
        return list(set(all_servers))
    
    def _query_single_dns(self, dns_server: str) -> bool:
        """Query a single DNS server.
        
        Args:
            dns_server: The DNS server IP address to query.
            
        Returns:
            True if query was successful, False otherwise.
        """
        # Check cache
        cache_key = f"{dns_server}_{self.domain}"
        if cache_key in self.dns_cache:
            cached_ips = self.dns_cache[cache_key]
            for ip in cached_ips:
                should_filter, reason = self._should_filter_ip(ip)
                if not should_filter:
                    self.found_ips.add(ip)
                    print(f"✓ {dns_server} (缓存): {ip}")
                else:
                    print(f"⚠️ {dns_server} (缓存，已过滤): {ip} - {reason}")
            return True
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = 3  # 增加超时时间到3秒
            resolver.lifetime = 5  # 增加总超时时间到5秒
            
            answers = resolver.resolve(self.domain, 'A')
            found_ips = []
            for answer in answers:
                ip = str(answer)
                should_filter, reason = self._should_filter_ip(ip)
                if not should_filter:
                    self.found_ips.add(ip)
                    found_ips.append(ip)
                    print(f"✓ {dns_server}: {ip}")
                else:
                    print(f"⚠️ {dns_server} (已过滤): {ip} - {reason}")
            
            # Cache results
            if found_ips:
                self.dns_cache[cache_key] = found_ips
                return True
            else:
                return False
                
        except dns.resolver.NXDOMAIN:
            # 域名不存在
            return False
        except dns.resolver.Timeout:
            # 超时
            return False
        except dns.resolver.NoAnswer:
            # 无答案
            return False
        except Exception:
            # 其他错误，记录但不输出（避免输出过多）
            return False
    
    def _verify_found_ips(self) -> None:
        """Verify found IP addresses are real and valid (fast mode).
        
        注意：如果验证失败，仍然保留IP地址，因为有些IP可能只支持HTTPS或特定端口。
        同时会过滤掉局域网IP和DNS服务器IP。
        """
        print("\n正在快速验证IP地址有效性...")
        print("💡 提示：即使验证失败，IP地址仍会被保留（某些IP可能只支持HTTPS）")
        
        # 先过滤掉应该被排除的IP
        filtered_count = 0
        ips_to_verify = []
        for ip in self.found_ips:
            should_filter, reason = self._should_filter_ip(ip)
            if should_filter:
                filtered_count += 1
                print(f"⚠️ 验证前已过滤: {ip} - {reason}")
            else:
                ips_to_verify.append(ip)
        
        if filtered_count > 0:
            print(f"📊 已过滤 {filtered_count} 个无效IP地址（局域网IP或DNS服务器IP）")
        
        # 更新found_ips为过滤后的IP列表
        self.found_ips = set(ips_to_verify)
        
        def verify_single_ip(ip: str) -> bool:
            """Verify a single IP address.
            
            Args:
                ip: The IP address to verify.
                
            Returns:
                True if the IP is valid, False otherwise.
            """
            # 尝试多个端口：80 (HTTP) 和 443 (HTTPS)
            ports_to_try = [80, 443]
            
            for port in ports_to_try:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)  # 增加超时时间到2秒
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        self.verified_ips.add(ip)
                        print(f"✓ 验证通过: {ip} (端口 {port})")
                        return True
                except Exception:
                    continue
            
            # 如果所有端口都失败，仍然保留IP（可能只是暂时不可用）
            print(f"⚠️ 验证未通过: {ip} (但会保留，可能在后续测试中可用)")
            return False
        
        # Verify IP addresses in parallel with increased concurrency
        verified_count = 0
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(verify_single_ip, ip): ip for ip in self.found_ips}
            
            for future in as_completed(futures, timeout=30):  # 增加总体超时
                try:
                    if future.result(timeout=5):
                        verified_count += 1
                except Exception:
                    continue
        
        # 保留所有找到的IP，包括未验证通过的（因为验证可能过于严格）
        # 只将验证通过的IP添加到verified_ips集合中，但保留所有IP在found_ips中
        print(f"验证完成: {verified_count} 个IP验证通过, 共 {len(self.found_ips)} 个IP地址")
        
        # 如果验证通过的IP为空，但found_ips不为空，说明验证可能过于严格
        # 在这种情况下，保留所有IP，让后续的HTTP/HTTPS测试来决定
        if len(self.verified_ips) == 0 and len(self.found_ips) > 0:
            print("⚠️ 所有IP验证未通过，但会保留所有IP进行后续测试")
            # 将所有IP添加到verified_ips，以便后续使用
            self.verified_ips = self.found_ips.copy()
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if the given string is a valid IP address.
        
        Args:
            ip: The string to check.
            
        Returns:
            True if the string is a valid IP address, False otherwise.
        """
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if the IP address is a private/local network IP.
        
        Args:
            ip: The IP address to check.
            
        Returns:
            True if the IP is a private IP, False otherwise.
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            
            # 127.0.0.0/8 (回环地址)
            if first == 127:
                return True
            
            # 169.254.0.0/16 (链路本地地址)
            if first == 169 and second == 254:
                return True
            
            return False
        except (ValueError, IndexError):
            return False
    
    def _is_dns_server_ip(self, ip: str) -> bool:
        """Check if the IP address is a DNS server IP.
        
        Args:
            ip: The IP address to check.
            
        Returns:
            True if the IP is a DNS server IP, False otherwise.
        """
        return ip in self.dns_servers
    
    def _should_filter_ip(self, ip: str) -> Tuple[bool, str]:
        """Check if an IP should be filtered out.
        
        Args:
            ip: The IP address to check.
            
        Returns:
            Tuple of (should_filter, reason). should_filter is True if IP should be filtered.
        """
        if not self._is_valid_ip(ip):
            return (True, "无效的IP地址格式")
        
        if self._is_private_ip(ip):
            return (True, "局域网/私有IP地址")
        
        if self._is_dns_server_ip(ip):
            return (True, "DNS服务器IP地址")
        
        return (False, "")


class NetworkQuality:
    """Real-time network quality assessment.
    
    This class monitors network performance metrics and provides quality
    factors for adaptive concurrency management.
    """
    
    def __init__(self) -> None:
        """Initialize network quality monitor."""
        self.recent_latencies: List[float] = []
        self.recent_errors: List[float] = []
        self.max_history: int = 10
    
    def get_quality_factor(self) -> float:
        """Get network quality factor (0.5-2.0).
        
        Returns:
            Quality factor based on latency and error rate.
        """
        if not self.recent_latencies:
            return 1.0
        
        avg_latency = sum(self.recent_latencies) / len(self.recent_latencies)
        error_rate = len(self.recent_errors) / max(len(self.recent_latencies), 1)
        
        # Calculate quality factor based on latency and error rate
        if avg_latency < 50 and error_rate < 0.1:
            return 2.0  # Excellent network, can use high concurrency
        elif avg_latency < 100 and error_rate < 0.2:
            return 1.5  # Good network
        elif avg_latency < 200 and error_rate < 0.3:
            return 1.0  # Average network
        else:
            return 0.5  # Poor network, reduce concurrency
    
    def update_metrics(self, latency: float, success: bool) -> None:
        """Update network quality metrics.
        
        Args:
            latency: Network latency in milliseconds.
            success: Whether the operation was successful.
        """
        self.recent_latencies.append(latency)
        if not success:
            self.recent_errors.append(time.time())
        
        # Keep history within reasonable limits
        if len(self.recent_latencies) > self.max_history:
            self.recent_latencies.pop(0)
        if len(self.recent_errors) > self.max_history:
            self.recent_errors.pop(0)


class AdaptiveConcurrencyManager:
    """Adaptive concurrency manager.
    
    This class dynamically adjusts concurrency based on network conditions
    to optimize performance and resource usage.
    """
    
    def __init__(self) -> None:
        """Initialize the adaptive concurrency manager."""
        self.base_workers: int = 10  # Increased base concurrency
        self.max_workers: int = 50   # Increased max concurrency
        self.network_quality: NetworkQuality = NetworkQuality()
        self.adaptive_mode: bool = True
    
    def get_optimal_workers(self, total_ips: int) -> int:
        """Calculate optimal concurrency based on network quality and IP count.
        
        Args:
            total_ips: Total number of IPs to process.
            
        Returns:
            Optimal number of worker threads.
        """
        if not self.adaptive_mode:
            return min(self.base_workers, total_ips)
        
        # Adjust base concurrency based on network quality
        quality_factor = self.network_quality.get_quality_factor()
        adjusted_workers = int(self.base_workers * quality_factor)
        
        # Adjust based on IP count
        if total_ips <= 5:
            return min(3, total_ips)  # Reduce concurrency for small IP counts
        elif total_ips <= 15:
            return min(adjusted_workers, total_ips)
        else:
            return min(self.max_workers, total_ips)


class OptimizedConnectionManager:
    """Optimized connection manager.
    
    This class manages HTTP connections with pooling and retry strategies
    to optimize network performance and resource usage.
    """
    
    def __init__(self, config: Optional[Dict] = None) -> None:
        """Initialize the connection manager.
        
        Args:
            config: Configuration dictionary for connection settings.
        """
        self.config = config or {}
        self.session_pool: Dict[str, requests.Session] = {}
        self.connection_pool: Optional[HTTPAdapter] = None
        self._setup_connection_pool()
    
    def _setup_connection_pool(self) -> None:
        """Setup connection pool."""
        # Get parameters from config
        retry_attempts = self.config.get("retry_attempts", 2)
        pool_size = self.config.get("connection_pool_size", 20)
        
        # Create optimized HTTP adapter
        retry_strategy = Retry(
            total=retry_attempts,  # Get retry count from config
            backoff_factor=0.1,  # Fast retry
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        self.connection_pool = HTTPAdapter(
            pool_connections=pool_size,  # Get pool size from config
            pool_maxsize=pool_size,
            max_retries=retry_strategy,
            pool_block=False  # Non-blocking mode
        )
    
    def get_session(self, ip: str) -> requests.Session:
        """Get or create a session for the given IP.
        
        Args:
            ip: The IP address for the session.
            
        Returns:
            A requests Session object.
        """
        if ip not in self.session_pool:
            session = requests.Session()
            session.mount("http://", self.connection_pool)
            session.mount("https://", self.connection_pool)
            
            # Optimize session configuration
            session.headers.update({
                'User-Agent': 'HostsOptimizer/1.0',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate'
            })
            
            self.session_pool[ip] = session
        
        return self.session_pool[ip]
    
    def cleanup(self) -> None:
        """Clean up connection pool."""
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
        except (requests.RequestException, Exception):
            pass
        
        # HTTPS支持
        try:
            response = requests.get(f"https://{ip}/", headers={'Host': domain}, timeout=5, verify=False)
            results['https_support'] = response.status_code in [200, 301, 302, 403]
        except (requests.RequestException, Exception):
            pass
        
        # 计算协议评分
        protocol_score = 0
        if results['http_support']:
            protocol_score += 25
        if results['https_support']:
            protocol_score += 50
        
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
                
        except (ValueError, KeyError, Exception):
            pass
        
        return results
    
    def comprehensive_health_check(self, ip: str, domain: str) -> Dict:
        """综合健康检查"""
        health_results = {
            'ip': ip,
            'overall_health_score': 0.0,
            'stability': {},
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
            
            for key, future in futures.items():
                try:
                    health_results[key] = future.result(timeout=5)  # 减少超时时间
                except Exception as e:
                    health_results[key] = {'error': str(e)}
        
        # 计算综合健康评分
        scores = []
        
        # 稳定性评分 (40%)
        if 'stability_score' in health_results['stability']:
            scores.append(health_results['stability']['stability_score'] * 0.4)
        
        # SSL质量评分 (30%)
        if 'cert_score' in health_results['ssl_quality']:
            scores.append(health_results['ssl_quality']['cert_score'] / 100 * 0.3)
        
        # 协议支持评分 (20%)
        if 'protocol_score' in health_results['protocol_support']:
            scores.append(health_results['protocol_support']['protocol_score'] / 100 * 0.2)
        
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
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError, Exception):
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
            ssl_verified = True
            
            # 从HTTPS状态中获取SSL信息
            for path, status in result.get('https_status', {}).items():
                if status.get('success', False):
                    if not status.get('ssl_verified', True):
                        ssl_verified = False
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
        self.test_urls = [
            f"http://{domain}/",
            f"https://{domain}/",
            f"http://{domain}/api/health",
            f"https://{domain}/api/health"
        ]
        
        # 硬编码配置 - 专为Arma Reforger优化
        self.config = {
            "backup_hosts": True,
            "test_timeout": 5,
            "test_count": 3,
            "test_http": True,
            "test_https": True,
            "http_timeout": 8,
            "verify_ssl": True,
            "ssl_check_enabled": True,
            "fallback_to_unverified_ssl": True,
            "scoring_weights": {
                "http_base": 50,
                "https_base": 80,
                "ping_base": 20,
                "protocol_complete_bonus": 30
            },
            "multi_dimensional_health": True,
            "health_test_iterations": 3,
            "stability_threshold": 0.8,
            "test_paths": ["/"],
            "show_detailed_results": True,
            "max_workers": 10,
            "adaptive_concurrency": True,
            "fast_mode": True,
            "connection_pool_size": 20,
            "retry_attempts": 2,
            "network_quality_monitoring": True
        }
        
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
    
    def _get_hosts_file_path(self) -> str:
        """获取系统 hosts 文件路径"""
        system = platform.system().lower()
        if system == "windows":
            return r"C:\Windows\System32\drivers\etc\hosts"
        elif system == "darwin":  # macOS
            return "/etc/hosts"
        else:  # Linux
            return "/etc/hosts"
    
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
            
        except PermissionError:
            print("❌ 权限不足，无法修改 hosts 文件")
            print("请以管理员身份运行此脚本")
            raise  # 重新抛出异常，让GUI能够捕获
        except Exception as ex:
            print(f"❌ 更新 hosts 文件失败: {ex}")
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
    
    def save_config(self):
        """保存配置到文件"""
        try:
            with open('hosts_config.json', 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置失败: {e}")


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
                self.log_message("❌ 无法获取域名的 IP 地址", "ERROR")
                self.log_detailed("DNS 解析失败，无法获取任何 IP 地址", "ERROR", "DNS_RESOLVE")
                self.log_message("💡 请检查:", "INFO")
                self.log_message("   1. 网络连接是否正常", "INFO")
                self.log_message("   2. 防火墙是否阻止了DNS查询", "INFO")
                self.log_message("   3. 是否使用了VPN或代理", "INFO")
                self.log_message("   4. DNS服务器是否可访问", "INFO")
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
                self.log_message("💡 请检查:", "INFO")
                self.log_message("   1. 网络连接是否正常", "INFO")
                self.log_message("   2. 防火墙是否阻止了DNS查询", "INFO")
                self.log_message("   3. 是否使用了VPN或代理", "INFO")
                self.log_message("   4. DNS服务器是否可访问", "INFO")
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
        # 使用内置的OptimizedTester类
        
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
        
        preview_content += "📊 统计信息:\n"
        preview_content += f"   • 总IP数量: {total_ips}\n"
        preview_content += f"   • 可用IP数量: {available_ips}\n"
        preview_content += f"   • HTTPS可用: {https_available}\n"
        preview_content += "   • 注：带宽测试仅用于网络质量评估\n\n"
        
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
        
        preview_content += "\n💡 建议:\n"
        if sorted_results:
            best_ip = sorted_results[0].get('ip', 'N/A')
            best_score = sorted_results[0].get('overall_score', 0)
            preview_content += f"   • 推荐使用: {best_ip} (评分: {best_score:.1f})\n"
            preview_content += "   • 点击'更新Hosts'按钮应用最佳IP\n"
        else:
            preview_content += "   • 没有找到可用的IP地址\n"
        
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

版本: 2.2.0
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
