#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""True parallel Hosts optimizer - integrated version.

This module integrates async I/O and true parallel processing into the existing
architecture to solve serial waiting issues.
"""

import asyncio
import json
import platform
import queue
import socket
import ssl
import statistics
import subprocess
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

import aiohttp


@dataclass
class TrueParallelResult:
    """True parallel test result.
    
    This dataclass represents the result of a parallel IP test,
    containing all relevant metrics and information.
    """
    ip: str
    ping_latency: float
    ping_success: bool
    http_available: bool
    https_available: bool
    http_status: int
    https_status: int
    http_latency: float
    https_latency: float
    ssl_cert_info: Optional[Dict]
    health_info: Optional[Dict]
    overall_score: float
    test_duration: float
    timestamp: datetime


class TrueParallelTester:
    """True parallel tester - solves serial waiting issues.
    
    This class provides true parallel testing capabilities using async I/O
    to eliminate serial waiting and improve performance.
    """
    
    def __init__(self, config: Dict) -> None:
        """Initialize the true parallel tester.
        
        Args:
            config: Configuration dictionary for testing parameters.
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.connector: Optional[aiohttp.TCPConnector] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.results_queue: queue.Queue = queue.Queue()
        self.progress_callback: Optional[Callable] = None
        
    async def __aenter__(self) -> 'TrueParallelTester':
        """Async context manager entry."""
        # Create optimized connector
        max_connections = self.config.get("max_concurrent_requests", 100)
        self.semaphore = asyncio.Semaphore(max_connections)
        
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=self.config.get("max_per_host", 30),
            ttl_dns_cache=0,  # Disable DNS cache to avoid cache errors
            use_dns_cache=False,  # Disable DNS cache
            enable_cleanup_closed=True,
            force_close=False,  # Allow connection reuse to avoid connection issues
            family=0,  # Allow both IPv4 and IPv6
            ssl=False,  # Disable SSL at connector level, handle at request level
            resolver=None,  # Use default resolver
            local_addr=None,  # Don't bind to local address
            keepalive_timeout=30  # Keep connections alive
        )
        
        # Create timeout configuration
        timeout = aiohttp.ClientTimeout(
            total=self.config.get("http_timeout", 8),
            connect=self.config.get("connect_timeout", 3),
            sock_read=self.config.get("read_timeout", 5)
        )
        
        # Create session
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers={'User-Agent': 'ArmaReforgerHostsOptimizer/1.3.0-TrueParallel'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    def test_ips_true_parallel(self, ips: List[str], domain: str, progress_callback: Optional[Callable] = None) -> List[TrueParallelResult]:
        """Test IPs with true parallel processing - solves serial waiting issues.
        
        Args:
            ips: List of IP addresses to test.
            domain: Domain name for testing.
            progress_callback: Optional callback for progress updates.
            
        Returns:
            List of test results.
        """
        if not ips:
            return []
        
        self.progress_callback = progress_callback
        print(f"🚀 启动并行测试模式")
        print(f"📊 测试IP数量: {len(ips)}")
        print(f"⚡ 最大并发数: {self.config.get('max_concurrent_requests', 100)}")
        
        # Run async tests in new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(self._test_all_ips_async(ips, domain))
            return results
        finally:
            loop.close()
    
    async def _test_all_ips_async(self, ips: List[str], domain: str) -> List[TrueParallelResult]:
        """Test all IPs asynchronously.
        
        Args:
            ips: List of IP addresses to test.
            domain: Domain name for testing.
            
        Returns:
            List of test results sorted by score.
        """
        async with self:
            start_time = time.time()
            results = []
            
            # Create all test tasks - true parallel
            tasks = []
            for ip in ips:
                task = asyncio.create_task(self._test_single_ip_async(ip, domain))
                tasks.append(task)
            
            # Use as_completed to get completed tasks, achieving true parallel processing
            completed_count = 0
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                    results.append(result)
                    completed_count += 1
                    
                    # Real-time progress callback
                    if self.progress_callback:
                        self.progress_callback(completed_count, len(ips), result.ip)
                    
                    # Real-time result display
                    self._display_result(result)
                    
                    # Put result in queue for GUI use
                    self.results_queue.put(result)
                    
                except Exception as e:
                    print(f"❌ 测试异常: {e}")
                    completed_count += 1
            
            # Sort by score
            results.sort(key=lambda x: x.overall_score, reverse=True)
            
            total_time = time.time() - start_time
            print(f"\n🎉 并行测试完成！")
            print(f"⏱️  总耗时: {total_time:.2f}秒")
            print(f"📈 平均每个IP耗时: {total_time/len(ips):.2f}秒")
            print(f"🏆 最佳IP: {results[0].ip} (评分: {results[0].overall_score:.1f})")
            return results
    
    async def _test_single_ip_async(self, ip: str, domain: str) -> TrueParallelResult:
        """Test a single IP asynchronously - all tests truly parallel.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            Test result for the IP.
        """
        async with self.semaphore:  # Limit concurrency
            start_time = time.time()
            
            # Execute all test tasks in parallel
            tasks = [
                self._ping_async(ip),
                self._test_http_async(ip, domain),
                self._test_https_async(ip, domain),
                self._test_ssl_async(ip, domain),
                self._health_check_async(ip, domain),
                self._test_connection_async(ip)  # Add basic connection test
            ]
            
            # Wait for all tasks to complete - true parallel waiting
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Parse results
            ping_result = results[0] if not isinstance(results[0], Exception) else (0, False)
            http_result = results[1] if not isinstance(results[1], Exception) else {'available': False, 'status': 0, 'latency': 999}
            https_result = results[2] if not isinstance(results[2], Exception) else {'available': False, 'status': 0, 'latency': 999}
            ssl_result = results[3] if not isinstance(results[3], Exception) else None
            health_result = results[4] if not isinstance(results[4], Exception) else None
            connection_result = results[5] if not isinstance(results[5], Exception) else {'available': False, 'latency': 999}
            
            # Calculate comprehensive score
            overall_score = self._calculate_comprehensive_score(
                ping_result, http_result, https_result, ssl_result, health_result, connection_result
            )
            
            test_duration = time.time() - start_time
            
            return TrueParallelResult(
                ip=ip,
                ping_latency=ping_result[0],
                ping_success=ping_result[1],
                http_available=http_result['available'],
                https_available=https_result['available'],
                http_status=http_result['status'],
                https_status=https_result['status'],
                http_latency=http_result['latency'],
                https_latency=https_result['latency'],
                ssl_cert_info=ssl_result,
                health_info=health_result,
                overall_score=overall_score,
                test_duration=test_duration,
                timestamp=datetime.now()
            )
    
    async def _ping_async(self, ip: str) -> Tuple[float, bool]:
        """Async ping test - use thread pool to avoid blocking.
        
        Args:
            ip: IP address to ping.
            
        Returns:
            Tuple of (latency, success).
        """
        try:
            loop = asyncio.get_event_loop()
            start_time = time.time()
            
            # Execute ping in thread pool
            result = await loop.run_in_executor(
                None, 
                self._ping_sync, 
                ip, 
                self.config.get("ping_timeout", 2)
            )
            
            latency = time.time() - start_time
            return (latency if result else 999, result)
            
        except Exception:
            return (999, False)
    
    def _ping_sync(self, ip: str, timeout: int) -> bool:
        """Synchronous ping implementation.
        
        Args:
            ip: IP address to ping.
            timeout: Timeout in seconds.
            
        Returns:
            True if ping successful, False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _test_http_async(self, ip: str, domain: str) -> Dict:
        """Async HTTP test.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            Dictionary with test results.
        """
        try:
            url = f"http://{ip}/"
            start_time = time.time()
            
            # Set more complete request headers - restore Host header with correct format
            headers = {
                'Host': domain,  # Restore Host header, important for CDN servers
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Add timeout and retry mechanism
            timeout = aiohttp.ClientTimeout(
                total=10,  # Total timeout
                connect=5,  # Connection timeout
                sock_read=5  # Read timeout
            )
            
            async with self.session.get(url, headers=headers, timeout=timeout) as response:
                latency = time.time() - start_time
                # More lenient status code judgment - 403 means server is reachable but needs auth, should count as success
                available = response.status in [200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 500, 502, 503]
                return {
                    'available': available,
                    'status': response.status,
                    'latency': latency
                }
        except asyncio.TimeoutError:
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientConnectorError:
            # Connection error, IP may be unreachable
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientError:
            # Other client errors
            return {'available': False, 'status': 0, 'latency': 999}
        except Exception:
            # Other unknown errors
            return {'available': False, 'status': 0, 'latency': 999}
    
    async def _test_https_async(self, ip: str, domain: str) -> Dict:
        """Async HTTPS test.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            Dictionary with test results.
        """
        try:
            url = f"https://{ip}/"
            start_time = time.time()
            
            # Set more complete request headers - restore Host header with correct format
            headers = {
                'Host': domain,  # Restore Host header, important for CDN servers
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Create SSL context - more lenient SSL settings
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.set_ciphers('DEFAULT:@SECLEVEL=0')  # Lower security level for compatibility
            
            # Add timeout configuration
            timeout = aiohttp.ClientTimeout(
                total=10,  # Total timeout
                connect=5,  # Connection timeout
                sock_read=5  # Read timeout
            )
            
            async with self.session.get(url, headers=headers, ssl=ssl_context, timeout=timeout) as response:
                latency = time.time() - start_time
                # More lenient status code judgment - 403 means server is reachable but needs auth, should count as success
                available = response.status in [200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 500, 502, 503]
                return {
                    'available': available,
                    'status': response.status,
                    'latency': latency
                }
        except asyncio.TimeoutError:
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientConnectorError:
            # Connection error, IP may be unreachable
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientError:
            # Other client errors
            return {'available': False, 'status': 0, 'latency': 999}
        except ssl.SSLError:
            # SSL errors
            return {'available': False, 'status': 0, 'latency': 999}
        except Exception:
            # Other unknown errors
            return {'available': False, 'status': 0, 'latency': 999}
    
    async def _test_connection_async(self, ip: str) -> Dict:
        """Async basic connection test - test if IP is reachable.
        
        Args:
            ip: IP address to test.
            
        Returns:
            Dictionary with connection test results.
        """
        try:
            start_time = time.time()
            
            # Test multiple common ports
            ports_to_test = [80, 443, 8080, 8443]
            for port in ports_to_test:
                try:
                    # Use asyncio for non-blocking connection test
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None,
                        self._test_port_sync,
                        ip,
                        port,
                        3  # 3 second timeout
                    )
                    if result:
                        latency = time.time() - start_time
                        return {
                            'available': True,
                            'latency': latency,
                            'port': port
                        }
                except Exception:
                    continue
            
            # If all ports fail, return unavailable
            return {'available': False, 'latency': 999, 'port': 0}
            
        except Exception as e:
            print(f"连接测试失败 {ip}: {str(e)[:50]}")
            return {'available': False, 'latency': 999, 'port': 0}
    
    def _test_port_sync(self, ip: str, port: int, timeout: int) -> bool:
        """Synchronous port test.
        
        Args:
            ip: IP address to test.
            port: Port number to test.
            timeout: Timeout in seconds.
            
        Returns:
            True if port is open, False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _test_ssl_async(self, ip: str, domain: str) -> Optional[Dict]:
        """Async SSL certificate check.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            SSL certificate information or None if disabled.
        """
        if not self.config.get("ssl_check_enabled", True):
            return None
            
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._check_ssl_sync,
                ip,
                domain
            )
            return result
        except Exception:
            return None
    
    def _check_ssl_sync(self, ip: str, domain: str) -> Dict:
        """Synchronous SSL certificate check.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            SSL certificate information.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'ssl_available': True,
                        'certificate_valid': True,
                        'hostname_verified': True,
                        'certificate_info': cert,
                        'issuer': cert.get('issuer', {}),
                        'subject': cert.get('subject', {}),
                        'not_after': cert.get('notAfter', ''),
                        'not_before': cert.get('notBefore', '')
                    }
        except ssl.SSLError as e:
            return {
                'ssl_available': False,
                'certificate_valid': False,
                'hostname_verified': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'ssl_available': False,
                'certificate_valid': False,
                'hostname_verified': False,
                'error': str(e)
            }
    
    async def _health_check_async(self, ip: str, domain: str) -> Optional[Dict]:
        """Async health check - multi-dimensional parallel check.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            Health check information or None if disabled.
        """
        if not self.config.get("multi_dimensional_health", True):
            return None
            
        try:
            # 并行执行健康检查的各个维度（移除带宽测试）
            tasks = [
                self._check_stability_async(ip),
                self._check_protocol_support_async(ip, domain)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            stability = results[0] if not isinstance(results[0], Exception) else {'stability_score': 0.5}
            protocol = results[1] if not isinstance(results[1], Exception) else {'protocol_score': 50}
            
            # 计算综合健康评分（移除带宽权重）
            overall_score = (
                stability.get('stability_score', 0.5) * 0.6 +
                protocol.get('protocol_score', 50) / 100 * 0.4
            )
            
            return {
                'overall_health_score': overall_score,
                'stability': stability,
                'protocol_support': protocol,
                'health_grade': self._get_health_grade(overall_score)
            }
        except Exception:
            return None
    
    async def _check_stability_async(self, ip: str) -> Dict:
        """异步稳定性检查 - 多次并行ping"""
        try:
            # 并行进行多次连接测试
            tasks = []
            for _ in range(3):
                task = asyncio.create_task(self._ping_async(ip))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            successes = sum(1 for _, success in results if success)
            avg_latency = statistics.mean([lat for lat, _ in results if lat < 999])
            
            stability_score = successes / 3.0
            if avg_latency < 0.1:
                stability_score *= 1.2
            elif avg_latency > 0.5:
                stability_score *= 0.8
            
            return {
                'stability_score': min(stability_score, 1.0),
                'success_rate': stability_score,
                'avg_latency': avg_latency
            }
        except Exception:
            return {'stability_score': 0.5}
    
    
    async def _check_protocol_support_async(self, ip: str, domain: str) -> Dict:
        """Async protocol support check.
        
        Args:
            ip: IP address to test.
            domain: Domain name for testing.
            
        Returns:
            Protocol support check results.
        """
        try:
            # Check HTTP/HTTPS protocol support in parallel
            http_task = asyncio.create_task(self._test_http_async(ip, domain))
            https_task = asyncio.create_task(self._test_https_async(ip, domain))
            
            http_result, https_result = await asyncio.gather(http_task, https_task)
            
            protocol_score = 0
            if http_result['available']:
                protocol_score += 50
            if https_result['available']:
                protocol_score += 50
            
            return {
                'protocol_score': protocol_score,
                'http_support': http_result['available'],
                'https_support': https_result['available']
            }
        except Exception:
            return {'protocol_score': 50}
    
    def _get_health_grade(self, score: float) -> str:
        """Get health grade based on score.
        
        Args:
            score: Health score (0.0-1.0).
            
        Returns:
            Health grade (A-F).
        """
        if score >= 0.9:
            return 'A'
        elif score >= 0.8:
            return 'B'
        elif score >= 0.7:
            return 'C'
        elif score >= 0.6:
            return 'D'
        else:
            return 'F'
    
    def _calculate_comprehensive_score(self, ping_result: Tuple, http_result: Dict, https_result: Dict, 
                                     ssl_result: Optional[Dict], health_result: Optional[Dict], connection_result: Dict) -> float:
        """Calculate comprehensive score - optimized scoring algorithm.
        
        Args:
            ping_result: Ping test results.
            http_result: HTTP test results.
            https_result: HTTPS test results.
            ssl_result: SSL certificate results.
            health_result: Health check results.
            connection_result: Connection test results.
            
        Returns:
            Comprehensive score (0.0-100.0).
        """
        
        # 基础评分组件
        ping_score = self._calculate_ping_score(ping_result)
        http_score = self._calculate_http_score(http_result)
        https_score = self._calculate_https_score(https_result)
        ssl_score = self._calculate_ssl_score(ssl_result)
        connection_score = self._calculate_connection_score(connection_result, http_result, https_result)
        stability_score = self._calculate_stability_score(ping_result, http_result, https_result, connection_result)
        
        # 加权计算总分 (权重总和为100%)
        total_score = (
            ping_score * 0.25 +           # 延迟性能 25%
            http_score * 0.20 +           # HTTP可用性 20%
            https_score * 0.25 +          # HTTPS可用性 25%
            ssl_score * 0.15 +            # SSL安全性 15%
            connection_score * 0.10 +     # 连接稳定性 10%
            stability_score * 0.05        # 综合稳定性 5%
        )
        
        # 健康检查奖励 (额外加分，但不超过100分)
        health_bonus = 0
        if health_result and health_result.get('overall_health_score', 0) > 0:
            health_bonus = health_result['overall_health_score'] * 10  # 最高10分奖励
        
        final_score = min(total_score + health_bonus, 100.0)
        return round(final_score, 1)  # 保留一位小数
    
    def _calculate_ping_score(self, ping_result: Tuple) -> float:
        """Calculate ping latency score (0-100 points).
        
        Args:
            ping_result: Ping test results tuple (latency, success).
            
        Returns:
            Ping score (0.0-100.0).
        """
        ping_latency, ping_success = ping_result
        
        if not ping_success:
            return 0.0
        
        # Use exponential decay function, lower latency = higher score
        if ping_latency <= 0.05:    # Very low latency
            return 100.0
        elif ping_latency <= 0.1:   # Low latency
            return 95.0
        elif ping_latency <= 0.2:   # Medium latency
            return 85.0
        elif ping_latency <= 0.5:   # High latency
            return 70.0
        elif ping_latency <= 1.0:   # Very high latency
            return 50.0
        elif ping_latency <= 2.0:   # Extremely high latency
            return 30.0
        else:                       # Ultra high latency
            return max(10.0, 100.0 / (ping_latency + 1))
    
    def _calculate_http_score(self, http_result: Dict) -> float:
        """Calculate HTTP service score (0-100 points).
        
        Args:
            http_result: HTTP test results.
            
        Returns:
            HTTP score (0.0-100.0).
        """
        if not http_result.get('available', False):
            if http_result.get('status', 0) > 0:
                # Has response but not available status code
                return min(30.0, http_result.get('status', 0) / 10.0)
            return 0.0
        
        status = http_result.get('status', 0)
        latency = http_result.get('latency', 999)
        
        # Score based on status code
        if status == 200:
            base_score = 100.0
        elif status in [301, 302, 307, 308]:
            base_score = 90.0
        elif status in [201, 204]:
            base_score = 85.0
        elif status in [400, 401, 403, 404, 405]:
            base_score = 60.0  # Server responds but request has issues
        elif status in [500, 502, 503, 504]:
            base_score = 40.0  # Server error
        else:
            base_score = 50.0
        
        # Adjust score based on response time
        if latency <= 0.5:
            time_bonus = 0
        elif latency <= 1.0:
            time_bonus = -5
        elif latency <= 2.0:
            time_bonus = -10
        else:
            time_bonus = -20
        
        return max(0.0, base_score + time_bonus)
    
    def _calculate_https_score(self, https_result: Dict) -> float:
        """Calculate HTTPS service score (0-100 points).
        
        Args:
            https_result: HTTPS test results.
            
        Returns:
            HTTPS score (0.0-100.0).
        """
        if not https_result.get('available', False):
            if https_result.get('status', 0) > 0:
                # Has response but not available status code
                return min(25.0, https_result.get('status', 0) / 15.0)
            return 0.0
        
        status = https_result.get('status', 0)
        latency = https_result.get('latency', 999)
        
        # HTTPS scoring similar to HTTP but with slightly higher weights
        if status == 200:
            base_score = 100.0
        elif status in [301, 302, 307, 308]:
            base_score = 95.0
        elif status in [201, 204]:
            base_score = 90.0
        elif status in [400, 401, 403, 404, 405]:
            base_score = 65.0
        elif status in [500, 502, 503, 504]:
            base_score = 45.0
        else:
            base_score = 55.0
        
        # Adjust score based on response time
        if latency <= 0.5:
            time_bonus = 0
        elif latency <= 1.0:
            time_bonus = -5
        elif latency <= 2.0:
            time_bonus = -10
        else:
            time_bonus = -20
        
        return max(0.0, base_score + time_bonus)
    
    def _calculate_ssl_score(self, ssl_result: Optional[Dict]) -> float:
        """Calculate SSL certificate score (0-100 points).
        
        Args:
            ssl_result: SSL certificate test results.
            
        Returns:
            SSL score (0.0-100.0).
        """
        if not ssl_result:
            return 50.0  # No SSL test, give medium score
        
        if not ssl_result.get('ssl_available', False):
            return 0.0
        
        score = 50.0  # Base SSL available score
        
        # Certificate validity bonus
        if ssl_result.get('certificate_valid', False):
            score += 30.0
            
            # Hostname verification bonus
            if ssl_result.get('hostname_verified', False):
                score += 20.0
            else:
                score += 10.0
        else:
            score += 10.0  # SSL available but certificate has issues
        
        return min(100.0, score)
    
    def _calculate_connection_score(self, connection_result: Dict, http_result: Dict, https_result: Dict) -> float:
        """Calculate connection stability score (0-100 points).
        
        Args:
            connection_result: Connection test results.
            http_result: HTTP test results.
            https_result: HTTPS test results.
            
        Returns:
            Connection score (0.0-100.0).
        """
        if not connection_result.get('available', False):
            return 0.0
        
        # If both HTTP and HTTPS fail but connection is available, give base score
        if not http_result.get('available', False) and not https_result.get('available', False):
            latency = connection_result.get('latency', 999)
            if latency <= 1.0:
                return 60.0
            elif latency <= 2.0:
                return 50.0
            else:
                return 40.0
        
        # If HTTP or HTTPS is available, connection test as stability indicator
        latency = connection_result.get('latency', 999)
        if latency <= 0.5:
            return 100.0
        elif latency <= 1.0:
            return 90.0
        elif latency <= 2.0:
            return 80.0
        else:
            return max(60.0, 100.0 / (latency + 0.5))
    
    def _calculate_stability_score(self, ping_result: Tuple, http_result: Dict, https_result: Dict, connection_result: Dict) -> float:
        """Calculate comprehensive stability score (0-100 points).
        
        Args:
            ping_result: Ping test results.
            http_result: HTTP test results.
            https_result: HTTPS test results.
            connection_result: Connection test results.
            
        Returns:
            Stability score (0.0-100.0).
        """
        stability_indicators = []
        
        # Ping stability
        ping_latency, ping_success = ping_result
        if ping_success and ping_latency <= 2.0:
            stability_indicators.append(1.0)
        elif ping_success:
            stability_indicators.append(0.5)
        else:
            stability_indicators.append(0.0)
        
        # HTTP stability
        if http_result.get('available', False):
            stability_indicators.append(1.0)
        elif http_result.get('status', 0) > 0:
            stability_indicators.append(0.5)
        else:
            stability_indicators.append(0.0)
        
        # HTTPS stability
        if https_result.get('available', False):
            stability_indicators.append(1.0)
        elif https_result.get('status', 0) > 0:
            stability_indicators.append(0.5)
        else:
            stability_indicators.append(0.0)
        
        # Connection stability
        if connection_result.get('available', False):
            stability_indicators.append(1.0)
        else:
            stability_indicators.append(0.0)
        
        # Calculate average stability
        if stability_indicators:
            avg_stability = sum(stability_indicators) / len(stability_indicators)
            return avg_stability * 100.0
        else:
            return 0.0
    
    def _display_result(self, result: TrueParallelResult) -> None:
        """Display single test result.
        
        Args:
            result: Test result to display.
        """
        status_icons = {
            True: "✅",
            False: "❌"
        }
        
        print(f"{status_icons[result.ping_success]} {result.ip:15s} | "
              f"Ping: {result.ping_latency:6.3f}s | "
              f"HTTP: {status_icons[result.http_available]} | "
              f"HTTPS: {status_icons[result.https_available]} | "
              f"评分: {result.overall_score:5.1f} | "
              f"耗时: {result.test_duration:.2f}s")


# Adapter class for integration with existing architecture
class TrueParallelOptimizerAdapter:
    """True parallel optimizer adapter - integrates with existing GUI.
    
    This class provides a bridge between the true parallel testing system
    and the existing GUI interface.
    """
    
    def __init__(self, config: Dict) -> None:
        """Initialize the adapter.
        
        Args:
            config: Configuration dictionary for testing parameters.
        """
        self.config = config
        self.tester = TrueParallelTester(config)
    
    def test_ips_with_true_parallel(self, ips: List[str], domain: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Test IPs with true parallel processing, return GUI-compatible format.
        
        Args:
            ips: List of IP addresses to test.
            domain: Domain name for testing.
            progress_callback: Optional callback for progress updates.
            
        Returns:
            List of test results in GUI-compatible format.
        """
        # Execute true parallel testing
        results = self.tester.test_ips_true_parallel(ips, domain, progress_callback)
        
        # Convert to GUI-expected format
        converted_results = []
        for result in results:
            converted_result = {
                'ip': result.ip,
                'ping_latency': result.ping_latency,
                'ping_success': result.ping_success,
                'http_available': result.http_available,
                'https_available': result.https_available,
                'best_http_latency': result.http_latency,
                'best_https_latency': result.https_latency,
                'overall_score': result.overall_score,
                'http_status': result.http_status,
                'https_status': result.https_status,
                'ssl_certificate': result.ssl_cert_info,
                'health_info': result.health_info,
                'test_duration': result.test_duration,
                'timestamp': result.timestamp.isoformat()
            }
            converted_results.append(converted_result)
        
        return converted_results


# 使用示例
if __name__ == "__main__":
    config = {
        "max_concurrent_requests": 100,
        "max_per_host": 30,
        "http_timeout": 8,
        "connect_timeout": 3,
        "read_timeout": 5,
        "ping_timeout": 2,
        "ssl_check_enabled": True,
        "multi_dimensional_health": True,
        "enable_bandwidth_test": True
    }
    
    # 测试IP列表
    test_ips = [
        "8.8.8.8", "1.1.1.1", "208.67.222.222"  # 示例DNS服务器IP
    ]
    
    adapter = TrueParallelOptimizerAdapter(config)
    results = adapter.test_ips_with_true_parallel(test_ips, "ar-gcp-cdn.bistudio.com")
    
    # 显示最佳结果
    if results:
        best_result = results[0]
        print(f"\n🏆 最佳IP: {best_result['ip']}")
        print(f"📊 综合评分: {best_result['overall_score']}")
        print(f"⚡ Ping延迟: {best_result['ping_latency']:.3f}秒")
        print(f"🔥 测试耗时: {best_result['test_duration']:.2f}秒")
