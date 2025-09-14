#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真正并行的Hosts优化器 - 集成版本
将异步IO和真正并行处理集成到现有架构中，解决串行等待问题
"""

import asyncio
import aiohttp
import socket
import time
import statistics
import ssl
import json
import threading
from typing import List, Dict, Tuple, Optional, Set, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import subprocess
import platform
from collections import deque
import queue


@dataclass
class TrueParallelResult:
    """真正并行测试结果"""
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
    """真正并行的测试器 - 解决串行等待问题"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.session = None
        self.connector = None
        self.semaphore = None
        self.results_queue = queue.Queue()
        self.progress_callback = None
        
    async def __aenter__(self):
        """异步上下文管理器入口"""
        # 创建优化的连接器
        max_connections = self.config.get("max_concurrent_requests", 100)
        self.semaphore = asyncio.Semaphore(max_connections)
        
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=self.config.get("max_per_host", 30),
            ttl_dns_cache=0,  # 禁用DNS缓存避免缓存错误
            use_dns_cache=False,  # 禁用DNS缓存
            enable_cleanup_closed=True,
            force_close=False,  # 允许连接复用，避免连接问题
            family=0,  # 允许IPv4和IPv6
            ssl=False,  # 在连接器级别禁用SSL，在请求级别处理
            resolver=None,  # 使用默认解析器
            local_addr=None,  # 不绑定本地地址
            keepalive_timeout=30  # 保持连接活跃
        )
        
        # 创建超时配置
        timeout = aiohttp.ClientTimeout(
            total=self.config.get("http_timeout", 8),
            connect=self.config.get("connect_timeout", 3),
            sock_read=self.config.get("read_timeout", 5)
        )
        
        # 创建会话
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers={'User-Agent': 'ArmaReforgerHostsOptimizer/1.3.0-TrueParallel'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    def test_ips_true_parallel(self, ips: List[str], domain: str, progress_callback: Callable = None) -> List[TrueParallelResult]:
        """真正并行的IP测试 - 解决串行等待问题"""
        if not ips:
            return []
        
        self.progress_callback = progress_callback
        print(f"🚀 启动并行测试模式")
        print(f"📊 测试IP数量: {len(ips)}")
        print(f"⚡ 最大并发数: {self.config.get('max_concurrent_requests', 100)}")
        
        # 在新的事件循环中运行异步测试
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(self._test_all_ips_async(ips, domain))
            return results
        finally:
            loop.close()
    
    async def _test_all_ips_async(self, ips: List[str], domain: str) -> List[TrueParallelResult]:
        """异步测试所有IP"""
        async with self:
            start_time = time.time()
            results = []
            
            # 创建所有测试任务 - 真正的并行
            tasks = []
            for ip in ips:
                task = asyncio.create_task(self._test_single_ip_async(ip, domain))
                tasks.append(task)
            
            # 使用as_completed获取完成的任务，实现真正的并行处理
            completed_count = 0
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                    results.append(result)
                    completed_count += 1
                    
                    # 实时进度回调
                    if self.progress_callback:
                        self.progress_callback(completed_count, len(ips), result.ip)
                    
                    # 实时显示结果
                    self._display_result(result)
                    
                    # 将结果放入队列供GUI使用
                    self.results_queue.put(result)
                    
                except Exception as e:
                    print(f"❌ 测试异常: {e}")
                    completed_count += 1
            
            # 按评分排序
            results.sort(key=lambda x: x.overall_score, reverse=True)
            
            total_time = time.time() - start_time
            print(f"\n🎉 并行测试完成！")
            print(f"⏱️  总耗时: {total_time:.2f}秒")
            print(f"📈 平均每个IP耗时: {total_time/len(ips):.2f}秒")
            print(f"🏆 最佳IP: {results[0].ip} (评分: {results[0].overall_score:.1f})")
            return results
    
    async def _test_single_ip_async(self, ip: str, domain: str) -> TrueParallelResult:
        """异步测试单个IP - 所有测试真正并行执行"""
        async with self.semaphore:  # 限制并发数
            start_time = time.time()
            
            # 并行执行所有测试任务
            tasks = [
                self._ping_async(ip),
                self._test_http_async(ip, domain),
                self._test_https_async(ip, domain),
                self._test_ssl_async(ip, domain),
                self._health_check_async(ip, domain),
                self._test_connection_async(ip)  # 添加基础连接测试
            ]
            
            # 等待所有任务完成 - 真正的并行等待
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 解析结果
            ping_result = results[0] if not isinstance(results[0], Exception) else (0, False)
            http_result = results[1] if not isinstance(results[1], Exception) else {'available': False, 'status': 0, 'latency': 999}
            https_result = results[2] if not isinstance(results[2], Exception) else {'available': False, 'status': 0, 'latency': 999}
            ssl_result = results[3] if not isinstance(results[3], Exception) else None
            health_result = results[4] if not isinstance(results[4], Exception) else None
            connection_result = results[5] if not isinstance(results[5], Exception) else {'available': False, 'latency': 999}
            
            # 计算综合评分
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
        """异步Ping测试 - 使用线程池避免阻塞"""
        try:
            loop = asyncio.get_event_loop()
            start_time = time.time()
            
            # 在线程池中执行ping
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
        """同步Ping实现"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except:
            return False
    
    async def _test_http_async(self, ip: str, domain: str) -> Dict:
        """异步HTTP测试"""
        try:
            url = f"http://{ip}/"
            start_time = time.time()
            
            # 设置更完整的请求头 - 恢复Host头但使用正确的格式
            headers = {
                'Host': domain,  # 恢复Host头，这对CDN服务器很重要
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # 添加超时和重试机制
            timeout = aiohttp.ClientTimeout(
                total=10,  # 总超时
                connect=5,  # 连接超时
                sock_read=5  # 读取超时
            )
            
            async with self.session.get(url, headers=headers, timeout=timeout) as response:
                latency = time.time() - start_time
                # 更宽松的状态码判断 - 403表示服务器可达但需要认证，应该算作成功
                available = response.status in [200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 500, 502, 503]
                return {
                    'available': available,
                    'status': response.status,
                    'latency': latency
                }
        except asyncio.TimeoutError:
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientConnectorError as e:
            # 连接错误，可能是IP不可达
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientError as e:
            # 其他客户端错误
            return {'available': False, 'status': 0, 'latency': 999}
        except Exception as e:
            # 其他未知错误
            return {'available': False, 'status': 0, 'latency': 999}
    
    async def _test_https_async(self, ip: str, domain: str) -> Dict:
        """异步HTTPS测试"""
        try:
            url = f"https://{ip}/"
            start_time = time.time()
            
            # 设置更完整的请求头 - 恢复Host头但使用正确的格式
            headers = {
                'Host': domain,  # 恢复Host头，这对CDN服务器很重要
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # 创建SSL上下文 - 更宽松的SSL设置
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.set_ciphers('DEFAULT:@SECLEVEL=0')  # 降低安全级别以兼容更多服务器
            
            # 添加超时配置
            timeout = aiohttp.ClientTimeout(
                total=10,  # 总超时
                connect=5,  # 连接超时
                sock_read=5  # 读取超时
            )
            
            async with self.session.get(url, headers=headers, ssl=ssl_context, timeout=timeout) as response:
                latency = time.time() - start_time
                # 更宽松的状态码判断 - 403表示服务器可达但需要认证，应该算作成功
                available = response.status in [200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 500, 502, 503]
                return {
                    'available': available,
                    'status': response.status,
                    'latency': latency
                }
        except asyncio.TimeoutError:
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientConnectorError as e:
            # 连接错误，可能是IP不可达
            return {'available': False, 'status': 0, 'latency': 999}
        except aiohttp.ClientError as e:
            # 其他客户端错误
            return {'available': False, 'status': 0, 'latency': 999}
        except ssl.SSLError as e:
            # SSL错误
            return {'available': False, 'status': 0, 'latency': 999}
        except Exception as e:
            # 其他未知错误
            return {'available': False, 'status': 0, 'latency': 999}
    
    async def _test_connection_async(self, ip: str) -> Dict:
        """异步基础连接测试 - 测试IP是否可达"""
        try:
            start_time = time.time()
            
            # 测试多个常用端口
            ports_to_test = [80, 443, 8080, 8443]
            for port in ports_to_test:
                try:
                    # 使用asyncio进行非阻塞连接测试
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None,
                        self._test_port_sync,
                        ip,
                        port,
                        3  # 3秒超时
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
            
            # 如果所有端口都失败，返回不可用
            return {'available': False, 'latency': 999, 'port': 0}
            
        except Exception as e:
            print(f"连接测试失败 {ip}: {str(e)[:50]}")
            return {'available': False, 'latency': 999, 'port': 0}
    
    def _test_port_sync(self, ip: str, port: int, timeout: int) -> bool:
        """同步端口测试"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def _test_ssl_async(self, ip: str, domain: str) -> Optional[Dict]:
        """异步SSL证书检查"""
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
        """同步SSL证书检查"""
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
        """异步健康检查 - 多维度并行检查"""
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
        """异步协议支持检查"""
        try:
            # 并行检查HTTP/HTTPS协议支持
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
        """根据健康评分获取等级"""
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
        """计算综合评分 - 优化后的评分算法"""
        
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
        """计算Ping延迟评分 (0-100分)"""
        ping_latency, ping_success = ping_result
        
        if not ping_success:
            return 0.0
        
        # 使用指数衰减函数，延迟越低分数越高
        if ping_latency <= 0.05:    # 极低延迟
            return 100.0
        elif ping_latency <= 0.1:   # 低延迟
            return 95.0
        elif ping_latency <= 0.2:   # 中等延迟
            return 85.0
        elif ping_latency <= 0.5:   # 较高延迟
            return 70.0
        elif ping_latency <= 1.0:   # 高延迟
            return 50.0
        elif ping_latency <= 2.0:   # 很高延迟
            return 30.0
        else:                       # 极高延迟
            return max(10.0, 100.0 / (ping_latency + 1))
    
    def _calculate_http_score(self, http_result: Dict) -> float:
        """计算HTTP服务评分 (0-100分)"""
        if not http_result.get('available', False):
            if http_result.get('status', 0) > 0:
                # 有响应但不是可用状态码
                return min(30.0, http_result.get('status', 0) / 10.0)
            return 0.0
        
        status = http_result.get('status', 0)
        latency = http_result.get('latency', 999)
        
        # 根据状态码评分
        if status == 200:
            base_score = 100.0
        elif status in [301, 302, 307, 308]:
            base_score = 90.0
        elif status in [201, 204]:
            base_score = 85.0
        elif status in [400, 401, 403, 404, 405]:
            base_score = 60.0  # 服务器响应但请求有问题
        elif status in [500, 502, 503, 504]:
            base_score = 40.0  # 服务器错误
        else:
            base_score = 50.0
        
        # 根据响应时间调整分数
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
        """计算HTTPS服务评分 (0-100分)"""
        if not https_result.get('available', False):
            if https_result.get('status', 0) > 0:
                # 有响应但不是可用状态码
                return min(25.0, https_result.get('status', 0) / 15.0)
            return 0.0
        
        status = https_result.get('status', 0)
        latency = https_result.get('latency', 999)
        
        # HTTPS评分标准与HTTP类似，但权重稍高
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
        
        # 根据响应时间调整分数
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
        """计算SSL证书评分 (0-100分)"""
        if not ssl_result:
            return 50.0  # 未测试SSL，给予中等分数
        
        if not ssl_result.get('ssl_available', False):
            return 0.0
        
        score = 50.0  # 基础SSL可用分数
        
        # 证书有效性加分
        if ssl_result.get('certificate_valid', False):
            score += 30.0
            
            # 主机名验证加分
            if ssl_result.get('hostname_verified', False):
                score += 20.0
            else:
                score += 10.0
        else:
            score += 10.0  # SSL可用但证书有问题
        
        return min(100.0, score)
    
    def _calculate_connection_score(self, connection_result: Dict, http_result: Dict, https_result: Dict) -> float:
        """计算连接稳定性评分 (0-100分)"""
        if not connection_result.get('available', False):
            return 0.0
        
        # 如果HTTP和HTTPS都失败但连接可用，给予基础分数
        if not http_result.get('available', False) and not https_result.get('available', False):
            latency = connection_result.get('latency', 999)
            if latency <= 1.0:
                return 60.0
            elif latency <= 2.0:
                return 50.0
            else:
                return 40.0
        
        # 如果HTTP或HTTPS可用，连接测试作为稳定性指标
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
        """计算综合稳定性评分 (0-100分)"""
        stability_indicators = []
        
        # Ping稳定性
        ping_latency, ping_success = ping_result
        if ping_success and ping_latency <= 2.0:
            stability_indicators.append(1.0)
        elif ping_success:
            stability_indicators.append(0.5)
        else:
            stability_indicators.append(0.0)
        
        # HTTP稳定性
        if http_result.get('available', False):
            stability_indicators.append(1.0)
        elif http_result.get('status', 0) > 0:
            stability_indicators.append(0.5)
        else:
            stability_indicators.append(0.0)
        
        # HTTPS稳定性
        if https_result.get('available', False):
            stability_indicators.append(1.0)
        elif https_result.get('status', 0) > 0:
            stability_indicators.append(0.5)
        else:
            stability_indicators.append(0.0)
        
        # 连接稳定性
        if connection_result.get('available', False):
            stability_indicators.append(1.0)
        else:
            stability_indicators.append(0.0)
        
        # 计算平均稳定性
        if stability_indicators:
            avg_stability = sum(stability_indicators) / len(stability_indicators)
            return avg_stability * 100.0
        else:
            return 0.0
    
    def _display_result(self, result: TrueParallelResult):
        """显示单个测试结果"""
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


# 集成到现有架构的适配器类
class TrueParallelOptimizerAdapter:
    """真正并行优化器适配器 - 集成到现有GUI"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.tester = TrueParallelTester(config)
    
    def test_ips_with_true_parallel(self, ips: List[str], domain: str, progress_callback: Callable = None) -> List[Dict]:
        """使用真正并行测试IP，返回兼容现有GUI的格式"""
        # 执行真正并行测试
        results = self.tester.test_ips_true_parallel(ips, domain, progress_callback)
        
        # 转换为现有GUI期望的格式
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
