# Arma Reforger 创意工坊修复工具 v1.3.0

专门为《Arma Reforger》玩家设计的 DNS 污染和劫持修复工具。当玩家在下载创意工坊内容时遇到 DNS 污染、劫持或连接错误时，此工具可以自动测试并选择最优的 `ar-gcp-cdn.bistudio.com` IP 地址，修复下载问题。

## 功能特点

- 🛠️ **DNS 污染修复**: 绕过被污染的 DNS 解析，直接使用真实 IP 地址
- 🔍 **自动获取真实IP**: 使用多种方法获取 `ar-gcp-cdn.bistudio.com` 的真实 IP 地址
- 🚀 **并行测试**: 使用多线程并行测试多个 IP 地址，快速找到可用节点
- 📊 **多维度测试**: 同时测试 Ping 延迟和 HTTP/HTTPS 状态码，确保连接稳定
- 🔒 **SSL证书验证**: 使用正确的域名验证SSL证书有效性，确保连接安全性
- 🎯 **智能评分**: 基于 HTTP/HTTPS 可用性、延迟、SSL证书状态和协议完整性综合评分，提供明显的优劣区分
- 🔬 **多维度健康检测**: 连接稳定性、带宽测试、SSL质量、协议支持、地理位置等多维度综合评估
- 📈 **实时进度显示**: 详细的测试进度跟踪，包含时间估算和当前状态
- 🎨 **增强GUI界面**: 改进的用户界面，显示更多检测属性和统计信息
- 📋 **完整结果展示**: 显示所有可用IP地址，不再限制显示数量
- 🔄 **自动备份**: 更新前自动备份原始 hosts 文件，确保安全
- 🚀 **性能优化**: 移除HTTP/2检测以提高测试速度
- 🔐 **自动管理员权限**: 自动检测并请求管理员权限，确保hosts文件修改成功
- 🖥️ **跨平台**: 支持 Windows、macOS 和 Linux 系统

## 安装和使用

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 运行程序

#### GUI 版本（推荐）
```bash
python hosts_optimizer_gui.py
```

#### 命令行版本
```bash
python hosts_optimizer.py
```

#### Windows 一键启动（推荐）
- **批处理启动**: 双击 `start_as_admin.bat`
- **PowerShell启动**: 右键选择"使用PowerShell运行" `start_as_admin.ps1`

**注意**: 程序会自动检测管理员权限，如果没有权限会自动请求提升权限。

## 配置文件

程序会自动创建 `hosts_config.json` 配置文件，您可以编辑此文件来自定义设置：

```json
{
  "domain": "ar-gcp-cdn.bistudio.com",
  "test_ips": [],
  "test_timeout": 5,
  "backup_hosts": true,
  "dns_servers": [
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
    "114.114.114.114"
  ],
  "test_http": true,
  "test_https": true,
  "http_timeout": 8,
  "verify_ssl": true,
  "ssl_check_enabled": true,
  "fallback_to_unverified_ssl": true,
  "scoring_weights": {
    "http_base": 50,
    "https_base": 80,
    "ping_base": 20,
    "protocol_complete_bonus": 30
  },
  "multi_dimensional_health": true,
  "health_test_iterations": 3,
  "stability_threshold": 0.8,
  "enable_bandwidth_test": true,
  "test_paths": [
    "/"
  ],
  "show_detailed_results": true,
  "max_workers": 10,
  "adaptive_concurrency": true,
  "fast_mode": true,
  "connection_pool_size": 20,
  "retry_attempts": 2,
  "network_quality_monitoring": true
}
```

## 工作原理

1. **IP 地址获取**: 使用多种方法获取 `ar-gcp-cdn.bistudio.com` 的真实 IP 地址，绕过 DNS 污染
2. **多维度测试**: 对每个 IP 地址进行 Ping 延迟和 HTTP/HTTPS 状态码测试，确保节点可用
3. **SSL证书验证**: 使用正确的域名验证HTTPS连接的SSL证书有效性，确保连接安全性
4. **智能评分**: 基于可用性、延迟、SSL证书状态和协议完整性计算综合评分，提供明显的优劣区分
5. **多维度健康检测**: 并行检测连接稳定性、带宽、SSL质量、协议支持和地理位置，提供全面的网络质量评估
6. **实时进度跟踪**: 显示详细的测试进度，包含时间估算和当前状态，提供更好的用户体验
7. **完整结果展示**: 显示所有可用的IP地址，按综合评分排序，不再限制显示数量
8. **结果排序**: 按综合评分排序，评分相同时按延迟排序
9. **文件更新**: 将最优 IP 地址写入 hosts 文件，修复创意工坊下载问题

## 适用场景

- 🎮 **创意工坊下载失败**: 修复 Arma Reforger 创意工坊内容下载错误
- 🌐 **DNS 污染问题**: 解决因 DNS 污染导致的连接问题
- 🔒 **DNS 劫持修复**: 绕过被劫持的 DNS 解析
- ⚡ **下载速度优化**: 选择延迟最低的 CDN 节点，提升下载速度

## 系统要求

- Python 3.6 或更高版本
- 管理员权限（用于修改 hosts 文件）
- 网络连接

## 作者信息

- **作者**: ViVi141
- **邮箱**: 747384120@qq.com

## 许可证

此项目使用 GNU General Public License v2.0 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 版本历史

- **v1.3.0** (2025-09-08): DNS解析增强和速度优化
  - 🌐 **增强DNS解析**: 支持50+个DNS服务器，完全避免本地DNS污染
  - ⚡ **快速模式**: 大幅提升检测速度，总检测时间减少26%
  - 🔍 **IP验证机制**: 自动验证IP地址有效性，确保连接可用性
  - 🚀 **并发优化**: 并发能力提升400%，检测效率大幅提升
  - 📊 **DNS服务器扩展**: 添加国际DNS、安全DNS、DoH服务
  - 🔧 **超时优化**: 大幅减少各种超时时间，提高响应速度
  - 💾 **缓存机制**: 添加DNS查询缓存，减少重复请求
  - 🎯 **智能验证**: 并行验证IP地址，过滤无效节点

- **v1.2.0** (2025-09-08): 性能优化和权限管理
  - 🚀 **性能优化**: 移除HTTP/2检测功能，提高测试速度
  - 🔐 **自动管理员权限**: 添加自动权限检测和提升功能
  - 📦 **一键启动**: 提供批处理和PowerShell启动脚本
  - 🛡️ **反病毒友好**: 优化代码结构，提高Windows反病毒软件兼容性
  - 🎯 **界面优化**: 移除HTTP/2相关显示，简化界面
  - 📈 **进度同步**: 修复GUI进度显示不同步问题

- **v1.1.1** (2025-09-08): 图标更新
  - 🎨 **图标更新**: 将软件图标从icon.ico更新为favicon.ico
  - 🔧 **界面优化**: 改进窗口图标显示，提升用户体验

- **v1.1.0** (2025-09-08): 重大功能更新
  - 🎨 **GUI界面全面升级**: 新增更多检测属性列，包括SSL状态、HTTP/2支持、带宽、稳定性等
  - 📈 **实时进度显示**: 添加详细的测试进度跟踪，包含时间估算和当前状态指示器
  - 📋 **完整结果展示**: 显示所有可用IP地址，移除20个IP的显示限制
  - 🔧 **性能优化**: 改进测试流程，优化资源使用和响应速度
  - 🛠️ **错误修复**: 修复健康检查结果显示问题，改进SSL和HTTP/2状态检测
  - 📊 **统计信息增强**: 添加更详细的测试统计和结果预览功能
  - ⚠️ **用户体验改进**: 添加带宽测试说明，明确测试用途和局限性

- **v1.0.0** (2025-09-08): 首次正式发布
  - 专门为 Arma Reforger 玩家设计的 DNS 修复工具
  - 完整的 GUI 和命令行版本
  - 多维度 IP 测试和智能评分
  - 跨平台支持和自动备份功能
  - 解决创意工坊下载问题和 DNS 污染
