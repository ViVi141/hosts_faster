# Arma Reforger 创意工坊修复工具 v1.0.0

专门为《Arma Reforger》玩家设计的 DNS 污染和劫持修复工具。当玩家在下载创意工坊内容时遇到 DNS 污染、劫持或连接错误时，此工具可以自动测试并选择最优的 `ar-gcp-cdn.bistudio.com` IP 地址，修复下载问题。

## 功能特点

- 🛠️ **DNS 污染修复**: 绕过被污染的 DNS 解析，直接使用真实 IP 地址
- 🔍 **自动获取真实IP**: 使用多种方法获取 `ar-gcp-cdn.bistudio.com` 的真实 IP 地址
- 🚀 **并行测试**: 使用多线程并行测试多个 IP 地址，快速找到可用节点
- 📊 **多维度测试**: 同时测试 Ping 延迟和 HTTP/HTTPS 状态码，确保连接稳定
- 🎯 **智能评分**: 基于 HTTP 可用性、延迟和协议类型综合评分，选择最佳节点
- 🔄 **自动备份**: 更新前自动备份原始 hosts 文件，确保安全
- 🖥️ **GUI界面**: 提供友好的图形用户界面，操作简单直观
- 🔧 **跨平台**: 支持 Windows、macOS 和 Linux 系统

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

**注意**: 在 Windows 系统上，需要以管理员身份运行。

## 配置文件

程序会自动创建 `hosts_config.json` 配置文件，您可以编辑此文件来自定义设置：

```json
{
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
  "http_timeout": 10,
  "verify_ssl": false,
  "test_paths": [
    "/",
    "/api/health",
    "/status",
    "/ping"
  ],
  "show_detailed_results": true,
  "max_workers": 10
}
```

## 工作原理

1. **IP 地址获取**: 使用多种方法获取 `ar-gcp-cdn.bistudio.com` 的真实 IP 地址，绕过 DNS 污染
2. **多维度测试**: 对每个 IP 地址进行 Ping 延迟和 HTTP/HTTPS 状态码测试，确保节点可用
3. **智能评分**: 基于可用性、延迟和协议类型计算综合评分，选择最佳下载节点
4. **结果排序**: 按综合评分排序，评分相同时按延迟排序
5. **文件更新**: 将最优 IP 地址写入 hosts 文件，修复创意工坊下载问题

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

- **v1.0.0** (2025-09-08): 首次正式发布
  - 专门为 Arma Reforger 玩家设计的 DNS 修复工具
  - 完整的 GUI 和命令行版本
  - 多维度 IP 测试和智能评分
  - 跨平台支持和自动备份功能
  - 解决创意工坊下载问题和 DNS 污染
