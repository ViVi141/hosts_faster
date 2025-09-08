# 强制以管理员权限启动 Hosts Optimizer GUI
# PowerShell 版本

Write-Host "正在启动 Arma Reforger 创意工坊修复工具..." -ForegroundColor Green
Write-Host ""

# 检查是否已经是管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($isAdmin) {
    Write-Host "✓ 检测到管理员权限" -ForegroundColor Green
    Write-Host "正在启动程序..." -ForegroundColor Yellow
    python hosts_optimizer_gui.py
} else {
    Write-Host "检测到需要管理员权限" -ForegroundColor Yellow
    Write-Host "正在以管理员身份重新启动..." -ForegroundColor Yellow
    
    # 以管理员权限重新运行此脚本
    Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    exit
}

Read-Host "按任意键退出"
