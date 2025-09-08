@echo off
:: 强制以管理员权限启动 Hosts Optimizer GUI
:: 此脚本将检查管理员权限，如果没有则自动提升权限

echo 正在启动 Arma Reforger 创意工坊修复工具...
echo.

:: 检查是否已经是管理员权限
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✓ 检测到管理员权限
    echo 正在启动程序...
    python hosts_optimizer_gui.py
) else (
    echo 检测到需要管理员权限
    echo 正在以管理员身份重新启动...
    
    :: 以管理员权限重新运行此脚本
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

pause
