#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
管理员权限检查模块
用于检查程序是否以管理员权限运行，如果不是则自动重启
"""

import ctypes
import sys
import os
import subprocess
import platform


def is_admin():
    """检查当前进程是否以管理员权限运行"""
    try:
        if platform.system() == "Windows":
            # Windows系统检查
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Linux/macOS系统检查
            return os.geteuid() == 0
    except:
        return False


def run_as_admin():
    """以管理员权限重新启动程序"""
    if platform.system() == "Windows":
        # Windows系统
        try:
            # 获取当前脚本的完整路径
            script_path = os.path.abspath(sys.argv[0])
            
            # 使用ShellExecute以管理员权限运行
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                f'"{script_path}"', 
                None, 
                1
            )
            return True
        except Exception as e:
            print(f"无法以管理员权限启动: {e}")
            return False
    else:
        # Linux/macOS系统
        try:
            # 使用sudo重新启动
            script_path = os.path.abspath(sys.argv[0])
            subprocess.run(['sudo', sys.executable, script_path] + sys.argv[1:])
            return True
        except Exception as e:
            print(f"无法以管理员权限启动: {e}")
            return False


def check_admin_privileges():
    """检查管理员权限，如果不是则尝试重启"""
    if not is_admin():
        print("检测到程序未以管理员权限运行")
        print("正在尝试以管理员权限重新启动...")
        
        if run_as_admin():
            print("程序已以管理员权限重新启动")
            sys.exit(0)
        else:
            print("无法以管理员权限启动程序")
            print("请手动以管理员身份运行此程序")
            
            # 在Windows上显示UAC提示
            if platform.system() == "Windows":
                try:
                    import tkinter as tk
                    from tkinter import messagebox
                    
                    root = tk.Tk()
                    root.withdraw()  # 隐藏主窗口
                    
                    result = messagebox.askyesno(
                        "需要管理员权限",
                        "此程序需要管理员权限才能修改hosts文件。\n\n"
                        "是否以管理员身份重新启动程序？\n\n"
                        "点击'是'将以管理员权限重启，\n"
                        "点击'否'将退出程序。"
                    )
                    
                    if result:
                        run_as_admin()
                        sys.exit(0)
                    else:
                        print("用户选择不重启，程序退出")
                        sys.exit(1)
                        
                except ImportError:
                    # 如果没有tkinter，使用命令行提示
                    input("请按Enter键退出程序，然后以管理员身份重新运行...")
                    sys.exit(1)
            else:
                input("请按Enter键退出程序，然后使用sudo重新运行...")
                sys.exit(1)
    else:
        print("✓ 程序以管理员权限运行")


if __name__ == "__main__":
    check_admin_privileges()
