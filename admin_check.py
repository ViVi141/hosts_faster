#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Administrator privilege check module.

This module is used to check if the program is running with administrator
privileges, and automatically restart if not.
"""

import ctypes
import os
import platform
import subprocess
import sys


def is_admin() -> bool:
    """Check if the current process is running with administrator privileges.
    
    Returns:
        True if running with admin privileges, False otherwise.
    """
    try:
        if platform.system() == "Windows":
            # Windows system check
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Linux/macOS system check
            return os.geteuid() == 0
    except Exception:
        return False


def run_as_admin() -> bool:
    """Restart the program with administrator privileges.
    
    Returns:
        True if restart was successful, False otherwise.
    """
    if platform.system() == "Windows":
        # Windows system
        try:
            # Get the full path of the current script
            script_path = os.path.abspath(sys.argv[0])
            
            # Use ShellExecute to run with administrator privileges
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
        # Linux/macOS system
        try:
            # Use sudo to restart
            script_path = os.path.abspath(sys.argv[0])
            subprocess.run(['sudo', sys.executable, script_path] + sys.argv[1:])
            return True
        except Exception as e:
            print(f"无法以管理员权限启动: {e}")
            return False


def check_admin_privileges() -> None:
    """Check administrator privileges and restart if necessary."""
    if not is_admin():
        print("检测到程序未以管理员权限运行")
        print("正在尝试以管理员权限重新启动...")
        
        if run_as_admin():
            print("程序已以管理员权限重新启动")
            sys.exit(0)
        else:
            print("无法以管理员权限启动程序")
            print("请手动以管理员身份运行此程序")
            
            # Show UAC prompt on Windows
            if platform.system() == "Windows":
                try:
                    import tkinter as tk
                    from tkinter import messagebox
                    
                    root = tk.Tk()
                    root.withdraw()  # Hide main window
                    
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
                    # If tkinter is not available, use command line prompt
                    input("请按Enter键退出程序，然后以管理员身份重新运行...")
                    sys.exit(1)
            else:
                input("请按Enter键退出程序，然后使用sudo重新运行...")
                sys.exit(1)
    else:
        print("✓ 程序以管理员权限运行")


if __name__ == "__main__":
    check_admin_privileges()
