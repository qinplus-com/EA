# -*- coding: utf-8 -*-
"""跨平台工具：命令执行 / 文件读取 / 权限查询
统一委托给当前执行器（本机或远程），检测代码无需感知目标位置。
"""
import os
import subprocess
import sys

from core.remote import LocalExecutor

CREATE_NO_WINDOW = 0x08000000 if sys.platform.startswith("win") else 0

_EXECUTOR = LocalExecutor()


def set_executor(ex):
    """切换执行器；传 None 恢复本机。engine 在每次检测前后调用。"""
    global _EXECUTOR
    _EXECUTOR = ex if ex is not None else LocalExecutor()


def get_executor():
    return _EXECUTOR


def run_cmd(cmd, timeout=25):
    """执行命令，返回 (returncode, stdout+stderr)。"""
    return _EXECUTOR.run(cmd, timeout)


def run_powershell(script, timeout=30):
    """执行 PowerShell 脚本片段（本机或远程 WinRM）。"""
    return _EXECUTOR.run_ps(script, timeout)


def read_file(path, encodings=("utf-8", "gbk", "latin-1")):
    return _EXECUTOR.read_file(path)


def is_privileged():
    """返回 (是否高权限, 说明)"""
    return _EXECUTOR.is_privileged()


def file_mode(path):
    """返回 (权限字符串 或 None, 说明)"""
    return _EXECUTOR.file_mode(path)
