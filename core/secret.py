# -*- coding: utf-8 -*-
"""敏感信息处理：口令加密存储 + 日志脱敏。

- 使用 cryptography Fernet 对称加密，密钥保存在 ~/.ea_dengbao/.secret.key
- encrypt() 返回 "enc:..." 前缀字符串，decrypt() 兼容明文（非 enc: 前缀原样返回）
- sanitize() 用于日志/错误信息，把疑似口令内容替换为 ******
"""
import os
import re

KEY_DIR = os.path.join(os.path.expanduser("~"), ".ea_dengbao")
KEY_PATH = os.path.join(KEY_DIR, ".secret.key")
_PREFIX = "enc:"
_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        try:
            os.chmod(KEY_PATH, 0o600)
        except Exception:
            pass
    with open(KEY_PATH, "rb") as f:
        key = f.read().strip()
    try:
        _fernet = Fernet(key)
    except Exception:
        _fernet = None
    return _fernet


def encrypt(text):
    """加密字符串；失败或依赖缺失时返回原文"""
    if not text:
        return ""
    f = _get_fernet()
    if f is None:
        return text
    try:
        return _PREFIX + f.encrypt(text.encode("utf-8")).decode("ascii")
    except Exception:
        return text


def decrypt(text):
    """解密字符串；明文原样返回"""
    if not text:
        return ""
    if not text.startswith(_PREFIX):
        return text
    f = _get_fernet()
    if f is None:
        return text
    try:
        from cryptography.fernet import InvalidToken
        return f.decrypt(text[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except Exception:
        return text


_PWD_PATTERNS = [
    re.compile(r"(password\s*[=:]\s*)([^\s,;]+)", re.I),
    re.compile(r"(passwd\s*[=:]\s*)([^\s,;]+)", re.I),
    re.compile(r"(口令[：:]\s*)([^\s,;]+)", re.I),
    re.compile(r"(密码[：:=]\s*)([^\s,;]+)", re.I),
    re.compile(r"(--password\s+)([^\s]+)", re.I),
    re.compile(r"(-p\s)([^\s]+)"),
]


def sanitize(text):
    """把日志/错误信息里的疑似口令替换为 ******"""
    if not text:
        return text
    out = str(text)
    for pat in _PWD_PATTERNS:
        out = pat.sub(lambda m: m.group(1) + "******", out)
    return out


def mask(text, keep=0):
    """显示用脱敏：只保留首尾少量字符"""
    if not text:
        return ""
    if keep <= 0:
        return "******"
    return text[:keep] + "******" + text[-keep:]
