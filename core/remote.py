# -*- coding: utf-8 -*-
"""执行器：本机 / SSH 远程 Linux / WinRM 远程 Windows
检测代码只依赖统一接口，从而同时支持本机与指定 IP 的远程服务器。
"""
import os
import shlex
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000 if sys.platform.startswith("win") else 0


def _decode(data):
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


class Executor:
    """执行器基类"""
    platform = "linux"
    is_local = False

    def connect(self):
        pass

    def close(self):
        pass

    def run(self, cmd, timeout=25):
        """执行命令，cmd 可为 str 或 list。返回 (returncode, stdout+stderr)。"""
        raise NotImplementedError

    def run_ps(self, script, timeout=30):
        raise NotImplementedError("当前执行器不支持 PowerShell")

    def read_file(self, path):
        raise NotImplementedError

    def is_privileged(self):
        """返回 (是否高权限, 说明)"""
        return False, "无法判断权限"

    def file_mode(self, path):
        """返回 (八进制权限字符串 或 None, 说明)"""
        return None, "无法读取文件权限"

    def os_name(self):
        return "未知系统"


class LocalExecutor(Executor):
    platform = "windows" if sys.platform.startswith("win") else "linux"
    is_local = True

    def run(self, cmd, timeout=25):
        try:
            p = subprocess.run(
                cmd, capture_output=True, timeout=timeout,
                creationflags=CREATE_NO_WINDOW, shell=isinstance(cmd, str),
            )
            return p.returncode, _decode(p.stdout + p.stderr)
        except FileNotFoundError:
            return -1, "命令不存在: %s" % (cmd if isinstance(cmd, str) else cmd[0])
        except subprocess.TimeoutExpired:
            return -1, "命令执行超时"
        except Exception as e:
            return -1, str(e)

    def run_ps(self, script, timeout=30):
        return self.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)

    def read_file(self, path):
        try:
            with open(path, "rb") as f:
                return _decode(f.read())
        except Exception:
            return ""

    def is_privileged(self):
        try:
            return os.geteuid() == 0, "root" if os.geteuid() == 0 else "普通用户"
        except AttributeError:
            return True, "Windows管理员会话"

    def file_mode(self, path):
        try:
            return oct(os.stat(path).st_mode & 0o777)[2:].zfill(3), ""
        except OSError as e:
            return None, str(e)

    def os_name(self):
        import platform as _pf
        try:
            if self.platform == "windows":
                return "Windows %s (%s)" % (_pf.version(), _pf.machine())
            return "%s %s (%s)" % (_pf.system(), _pf.release(), _pf.machine())
        except Exception:
            return _pf.platform()


class SSHExecutor(Executor):
    """通过 SSH 检测远程 Linux 服务器（麒麟/UOS/CentOS/Ubuntu 等）"""
    platform = "linux"

    def __init__(self, host, port=22, user="root", password="", keyfile="", timeout=12):
        self.host = host
        self.port = int(port or 22)
        self.user = user or "root"
        self.password = password or ""
        self.keyfile = keyfile or ""
        self.timeout = timeout
        self.client = None
        self._connected_ok = False

    def connect(self):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("缺少 paramiko 依赖，请执行：pip install paramiko")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                self.host, port=self.port, username=self.user,
                password=self.password or None,
                key_filename=self.keyfile or None,
                timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
                look_for_keys=not self.password, allow_agent=not self.password,
            )
        except paramiko.AuthenticationException:
            self.client = None
            raise RuntimeError("SSH 认证失败：用户名或口令/私钥不正确")
        except paramiko.SSHException as e:
            self.client = None
            raise RuntimeError("SSH 连接失败：%s（请确认目标机 sshd 已启动）" % e)
        except Exception as e:
            self.client = None
            raise RuntimeError("无法连接到 %s:%s —— %s（请检查IP、端口与网络连通性）"
                               % (self.host, self.port, e))
        # 二次验证：跑 uname -a 确认通道真的可用
        rc, out = self._exec("uname -a 2>/dev/null || echo SSH_OK")
        if rc != 0 and "SSH_OK" not in out:
            self.client = None
            raise RuntimeError("SSH 通道已建立但远程命令无法执行（exit=%s out=%s）" % (rc, out[:80]))
        self._connected_ok = True

    def close(self):
        self._connected_ok = False
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def _exec(self, cmd_str, timeout=25):
        if not self.client:
            return -1, "尚未连接远程服务器"
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd_str, timeout=timeout)
            out = stdout.read() + stderr.read()
            rc = stdout.channel.recv_exit_status()
            return rc, _decode(out)
        except Exception as e:
            return -1, "远程命令执行失败: %s" % e

    def run(self, cmd, timeout=25):
        if isinstance(cmd, str):
            cmd_str = cmd
        else:
            cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
        return self._exec(cmd_str, timeout)

    def read_file(self, path):
        rc, out = self._exec("cat %s 2>/dev/null" % shlex.quote(path))
        return out if rc == 0 else ""

    def is_privileged(self):
        rc, out = self._exec("id -u")
        ok = rc == 0 and out.strip() == "0"
        return ok, ("root" if ok else "非root用户(%s)" % out.strip())

    def file_mode(self, path):
        rc, out = self._exec("stat -c %%a %s 2>/dev/null" % shlex.quote(path))
        mode = out.strip() if rc == 0 and out.strip() else None
        return mode, "" if mode else "无法读取权限"

    def os_name(self):
        rc, out = self._exec(
            ". /etc/os-release 2>/dev/null; echo \"${PRETTY_NAME:-unknown}\"; uname -r")
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) >= 2:
            return "%s (内核 %s)" % (lines[0], lines[1])
        return lines[0] if lines else "远程Linux"


class WinRMExecutor(Executor):
    """通过 WinRM 检测远程 Windows 服务器"""
    platform = "windows"

    def __init__(self, host, port=5985, user="Administrator", password="",
                 transport="ntlm", timeout=20):
        self.host = host
        self.port = int(port or 5985)
        self.user = user or "Administrator"
        self.password = password or ""
        self.transport = transport or "ntlm"
        self.timeout = timeout
        self.session = None
        self._connected_ok = False

    def connect(self):
        try:
            import winrm
        except ImportError:
            raise RuntimeError("缺少 pywinrm 依赖，请执行：pip install pywinrm")
        scheme = "https" if self.port in (5986,) else "http"
        endpoint = "%s://%s:%d/wsman" % (scheme, self.host, self.port)
        try:
            self.session = winrm.Session(
                endpoint, auth=(self.user, self.password),
                transport=self.transport, server_cert_validation="ignore",
                operation_timeout_sec=self.timeout, read_timeout_sec=self.timeout + 10)
            # 二次验证：跑 Get-ComputerInfo 确认通道可用
            r = self.session.run_ps("$PSVersionTable.PSVersion.ToString()")
            if r.status_code != 0:
                self.session = None
                raise RuntimeError(
                    "WinRM 通道已建立但远程命令无法执行（exit=%s out=%s）"
                    % (r.status_code, (r.std_err or r.std_out or "")[:120]))
        except Exception as e:
            self.session = None
            raise RuntimeError(
                "WinRM 连接 %s 失败：%s\n请确认目标机已执行 Enable-PSRemoting -Force，"
                "并允许 5985(HTTP)/5986(HTTPS) 端口与 NTLM 认证。" % (endpoint, e))
        self._connected_ok = True

    def close(self):
        self._connected_ok = False
        self.session = None

    @staticmethod
    def _argv_to_ps(argv):
        def q(s):
            return "'" + str(s).replace("'", "''") + "'"
        return "& " + " ".join(q(a) for a in argv)

    def run_ps(self, script, timeout=30):
        if not self.session:
            return -1, "尚未连接远程服务器"
        try:
            r = self.session.run_ps(script)
            return r.status_code, _decode(r.std_out + r.std_err)
        except Exception as e:
            return -1, "远程PowerShell执行失败: %s" % e

    def run(self, cmd, timeout=25):
        if isinstance(cmd, str):
            return self.run_ps(cmd, timeout)
        return self.run_ps(self._argv_to_ps(cmd), timeout)

    def read_file(self, path):
        p = str(path).replace("'", "''")
        rc, out = self.run_ps("if(Test-Path '%s'){Get-Content '%s' -Raw}else{'NOPATH'}" % (p, p))
        return "" if "NOPATH" in out else out

    def is_privileged(self):
        rc, out = self.run_ps(
            "$p=New-Object Security.Principal.WindowsPrincipal("
            "[Security.Principal.WindowsIdentity]::GetCurrent());"
            "if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){'YES'}else{'NO'}")
        ok = "YES" in out
        return ok, "管理员权限" if ok else "非管理员权限，部分检测项将被跳过"

    def file_mode(self, path):
        return None, "Windows不使用Unix文件权限"

    def os_name(self):
        rc, out = self.run_ps(
            "$k=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
            "-ErrorAction SilentlyContinue;"
            "if($k){$k.ProductName+' '+$k.DisplayVersion+' Build '+$k.CurrentBuild}else{'Windows'}")
        return out.strip().splitlines()[0] if out.strip() else "远程Windows"


def build_executor(conf):
    """根据界面配置构造执行器。conf: dict(mode/host/port/user/password/keyfile/transport)

    连接超时优先取 conf["timeout"]，其次取「系统设置」里的 timeout（默认 12 秒）。
    """
    conf = conf or {}
    try:
        from core import appconfig
        timeout = int(conf.get("timeout") or appconfig.get("timeout", 12) or 12)
    except Exception:
        timeout = 12
    mode = conf.get("mode", "local")
    if mode == "ssh":
        return SSHExecutor(conf.get("host", ""), conf.get("port", 22),
                           conf.get("user", "root"), conf.get("password", ""),
                           conf.get("keyfile", ""), timeout=timeout)
    if mode == "winrm":
        return WinRMExecutor(conf.get("host", ""), conf.get("port", 5985),
                             conf.get("user", "Administrator"),
                             conf.get("password", ""),
                             conf.get("transport", "ntlm"), timeout=timeout)
    return LocalExecutor()
