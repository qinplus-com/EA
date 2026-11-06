# 勤加等保测评助手（EA）

等级保护 2.0 技术检测与问卷评估一体化工具，依据 GB/T 22239-2019，支持等保二级 / 三级。

- Windows 桌面版：**勤加等保测评助手**（PyQt5，绿色免安装）
- Linux 版：**qinplus-dengbao**（GUI / 命令行 `qinplus-dengbao-cli`）
- 当前版本：**V1.0**

在线演示（不完全功能）：https://ea.qinplus.com

## 功能

| 模块 | 说明 |
| --- | --- |
| 检测范围 | 按层面选择待测对象：物理安全、计算环境、区域边界、通信网络、管理中心、管理安全 |
| 技术检测 | 本地 / SSH 远程一键自查：操作系统、数据库、中间件、网络设备、安全设备、物理环境 |
| 问卷评估 | 自动生成等保问卷（三级 144 题：物理 30 + 管理 114），草稿自动保存 |
| 检测报告 | 汇总技术检测与问卷结果，导出 Word / HTML / PDF，不符合项整改建议 |
| 历史对比 | 多次检测留痕，对比整改成效 |
| 安全基线 | 版本基线 + CVE 漏洞库，支持在线更新 / 本地导入 / 恢复内置 |

## 基线数据与在线更新

- `data/security_baseline.json`：版本基线（各产品安全版本下限）
- `data/cve_db.json`：CVE 漏洞库（组件版本区间 → CVE 映射，16 个组件）
- 客户端默认在线更新链接（按当天日期生成）：
  - `https://ea.qinplus.com/security_baseline.<YYYY-MM-DD>.json`
  - `https://ea.qinplus.com/cve_db.<YYYY-MM-DD>.json`
- 服务端每日自动生成：`tools/update_baseline.sh`（拉取 NVD 近 7 天 CVE 并发布，cron 部署示例见脚本注释）

## 运行（源码）

```bash
pip install -r requirements.txt
python main.py          # GUI
python cli.py --help    # 命令行
```

## 打包

```bash
# Windows：生成解压版 zip（exe + data 基线数据）
python build_windows.py
#   产物：dist/勤加等保测评助手V1.0_windows.zip

# Linux 源码发行包（含源码 + 基线数据，可在任意平台生成）
#   产物：dist/qinplus-dengbao-1.0.tar.gz
tar -czf dist/qinplus-dengbao-1.0.tar.gz ...   # 或使用 make dist
```

### Linux 安装（麒麟 Kylin / 统信 UOS / Deepin / Ubuntu）

```bash
tar -xzf qinplus-dengbao-1.0.tar.gz
cd qinplus-dengbao-1.0
sudo apt install python3-pyqt5 python3-paramiko python3-docx   # 依赖（可选）
./configure --prefix=/usr
make
sudo make install        # 安装 qinplus-dengbao（GUI）与 qinplus-dengbao-cli（命令行）
sudo make uninstall      # 卸载
```

如需在本机生成原生二进制 / RPM / DEB（需在 Linux 上执行）：

```bash
./build_linux.sh         # PyInstaller 独立可执行文件 + .deb
make rpm                 # RPM 安装包
make deb                 # DEB 安装包
```

### Linux 依赖安装常见问题

**1. yum 没有 `python3-pyqt5`**

`python3-pyqt5` 是 Debian/Ubuntu 的包名。CentOS / RHEL / 麒麟服务器版请用 EPEL 源，包名前缀不同：

```bash
# CentOS 7（Python 3.6，包名带 python36- 前缀）
sudo yum install -y epel-release
sudo yum install -y python36-qt5 python36-paramiko

# CentOS / Rocky 8、9 或麒麟 V10 服务器版
sudo yum install -y epel-release
sudo yum install -y python3-qt5 python3-paramiko
```

可用镜像（EPEL）：

| 镜像 | 地址 |
| --- | --- |
| 阿里云 | `https://mirrors.aliyun.com/epel/` |
| 清华 | `https://mirrors.tuna.tsinghua.edu.cn/epel/` |
| 华为云 | `https://repo.huaweicloud.com/epel/` |

**2. `Could not find a version that satisfies the requirement PyQt5-Qt5>=5.15.2`**

原因：CentOS 7 自带的 pip 是 9.x，不识别 `manylinux2014` 轮子标签，`PyQt5-Qt5` 的 wheel 被全部过滤掉。两种解法任选其一：

```bash
# 方案 A（推荐）：PyQt5 5.14.2 把 Qt 内置在同一个 manylinux1 轮子里，无该依赖
sudo python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple/ PyQt5==5.14.2

# 方案 B：升级 pip（21.3.1 是最后一个支持 Python 3.6 的版本）后再装最新版
sudo python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple/ --upgrade "pip==21.3.1"
sudo python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple/ PyQt5==5.15.6
```

pip 自身升级失败时，可离线引导：

```bash
curl -L -o get-pip.py https://bootstrap.pypa.io/pip/3.6/get-pip.py
sudo python3 get-pip.py -i https://mirrors.aliyun.com/pypi/simple/
```

**3. 其余依赖在老 pip 上也要锁版本**

```bash
sudo python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple/ \
    paramiko==2.12.0 cryptography==3.3.2 bcrypt==3.2.0 pynacl==1.4.0 python-docx==0.8.11
```

**4. 启动报 xcb 插件加载失败**

```bash
sudo yum install -y mesa-libGL libXext libXrender libX11-xcb libxcb libxkbcommon-x11
```

**5. 安装后自检**

```bash
python3 -c "import PyQt5.QtCore as c; print('PyQt5', c.PYQT_VERSION_STR)"
python3 -c "import paramiko, docx; print('依赖 OK')"
qinplus-dengbao-cli --list-layers     # 命令行版可用即说明数据与检测项正常
```

注意：`pip3` 必须与运行程序的 `python3` 是同一个解释器（`pip3 -V` 的路径应为 python3.6）。

## 目录结构

```
assets/         图标资源
checks/         检测项实现（版本比对、SSH、本地策略等）
core/           引擎、存储、报告、基线、配置
data/           基线数据（security_baseline.json / cve_db.json）
packaging/      Linux 打包模板（RPM/DEB/autotools）
questionnaire/  问卷题库（由 checks/manual_checks.py 生成）
tools/          运维脚本（基线日更等）
ui/             PyQt5 界面
```

## 开源协议

[MIT](LICENSE) © 2026 内蒙古勤加软件有限公司
