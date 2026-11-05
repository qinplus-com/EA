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

# Linux：RPM / DEB / 源码 tar.xz
./build_linux.sh
```

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
