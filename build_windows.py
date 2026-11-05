# -*- coding: utf-8 -*-
"""Windows 打包脚本：勤加等保测评助手 V1.0（仅提供解压版 zip）

运行：
    python build_windows.py

产物：
    dist/勤加等保测评助手V1.0_windows.zip
        ├─ 勤加等保测评助手.exe      （PyInstaller 单文件，绿色免安装）
        └─ data/                    （基线数据，用户可见可编辑）
            ├─ security_baseline.json   版本基线
            └─ cve_db.json              CVE 漏洞库

依赖：
    pip install pyinstaller python-docx PyQt5
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
APP_EXE = "ea_dengbao"          # PyInstaller 产物名（spec 中定义）
APP_CN = "勤加等保测评助手"      # 对外中文名
VERSION = "V1.0"


def clean():
    for d in (DIST, BUILD):
        if d.exists():
            print(f"清理 {d} ...")
            shutil.rmtree(d, ignore_errors=True)


def build_exe():
    print("=" * 60)
    print("开始 PyInstaller 打包（Windows）...")
    print("=" * 60)
    cmd = [sys.executable, "-m", "PyInstaller",
           "--noconfirm", str(ROOT / "ea_dengbao.spec")]
    ret = subprocess.call(cmd, cwd=str(ROOT))
    if ret != 0:
        print("打包失败，退出码", ret)
        sys.exit(ret)
    exe = DIST / f"{APP_EXE}.exe"
    if not exe.exists():
        print("✗ 未找到 exe 产物")
        sys.exit(1)
    size_mb = exe.stat().st_size / 1024 / 1024
    print(f"✓ 生成 exe: {exe}  ({size_mb:.1f} MB)")
    return exe


def build_zip(exe):
    """打 zip 解压版：exe（中文名）+ data/ 基线数据"""
    stage = DIST / f"{APP_CN}{VERSION}"
    if stage.exists():
        shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)

    # exe 以中文名放入压缩包
    shutil.copy2(exe, stage / f"{APP_CN}.exe")

    # 基线数据（版本基线 + CVE 漏洞库），随包分发、用户可见可编辑
    data_out = stage / "data"
    data_out.mkdir()
    for name in ("security_baseline.json", "cve_db.json"):
        src = ROOT / "data" / name
        if not src.exists():
            print(f"✗ 缺少基线数据 {src}")
            sys.exit(1)
        shutil.copy2(src, data_out / name)
        print(f"✓ 打包基线数据: data/{name}")

    zip_path = shutil.make_archive(
        str(DIST / f"{APP_CN}{VERSION}_windows"), "zip", root_dir=DIST,
        base_dir=stage.name)
    size_mb = Path(zip_path).stat().st_size / 1024 / 1024
    print(f"✓ 解压版压缩包: {zip_path}  ({size_mb:.1f} MB)")
    return zip_path


def main():
    clean()
    exe = build_exe()
    zip_path = build_zip(exe)
    print("\n打包完成！")
    print(f"发布产物（解压即用）: {zip_path}")


if __name__ == "__main__":
    main()
