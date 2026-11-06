# -*- coding: utf-8 -*-
"""勤加等保测评助手 - 使用帮助内容（内嵌 HTML，Windows / Linux 桌面版通用）

使用 QTextBrowser 渲染，仅使用其支持的基础 HTML 标签与少量内联样式。
在线演示完整版：https://ea.qinplus.com/docs/usage.html
"""

HELP_HTML = """
<h2>勤加等保测评助手 · 使用文档</h2>
<p><b>版本 V1.0</b>　简称：测评助手（Evaluation Assistant）<br>
在线演示：https://ea.qinplus.com　｜　HTML 版使用文档：https://ea.qinplus.com/docs/usage.html</p>
<hr>

<h3>一、产品简介</h3>
<p>本工具按《信息安全技术 网络安全等级保护基本要求》（GB/T 22239-2019）二级 / 三级要求，
将一次完整的等保自查拆解为「资产识别 → 技术检测 → 问卷评估 → 报告输出」四个环节：</p>
<ul>
<li><b>技术检测</b>：操作系统、网络与边界、数据库、中间件与 Web、应用与数据等层面自动取证；</li>
<li><b>问卷评估</b>：安全物理与通信安全、安全管理（制度/机构/人员/建设/运维）等人工核查项，按条款逐题确认；</li>
<li><b>报告输出</b>：自动汇总符合率，导出 HTML / Word / PDF 自查报告。</li>
</ul>

<h3>二、安装与启动</h3>
<p><b>Windows</b>：解压「勤加等保测评助手V1.0_windows.zip」后运行「勤加等保测评助手.exe」（绿色免安装，压缩包已含 data/ 基线数据）。
部分检测项（如本地安全策略）需管理员权限，程序已内置管理员清单。</p>
<p><b>Linux / 国产操作系统（麒麟 Kylin、统信 UOS、Deepin、OpenEuler 等）</b>：</p>
<pre>
# 方式一：源码安装（configure / make / make install）
sh ./configure --prefix=/usr
make
sudo make install          # 安装桌面版 qinplus-dengbao 与命令行版 qinplus-dengbao-cli

# 方式二：RPM 安装（CentOS / OpenEuler / Anolis / 麒麟服务器版）
make rpm                   # 生成 dist/rpmbuild/RPMS/noarch/*.rpm
sudo rpm -ivh qinplus-dengbao-1.0-1.noarch.rpm

# 方式三：DEB 安装（Debian / Ubuntu / UOS / Deepin）
make deb
sudo dpkg -i dist/qinplus-dengbao_1.0_amd64.deb
</pre>
<p>依赖（建议统一用 pip 安装，镜像更快、版本可控）：</p>
<pre>
python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple/ \
    dataclasses PyQt5==5.14.2 paramiko==2.12.0 cryptography==3.3.2 \
    bcrypt==3.2.0 pynacl==1.4.0 python-docx==0.8.11
</pre>
<p>说明：dataclasses 在 Python 3.7+ 已内置；Python 3.6（CentOS 7 / 麒麟 V10 等）需单独安装。PyQt5 仅桌面版需要，命令行版可不装。</p>

<h3>三、界面导航</h3>
<ul>
<li><b>关于</b>：启动后的默认首页，展示产品信息与在线演示入口；</li>
<li><b>检测范围</b>：选择等保级别（二级/三级）与安全层面，填写被测对象名称与登录信息；</li>
<li><b>技术检测</b>：查看检测进度与逐项结果（符合/不符合/部分符合/人工核查）；</li>
<li><b>问卷评估</b>：人工核查问卷，支持草稿自动保存与 CSV 导出/导入；</li>
<li><b>检测报告</b>：汇总评分与不符合项，导出报告；</li>
<li><b>历史对比</b>：对比历次自查结果，跟踪整改成效；</li>
<li><b>系统设置</b>：报告目录、机构名称、SNMP 团体名、超时、主题等；</li>
<li><b>安全基线</b>：内置安全基线库与 CVE 漏洞库，支持离线更新与版本追溯；</li>
<li><b>运行日志</b>：查看运行与检测日志；</li>
<li><b>使用帮助</b>：即本文档。</li>
</ul>

<h3>四、检测流程</h3>
<ol>
<li>在「检测范围」选择等保级别与安全层面，填写被测对象名称；</li>
<li>选择登录方式：本机 / SSH（Linux）/ WinRM（Windows），填写账号口令或密钥，点击「测试连接」；</li>
<li>点击「开始一键自查」，技术层面自动取证；「物理与通信」「安全管理」层面自动进入问卷评估（人工核查）；</li>
<li>在「问卷评估」按现场取证情况逐题确认，答案自动保存草稿；</li>
<li>在「检测报告」查看符合率与整改建议，导出 HTML / Word / PDF 报告。</li>
</ol>
<p><b>权限提示</b>：Linux 建议 root（或 sudo），Windows 建议管理员；权限不足时检测结果会标注「需提升权限」。</p>

<h3>五、命令行版本（qinplus-dengbao-cli）</h3>
<p>适用于无图形环境的服务器，参数与桌面版一致：</p>
<pre>
qinplus-dengbao-cli --list-layers                          # 列出可用检测层面
qinplus-dengbao-cli --level 三级 --format all              # 本机全层面检测
qinplus-dengbao-cli --mode ssh --host 192.168.1.10 \\
    --user root --password 'xxx' --layers 设备,数据库 \\
    --format html --out /tmp/ea-reports
qinplus-dengbao-cli --quiz-template 问卷模板.csv            # 导出空白问卷
qinplus-dengbao-cli --quiz 已答问卷.csv                     # 将问卷答案写入报告
</pre>

<h3>六、常见问题</h3>
<ul>
<li><b>SSH 连接失败</b>：确认目标开启 22 端口、账号口令正确；密钥登录请使用 --keyfile 或在界面选择私钥文件。</li>
<li><b>检测项显示「需人工核查」</b>：该类项属于物理环境或管理要求，请在问卷评估中作答。</li>
<li><b>报告输出位置</b>：默认在桌面「等保自查报告」文件夹，可在系统设置中修改。</li>
<li><b>Linux 桌面版无法启动</b>：提示未安装 PyQt5 时，执行 python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple/ PyQt5==5.14.2（Python 3.6 请用 5.14.2，详见 README「Linux 依赖安装常见问题」）。</li>
</ul>

<h3>七、免责声明</h3>
<p>本工具仅用于内部等保自测与学习交流，不作为等级保护测评的正式评审依据。
如需正式测评，请委托具备资质的测评机构。</p>
<p>内蒙古勤加软件有限公司　｜　https://www.qinplus.com　｜　info@qinplus.com</p>
"""
