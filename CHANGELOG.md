# 更新日志
## v0.1.3 (2026-08-26)

- **ClawHub 展示名 + 分类修正（三源重发）**：v0.1.2 发布到 ClawHub 时展示名未传 `--name`（默认成 `yotta-recon`，漏「元析」前缀），且 `--topics` 被误传成带空格的单个串，导致 ClawHub 把它存成单一 topic `security network recon`、界面连成 `#security-network-recon` 派生新分组。
- 本版修正：展示名显式传 `元析 yotta-recon`；分类用逗号分隔传 `--topics security,network,recon`，落回 `security` 分组下的三个独立 topic 标签（`#security #network #recon`）。
- 版本 0.1.2 → 0.1.3（package.json / SKILL.md frontmatter / 引擎 VERSION / 测试断言对齐）。
## v0.1.2 (2026-08-26)

- **ClawHub 补分类（三源重发）**：v0.1.1 发布到 ClawHub 时未传 `--categories`/`--topics`，导致技能在 ClawHub 落入 Uncategorized（无分组）；按 2026-08-26「ClawHub 发布必带分类」红线，本版重新发布并补上分类。
- ClawHub 分类：`security`（分组）+ topics `security, network, recon`；GitHub / npm / ClawHub 三源同步发布。
- 版本 0.1.1 → 0.1.2（package.json / SKILL.md frontmatter / 引擎 VERSION 对齐）。

## v0.1.1 (2026-08-26)

- 中文名统一为「元析」（去掉「（元征）」双名）：SKILL.md / README / package.json / 引擎 TOOL_CN 与 docstring / 测试断言 / NOTICE 同步。
- 版本 0.1.0 → 0.1.1（SKILL.md frontmatter + package.json + 引擎 VERSION 对齐）。

## v0.1.0 (2026-08-26)

YottaMeta 自有实现首版（网络侦察方向参考开源社区 network-security-scanner 类技能思路，已完全重写，零依赖、无上游代码）：

- **零依赖自研引擎**（scripts/yotta_recon.py，Python 3.8+ 标准库）：TCP connect 端口扫描（并发/限速/超时可调）+ 服务 banner 抓取 + 协议探测（HTTP / SSH / FTP / SMTP / POP3 / IMAP / Redis / MySQL / PostgreSQL / TLS / MongoDB）。
- **Scope Guard 授权纪律**：未授权目标默认拒绝（退出码 3）；回环地址默认放行；--scope 授权文件 / --assume-authorized --yes 显式授权；check-scope 授权预检；交互确认（AI 无输入自动拒绝）。
- **版本提取与已知风险提示**：内置风险映射（ProFTPD 1.3.5 / vsftpd 2.3.4 / 旧版 OpenSSH / Apache 等），只提示「请人工核实」，不提供利用细节。
- **三种输出**：文本表格 / JSON（stdout 纯净）/ Markdown 报告（scan_id + 时间 + 授权来源，操作留痕）。
- **本机清单**：local 子命令读取本机监听端口（Linux/macOS 读 /proc/net/tcp；Windows 用系统 netstat 只读查询）。
- **测试**：scripts/test_yotta_recon.py 61 项全绿（解析 / Scope Guard / 真实本地服务指纹 / 输出 / CLI 退出码）。
- **文档**：SKILL.md / README.md / references（scope-guard / service-fingerprints / protocol-probes）/ assets/banner.png。
- 版权：YottaMeta 纯自有 MIT + NOTICE 品牌声明；README 一行上游致谢。
