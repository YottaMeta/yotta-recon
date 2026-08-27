<p align="center"><b>Language</b>: <a href="./README.md">English</a> · 中文</p>

<p align="center">
  <img src="assets/banner.png" alt="yotta-recon banner" width="100%" />
</p>

<h1 align="center">yotta-recon · 元析</h1>

<p align="center">YottaMeta 自有的零依赖网络侦察引擎：<b>端口扫描 · 服务识别 · 版本指纹</b>，纯 Python 3.8+ 标准库实现，内建授权纪律（Scope Guard）。适用于安全测试侦察阶段、资产盘点、暴露面摸底等需要先摸清目标开放端口与服务版本的场景。</p>
<p align="center">检测到扫描网络 / 端口扫描 / 服务识别 / 版本指纹 / 资产盘点 / CDN 溯源 / 安全测试侦察阶段 等意图时自动激活——<b>不靠关键词碰运气，按待侦察目标判定</b>。</p>
<p align="center">不依赖 nmap 等任何外部工具；Windows + Linux + macOS 通用；只读探测、默认拒绝未授权目标、报告留痕。</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue" /></a>
  <a href="https://agentskills.io/"><img alt="Standard: agentskills.io" src="https://img.shields.io/badge/standard-agentskills.io-orange" /></a>
  <a href="https://www.npmjs.com/package/@yottameta/yotta-recon"><img alt="npm package" src="https://img.shields.io/npm/v/@yottameta/yotta-recon" /></a>
  <a href="https://github.com/YottaMeta/yotta-recon"><img alt="GitHub stars" src="https://img.shields.io/github/stars/YottaMeta/yotta-recon" /></a>
  <a href="https://github.com/YottaMeta/yotta-recon/commits/main"><img alt="last commit" src="https://img.shields.io/github/last-commit/YottaMeta/yotta-recon" /></a>
  <a href="https://github.com/YottaMeta/yotta-recon"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen" /></a>
</p>

## 这是什么

安全测试的第一步是侦察：目标开放了哪些端口、跑着什么服务、版本是什么。元析把这些能力做成零依赖的自研引擎——不依赖 nmap 等外部工具，纯 Python 标准库即可完成 TCP connect 端口扫描、服务 banner 抓取与版本指纹识别，并把「未授权目标默认拒绝」做成硬机制（Scope Guard）。

它不是某个平台的专属功能，而是一份与智能体无关的工具包：装进任何支持 Agent Skills 的智能体即可按需调用。只读探测、绝不写入目标系统，也不需要常驻服务。

## 核心价值

- **零依赖自研**：TCP 端口扫描 / banner 抓取 / 协议探测全部用 Python 3.8+ 标准库实现，不依赖 nmap 等外部工具。
- **服务与版本指纹**：HTTP / SSH / FTP / SMTP / POP3 / IMAP / Redis / MySQL / PostgreSQL / TLS / MongoDB 等常见服务自动识别产品与版本。
- **Scope Guard 授权纪律**：未授权目标默认拒绝（退出码 3）；--scope 授权文件或 --assume-authorized --yes 显式声明后放行。
- **已知风险提示**：版本指纹命中内置风险映射时标注等级并提示「请人工核实」，不提供利用细节。
- **三种输出**：文本表格 / JSON（stdout 纯净）/ Markdown 报告（含 scan_id、时间、授权来源，操作留痕）。
- **本机清单**：local 子命令读取本机监听端口（只读），方便资产盘点。

## 核心优势

| 优势 | 说明 |
|---|---|
| **零依赖** | Python 3.8+ 标准库，无 daemon / 无数据库 / 无外部扫描器；Windows + Linux + macOS 通用 |
| **授权纪律** | 默认只放行回环地址；授权范围文件 / 显式声明两种授权方式；AI 场景无确认直接拒绝 |
| **温和可调** | 并发（--concurrency）、超时（--timeout）、限速（--rate）可调，避免扫描风暴 |
| **指纹可解释** | 产品 / 版本 / 风险等级逐项输出，风险提示只匹配、不利用、需人工核实 |
| **目标灵活** | IP / CIDR / 主机名 / 目标文件，端口自定义或内置常用端口表 |
| **生态分发** | GitHub + npm + ClawHub 三源同步发布；npx / install.sh / 手动复制三种安装方式 |

## 功能体系

| 能力 | 说明 |
|---|---|
| scan | 端口 / 服务 / 版本指纹扫描，输出文本 / JSON / Markdown |
| fingerprint | 单端口深度指纹（服务、版本、风险、banner） |
| check-scope | Scope Guard 授权预检（AI 先 check 再 scan） |
| local | 本机监听端口清单（只读） |
| list-ports | 列出内置常用端口表 |

## 快速使用

Windows 用 python，Linux/macOS 用 python3。

```bash
# 扫描本机回环（默认放行，无需授权）
python3 scripts/yotta_recon.py scan --targets 127.0.0.1 --top 100

# 有授权范围文件（Scope Guard 声明授权）
python3 scripts/yotta_recon.py scan --targets 192.168.1.0/30 --scope scope.txt --yes

# 用户明确声明已获授权
python3 scripts/yotta_recon.py scan --targets <目标> --assume-authorized --yes

# 单端口深度指纹
python3 scripts/yotta_recon.py fingerprint --host 127.0.0.1 --port 80

# 授权预检（AI 先 check 再 scan）
python3 scripts/yotta_recon.py check-scope --targets <目标> --scope scope.txt

# 本机监听端口清单（只读）
python3 scripts/yotta_recon.py local

# JSON 输出 / Markdown 报告
python3 scripts/yotta_recon.py scan --targets 127.0.0.1 --json
python3 scripts/yotta_recon.py scan --targets 127.0.0.1 --report report.md
```

## 安装

三种方式任选其一，技能文件统一从 **npm** 获取（GitHub 无代理时较慢，npm 可配国内镜像加速）。

### 方式一：npm（推荐，一行安装）
```bash
# 国内加速（可选）：npm config set registry https://registry.npmmirror.com
npx -y @yottameta/yotta-recon -g
npx -y @yottameta/yotta-recon --dir <你的技能目录>   # 任意智能体：指定目录安装
```
> 智能体不在预置列表里？用 --dir 指定它的 skills 目录，或手动复制（方式三）。--list 可查看各智能体对应的默认目录。想手动拿文件也可 npm pack @yottameta/yotta-recon 解包后按方式二/三安装。

### 方式二：install.sh 一键安装
获取技能文件夹后（npm pack 解包或 git clone），进入技能文件夹：
```bash
bash install.sh -g    # 用户级；bash install.sh --list 查看全部目录
bash install.sh --agent codex   # 指定智能体（--list 可查看可用项）
bash install.sh       # 项目级：自动检测已存在的 .claude/.cursor/.codex 等 skills 目录
bash install.sh --dir /path/to/skills
```
> 覆盖 17 类智能体，含国内 Trae / Qwen / Comate / CodeBuddy / Kimi。Windows 用户：装有 Git Bash 即可用；否则用方式三手动复制。

### 方式三：手动复制
把整个 yotta-recon 文件夹复制到目标智能体的 skills 目录。常见位置（用户级；Windows 用 %USERPROFILE%，Linux/macOS 用 ~）：

| 智能体 | 用户级目录 | 项目级目录 |
|---|---|---|
| Codex | %USERPROFILE%\.codex\skills\yotta-recon\ | .codex\skills\ |
| Claude Code | %USERPROFILE%\.claude\skills\yotta-recon\ | .claude\skills\ |
| Cursor | %USERPROFILE%\.cursor\skills\yotta-recon\ | .cursor\skills\ |
| Windsurf | %USERPROFILE%\.codeium\windsurf\skills\yotta-recon\ | .windsurf\skills\ |
| opencode | %USERPROFILE%\.config\opencode\skills\yotta-recon\ | .opencode\skills\ |
| Gemini | %USERPROFILE%\.gemini\skills\yotta-recon\ | .gemini\skills\ |
| Goose | %USERPROFILE%\.config\goose\skills\yotta-recon\ | .goose\skills\ |
| Amp | %USERPROFILE%\.config\agents\skills\yotta-recon\ | .agents\skills\ |
| Kiro | %USERPROFILE%\.kiro\skills\yotta-recon\ | .kiro\skills\ |
| WorkBuddy | %USERPROFILE%\.workbuddy\skills\yotta-recon\ | .workbuddy\skills\ |
| Trae Code CLI | %USERPROFILE%\.traecli\skills\yotta-recon\ | .traecli\skills\ |
| Trae IDE（国内） | %USERPROFILE%\.trae-cn\skills\yotta-recon\ | .trae\skills\ |
| Qwen Code | %USERPROFILE%\.qwen\skills\yotta-recon\ | .qwen\skills\ |
| Comate | %USERPROFILE%\.comate\skills\yotta-recon\ | .comate\skills\ |
| CodeBuddy | %USERPROFILE%\.codebuddy\skills\yotta-recon\ | .codebuddy\skills\ |
| Kimi | %USERPROFILE%\.kimi\skills\yotta-recon\ | .kimi\skills\ |
| 通用 AGENTS.md | %USERPROFILE%\.agents\skills\yotta-recon\ | .agents\skills\ |

> Codex 默认目录若设置了环境变量 CODEX_HOME，以该变量为准；opencode 若设置 XDG_CONFIG_HOME 同理。.agents\skills 并非通用目录，仅 OpenCode / Cursor / Cline / Amp / Kimi / Gemini CLI / GitHub Copilot 等会读取，**Claude Code 与 Codex 默认不读**。不确定时用 --dir 指定，或让该智能体自行安装。

## 升级 / 卸载

- **升级**：重新安装最新版覆盖即可——npx -y @yottameta/yotta-recon -g 或重跑 bash install.sh -g。技能目录内的旧文件会被覆盖；不影响项目中已有的其他文件。
- **卸载**：删除目标智能体 skills 目录下的 yotta-recon 文件夹（各智能体目录见上表）即可。卸载后本技能不再生效。

## 常见问题

- **会主动攻击目标吗？** 不会。元析只做只读探测（TCP connect / banner 读取 / 协议探测），不发送攻击载荷、不写入、不删除、不利用。
- **扫描别的机器合规吗？** 仅对已获明确授权的目标进行侦察。未经授权扫描他人系统违反《网络安全法》与《刑法》285/286 条，使用者自行承担法律责任。
- **为什么默认拒绝非回环目标？** 侦察是安全测试中法律风险最高的环节之一，Scope Guard 把「未授权默认拒绝」做成硬机制，需要 --scope 授权文件或 --assume-authorized --yes 显式声明。
- **风险提示代表目标一定有问题吗？** 不是。风险提示仅为版本指纹匹配，版本号可能被伪装或已打补丁；报告措辞为「请人工核实」，需结合上下文判断。
- **和 nmap 有什么区别？** 元析不依赖任何外部工具，零依赖即可完成常见侦察任务；nmap 功能更全，但需要安装与权限。需要更深度扫描时两者可互补。

## 相关技能

同属 YottaMeta 技能矩阵（安全家族）：[yotta-security-audit](https://github.com/YottaMeta/yotta-security-audit)（元安，技能与系统安全审计）与 [yotta-vetter](https://github.com/YottaMeta/yotta-vetter)（元审，安装前四阶段初审）负责风险核查；[yotta-memory](https://github.com/YottaMeta/yotta-memory)（元忆）负责跨会话长期记忆。

## 开发与校验

本项目内运行：python tools/validate-skill.py yotta-recon。

## 许可证

MIT © YottaMeta —— 详见 [LICENSE](./LICENSE)。品牌声明见 [NOTICE](./NOTICE)。上游来源致谢：网络侦察方向参考开源社区 network-security-scanner 类技能思路，实现为 YottaMeta 自有、零依赖重写。
