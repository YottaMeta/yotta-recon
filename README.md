<p align="center"><b>Language</b>: English · <a href="./README.zh-CN.md">中文</a></p>

<p align="center">
  <img src="assets/banner.png" alt="yotta-recon banner" width="100%" />
</p>

<h1 align="center">yotta-recon · 元析 (Yuanxi)</h1>

<p align="center">YottaMeta's zero-dependency network recon engine: <b>port scanning · service identification · version fingerprinting</b>, implemented purely with the Python 3.8+ standard library and built-in authorization discipline (Scope Guard). Use it for the recon phase of security testing, asset inventory, and exposure mapping where you need to first establish which ports are open and which services / versions a target runs.</p>
<p align="center">Activates when the user asks to scan a network / ports, identify services or version fingerprints, inventory assets, trace CDN origins, or run the recon phase of a security test — <b>judged by the target, not keyword luck</b>.</p>
<p align="center">No external tools required (no nmap); Windows + Linux + macOS; read-only probing, unauthorized targets denied by default, reports leave an audit trail.</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue" /></a>
  <a href="https://agentskills.io/"><img alt="Standard: agentskills.io" src="https://img.shields.io/badge/standard-agentskills.io-orange" /></a>
  <a href="https://www.npmjs.com/package/@yottameta/yotta-recon"><img alt="npm package" src="https://img.shields.io/npm/v/@yottameta/yotta-recon" /></a>
  <a href="https://github.com/YottaMeta/yotta-recon"><img alt="GitHub stars" src="https://img.shields.io/github/stars/YottaMeta/yotta-recon" /></a>
  <a href="https://github.com/YottaMeta/yotta-recon/commits/main"><img alt="last commit" src="https://img.shields.io/github/last-commit/YottaMeta/yotta-recon" /></a>
  <a href="https://github.com/YottaMeta/yotta-recon"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen" /></a>
</p>

## What it is

The first step of a security test is recon: which ports are open on the target, what services are running, and what versions. Yuanxi packages this into a zero-dependency in-house engine — no external tools like nmap; TCP connect port scanning, service banner grabbing and version fingerprinting are done with the Python standard library alone, and "unauthorized target denied by default" is a hard mechanism (Scope Guard).

It is not tied to any single platform: an agent-agnostic toolkit that works in any agent supporting Agent Skills. Read-only probing only — it never writes to the target system and needs no resident service.

## Core value

- **Zero-dependency in-house** — TCP port scanning / banner grabbing / protocol probing all implemented with the Python 3.8+ standard library; no external tools like nmap.
- **Service & version fingerprinting** — HTTP / SSH / FTP / SMTP / POP3 / IMAP / Redis / MySQL / PostgreSQL / TLS / MongoDB and other common services auto-identified with product and version.
- **Scope Guard authorization discipline** — unauthorized targets are denied by default (exit code 3); a --scope authorization file or an explicit --assume-authorized --yes declaration is required to proceed.
- **Known-risk hints** — when a version fingerprint hits the built-in risk map, it flags the level and says "please verify manually"; it never ships exploit details.
- **Three output modes** — text table / JSON (clean stdout) / Markdown report (with scan_id, time, authorization source — a full audit trail).
- **Local inventory** — the local subcommand lists this machine's listening ports (read-only), handy for asset inventory.

## Why use it

| Advantage | Description |
|---|---|
| **Zero dependency** | Python 3.8+ standard library; no daemon / database / external scanner; Windows + Linux + macOS |
| **Authorization discipline** | Only loopback is allowed by default; scope file or explicit declaration are the two authorization paths; in agent scenarios, no confirmation means denial |
| **Gentle & tunable** | Concurrency (--concurrency), timeout (--timeout) and rate limit (--rate) are adjustable to avoid scan storms |
| **Explainable fingerprints** | Product / version / risk level output item by item; risk hints match only, never exploit, and require human verification |
| **Flexible targets** | IP / CIDR / hostname / target file; custom ports or the built-in common-port table |
| **Ecosystem distribution** | GitHub + npm + ClawHub synced; install via npx / install.sh / manual copy |

## Commands

| Command | Description |
|---|---|
| scan | Port / service / version-fingerprint scan; text / JSON / Markdown output |
| fingerprint | Single-port deep fingerprint (service, version, risk, banner) |
| check-scope | Scope Guard authorization pre-check (the agent checks before scanning) |
| local | Local listening-port inventory (read-only) |
| list-ports | List the built-in common-port table |

## Quick start

Windows uses python, Linux/macOS uses python3.

```bash
# Scan local loopback (allowed by default, no authorization needed)
python3 scripts/yotta_recon.py scan --targets 127.0.0.1 --top 100

# With an authorization scope file (Scope Guard declared authorization)
python3 scripts/yotta_recon.py scan --targets 192.168.1.0/30 --scope scope.txt --yes

# The user explicitly declares authorization
python3 scripts/yotta_recon.py scan --targets <target> --assume-authorized --yes

# Single-port deep fingerprint
python3 scripts/yotta_recon.py fingerprint --host 127.0.0.1 --port 80

# Authorization pre-check (the agent checks before scanning)
python3 scripts/yotta_recon.py check-scope --targets <target> --scope scope.txt

# Local listening-port inventory (read-only)
python3 scripts/yotta_recon.py local

# JSON output / Markdown report
python3 scripts/yotta_recon.py scan --targets 127.0.0.1 --json
python3 scripts/yotta_recon.py scan --targets 127.0.0.1 --report report.md
```

## Install

Pick any one of the three methods; skill files are fetched from **npm** (GitHub is slower without a proxy; npm can use a domestic mirror).

### Method 1: npm (recommended, one-liner)
```bash
# domestic mirror (optional): npm config set registry https://registry.npmmirror.com
npx -y @yottameta/yotta-recon -g
npx -y @yottameta/yotta-recon --dir <your-skills-dir>   # any agent: install to a specific directory
```
> Not in the preset list? Use --dir to point at the agent's skills directory, or manual copy (method 3). --list shows each agent's default directory. You can also npm pack @yottameta/yotta-recon and unpack it to install via method 2 / 3.

### Method 2: install.sh one-shot
After obtaining the skill folder (npm pack unpack or git clone), enter the folder:
```bash
bash install.sh -g    # user level; bash install.sh --list shows all directories
bash install.sh --agent codex   # specific agent (--list shows available ones)
bash install.sh       # project level: auto-detect existing .claude/.cursor/.codex skills dirs
bash install.sh --dir /path/to/skills
```
> Covers 17 agent families including Trae / Qwen / Comate / CodeBuddy / Kimi. Windows users: works with Git Bash; otherwise use method 3.

### Method 3: manual copy
Copy the whole yotta-recon folder into the target agent's skills directory. Common locations (user level; Windows uses %USERPROFILE%, Linux/macOS uses ~):

| Agent | User-level directory | Project-level directory |
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
| Trae IDE (CN) | %USERPROFILE%\.trae-cn\skills\yotta-recon\ | .trae\skills\ |
| Qwen Code | %USERPROFILE%\.qwen\skills\yotta-recon\ | .qwen\skills\ |
| Comate | %USERPROFILE%\.comate\skills\yotta-recon\ | .comate\skills\ |
| CodeBuddy | %USERPROFILE%\.codebuddy\skills\yotta-recon\ | .codebuddy\skills\ |
| Kimi | %USERPROFILE%\.kimi\skills\yotta-recon\ | .kimi\skills\ |
| Generic AGENTS.md | %USERPROFILE%\.agents\skills\yotta-recon\ | .agents\skills\ |

> If Codex's CODEX_HOME is set, it overrides the default; the same applies to opencode's XDG_CONFIG_HOME. .agents\skills is not a universal directory — only OpenCode / Cursor / Cline / Amp / Kimi / Gemini CLI / GitHub Copilot etc. read it; **Claude Code and Codex do not read it by default**. When unsure, use --dir or let the agent install it.

## Upgrade / uninstall

- **Upgrade**: reinstall the latest version to overwrite — npx -y @yottameta/yotta-recon -g or rerun bash install.sh -g. Old files inside the skill folder are overwritten; other project files are untouched.
- **Uninstall**: delete the yotta-recon folder under the target agent's skills directory (see the table above). The skill stops taking effect after removal.

## FAQ

- **Does it actively attack targets?** No. Yuanxi only does read-only probing (TCP connect / banner read / protocol probe); it sends no attack payloads, writes nothing, deletes nothing and exploits nothing.
- **Is scanning other machines legal?** Recon is only performed on explicitly authorized targets. Scanning others' systems without authorization violates the Cybersecurity Law and Articles 285/286 of the Criminal Law; the user bears the legal responsibility.
- **Why deny non-loopback targets by default?** Recon is one of the highest-liability steps in security testing. Scope Guard makes "unauthorized denied by default" a hard mechanism: it requires a --scope authorization file or an explicit --assume-authorized --yes declaration.
- **Does a risk hint mean the target is really vulnerable?** No. Risk hints are version-fingerprint matches only; versions can be spoofed or already patched. The report says "please verify manually" — judge in context.
- **How is this different from nmap?** Yuanxi depends on no external tools and completes common recon with zero dependencies; nmap is more feature-complete but requires installation and privileges. For deeper scanning the two complement each other.

## Related skills

Part of the YottaMeta skill matrix (security family): [yotta-security-audit](https://github.com/YottaMeta/yotta-security-audit) (YuanAn, skill & system security audit) and [yotta-vetter](https://github.com/YottaMeta/yotta-vetter) (YuanShen, four-phase pre-install review) handle risk verification; [yotta-memory](https://github.com/YottaMeta/yotta-memory) (Yuanyi) handles cross-session long-term memory.

## Boundaries (security red lines)

- **Authorized targets only** — scan only targets with explicit authorization (scope file or explicit declaration); unauthorized targets are denied by default.
- **Read-only probing** — TCP connect / banner / protocol probes only; no active attacks, no exfiltration, no destruction, no exploitation.
- **No exploit details** — risk hints match known versions and ask for manual verification; they never include exploitation steps.

## Development & validation

- Run at the project root: python tools/validate-skill.py yotta-recon
- Tests: python scripts/test_yotta_recon.py (Windows: python)
- Details: references/protocol-probes.md, references/service-fingerprints.md, references/scope-guard.md

Keep tests green and bump the version before releasing changes.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## License

[MIT](./LICENSE) © YottaMeta. "Yuanxi" / "yotta-recon" and the YottaMeta family names (yotta-* prefix) are YottaMeta brand identifiers; derived works must not reuse them, see [NOTICE](./NOTICE). The network-recon direction references open-source network-scanner style skills; the implementation is YottaMeta's own zero-dependency rewrite.
