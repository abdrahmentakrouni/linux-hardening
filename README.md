# linux-hardening

[![CI](https://github.com/abderrahmen-takrouni/linux-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/abderrahmen-takrouni/linux-hardening/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/shellcheck-passed-brightgreen.svg)](.github/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20RHEL%20%7C%20Rocky%20%7C%20Alma-informational)](#requirements)

**One-shot, idempotent hardening for fresh Linux servers.** Point it at a new
VPS or cloud instance and it closes dangerous ports, configures a firewall,
enforces a strong password policy, hardens SSH, installs brute-force
protection and enables automatic security updates — with a read-only audit
mode, a zero-change dry-run, and full backups before any modification.

> **TL;DR بالتونسي:** سكريبت Bash واحد يحمّي السيرفر الجديد أوتوماتيكياً: يسكّر
> البورتات الخطيرة، يفعّل جدار الحماية، يفرض كلمات سر قوية، يصلّد SSH، يركّب
> fail2ban ويشغّل التحديثات الأمنية الأوتوماتيكية. تجربو بـ `--audit` (قراءة فقط)
> و `--dry-run` (بلا تعديل) قبل ما تعملو `--apply`. كل ملف يتبدّل يعمللو backup
> أوتوماتيكياً.

---

## Why

Companies run thousands of servers on the cloud. Hardening one by hand —
port by port, file by file — wastes hours and invites human error, and the
servers that get forgotten are the ones that get breached. This script turns
that repetitive runbook into a single, reviewable, repeatable command that
produces the same hardened baseline on every machine.

## Demo

```text
$ sudo ./harden.sh --audit
linux-hardening v1.1.0 — automated server hardening
------------------------------------------------------------------------
[INFO] mode      : audit
[INFO] distro    : Ubuntu 24.04 LTS (debian family, pkg=apt)
[INFO] firewall  : ufw
[INFO] modules   : firewall, ssh, passwords, sysctl, fail2ban, autoupdates
[INFO] ssh port  : 22
[INFO] log file  : /var/log/linux-hardening/audit-20260911-120000.log
------------------------------------------------------------------------

---- [ module: firewall ] ----
  ✔ PASS  FW-01   ufw firewall is active
  ✔ PASS  FW-02   default incoming policy is 'deny'
  ✘ FAIL  FW-03   SSH (tcp/22) is NOT allowed — lockout risk

---- [ module: ssh ] ----
  ✔ PASS  SSH-01  PermitRootLogin=no
  ✘ FAIL  SSH-02  PasswordAuthentication=yes (target: no)
  ✔ PASS  SSH-03  PubkeyAuthentication=yes

...

------------------------------------------------------------------------
Summary: 14 passed, 3 warnings, 6 failed — score 61%
[ERROR] HARDENING REQUIRED — 6 check(s) failed (exit code 2)
```

## What it hardens

| Module         | What it does                                                                 | Key files touched |
|----------------|------------------------------------------------------------------------------|-------------------|
| `firewall`     | Default-deny inbound, allow SSH + chosen ports. Auto-picks **ufw** (Debian) / **firewalld** (RHEL) / raw **iptables** fallback | `/etc/default/ufw`, firewalld runtime config |
| `ssh`          | `PermitRootLogin no`, key-only auth (smart auto-detect), hardened timeouts, `sshd -t` validation with auto-revert | `/etc/ssh/sshd_config.d/10-hardening.conf` |
| `passwords`    | Aging policy, complexity rules, brute-force account lockout, retro-applies aging to existing users | `/etc/login.defs`, `/etc/security/pwquality.conf.d/`, `/etc/security/faillock.conf` |
| `sysctl`       | 27 kernel parameters: ASLR, ptrace/BPF restrictions, anti-spoofing, redirect & source-route protection | `/etc/sysctl.d/99-linux-hardening.conf` |
| `fail2ban`     | SSH jail (5 tries → 1h ban, escalating), systemd journal backend, EPEL bootstrap on RHEL | `/etc/fail2ban/jail.d/99-hardening.local` |
| `autoupdates`  | Daily unattended security upgrades: `unattended-upgrades` (Debian) / `dnf-automatic` (RHEL) | `/etc/apt/apt.conf.d/20auto-upgrades`, `/etc/dnf/automatic.conf` |

Every check in audit mode has a stable ID (`FW-01`, `SSH-02`, `SYS-04`, …)
inspired by the CIS Benchmarks, so audit results are greppable and comparable
across servers.

## Quick start

```bash
git clone https://github.com/abderrahmen-takrouni/linux-hardening.git
cd linux-hardening

# 1. See the current security posture (read-only, changes nothing)
sudo ./harden.sh --audit

# 2. Preview every change it would make (still changes nothing)
sudo ./harden.sh --dry-run

# 3. Enforce the hardening (backs up every file it touches)
sudo ./harden.sh --apply

# 4. Verify
sudo ./harden.sh --audit
```

Always run `--dry-run` first on production machines. Keep your current SSH
session open while applying until a new connection is confirmed working.

## Run modes & exit codes

| Mode        | Changes files | Use case                                  | Exit codes |
|-------------|---------------|-------------------------------------------|------------|
| `--audit`   | No            | Scored report, CI gate, compliance checks | 0 = clean, 1 = warnings, 2 = failures |
| `--dry-run` | No            | Review the exact change plan beforehand   | 0 = plan built, 1 = warnings |
| `--apply`   | Yes (backed up) | Enforce hardening                       | 0 = clean, 1 = completed with warnings |

## CLI options

| Flag                  | Description                                    | Default |
|-----------------------|------------------------------------------------|---------|
| `-y, --yes`           | Never prompt (CI / automation)                 | prompt on apply |
| `-c, --config FILE`   | Extra config file (loaded last)                | — |
| `--port N`            | SSH port to protect                            | `22` |
| `--allow-ports LIST`  | Extra TCP ports to keep open                   | `80,443` |
| `--only a,b`          | Run only these modules                         | all |
| `--skip a,b`          | Skip these modules                             | — |
| `--no-color`          | Plain output (for logs/CI)                     | auto |
| `--log FILE`          | Custom log file                                | `/var/log/linux-hardening/` |

Examples:

```bash
sudo ./harden.sh --apply --yes --port 2222 --allow-ports "80,443,8443"
sudo ./harden.sh --apply --only ssh,firewall          # just the network basics
sudo ./harden.sh --audit --skip fail2ban,autoupdates  # audit everything else
```

## Configuration

Defaults live in the script; override them via config files or CLI flags.
Load order (later wins): built-in defaults → `config/harden.conf` →
`/etc/linux-hardening/harden.conf` → `--config FILE` → CLI flags.
See [`config/harden.conf`](config/harden.conf) for the fully documented list.

Notable smart behaviors:

- **`DISABLE_PASSWORD_AUTH=auto`** (default) switches SSH to key-only *only if*
  at least one user already has `~/.ssh/authorized_keys` — otherwise it keeps
  password auth and warns, so you never lock yourself out of a fresh box.
- **Docker-aware `ip_forward`**: the script never disables IP forwarding on
  hosts running Docker, and `IP_FORWARD=true` opts in explicitly for routers.

## Safety design

- **Backups**: every modified file is copied under
  `/var/backups/linux-hardening/<timestamp>/` preserving its full path.
- **Dry-run by design**: `--dry-run` goes through the *same* code path as
  `--apply`, with all write helpers stubbed — the preview cannot drift from
  reality.
- **Validated SSH changes**: the generated sshd config is checked with
  `sshd -t` *before* any reload; on failure the change is reverted
  automatically.
- **Idempotent**: run `--apply` ten times, the result is the same.
- **Concurrency lock**: an `flock` guard prevents two applies racing.
- **Container-tolerant**: missing systemd or missing tools degrade to
  warnings instead of crashing.
- **Full logging**: every run writes a timestamped log to
  `/var/log/linux-hardening/`.

## Requirements

- Bash ≥ 4.4 (any current Ubuntu/Debian/RHEL/Rocky/Alma)
- Run as root (`sudo`)
- systemd recommended (services/timers degrade gracefully without it)
- Supported families: Debian/Ubuntu and RHEL/Rocky/Alma/Fedora (auto-detected)

## Testing & CI

The repo ships a Docker test suite that runs the script end-to-end inside
real distro containers and asserts: syntax validity, `--help/--version`,
audit behavior, that **dry-run changes zero files under `/etc`**, that apply
writes the expected drop-ins, idempotency, and a clean post-apply audit.

```bash
make test      # ubuntu 24.04 + debian 12 + rocky 9
make test-ubuntu
make lint      # shellcheck
```

GitHub Actions runs shellcheck + bashate and the full 3-distro test matrix on
every push and pull request (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Roadmap

- [ ] CIS benchmark mapping table in the wiki
- [ ] HTML/PDF audit report export
- [ ] Remote fleet mode (apply over SSH to an inventory list)
- [ ] Lynis integration for deeper scanning

## Contributing

Issues and PRs are welcome. Please run `make lint` and `make test-ubuntu`
before opening a pull request.

## Author

**Abderrahmen Takrouni** — built as a portfolio project to demonstrate
production-grade Linux automation: safe defaults, idempotent execution,
auditability and CI-verified correctness.

## License

[MIT](LICENSE) — free to use, modify and ship.
