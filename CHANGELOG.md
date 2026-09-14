# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] — 2026-09-11

### Fixed
- **SSH drop-in shadowing (critical):** the managed drop-in moved from
  `sshd_config.d/99-hardening.conf` to `sshd_config.d/10-hardening.conf`.
  sshd uses the first value it encounters and processes drop-ins in lexical
  order, so on Ubuntu cloud images a `99-` file silently lost against vendor
  configs such as `50-cloud-init.conf` / `60-cloudimg-settings.conf`
  (`PasswordAuthentication yes`). `apply` now also verifies the *effective*
  configuration via `sshd -T` after `sshd -t` passes, and removes the legacy
  `99-` drop-in when it is ours.
- **Warning count accuracy:** the apply summary now counts *every* warning
  (previously only failed commands were counted, so the log could show 16
  `[WARN]` lines while the summary reported 9). Exit code 1 semantics unchanged.
- RHEL: account lockout is now wired the supported way via
  `authselect enable-feature with-faillock` before any direct PAM fallback.
- CI test images pre-install `openssh-server` + `libpam-pwquality`
  (Debian/Ubuntu) and `openssh-server` + `libpwquality` + `authselect` +
  `epel-release` (Rocky), so the matrix exercises the real sshd drop-in,
  `sshd -t` validation, effective-config checks and the authselect path.
- Test suite gains an "effective sshd config" stage (first-match-wins guard)
  and an `sshd -t` assertion.

## [1.0.0] — 2026-09-11

### Added
- Three run modes: `--audit` (read-only scored report), `--dry-run` (zero-change
  preview) and `--apply` (enforcement with automatic backups).
- Automatic distribution detection: Debian/Ubuntu family and RHEL/Rocky/Alma family.
- Automatic firewall backend detection: ufw (Debian) / firewalld (RHEL) /
  raw iptables fallback with rule persistence on RHEL.
- SSH hardening via a managed drop-in (`sshd_config.d/99-hardening.conf`) with
  `sshd -t` validation and automatic revert on failure.
- Smart SSH password-auth handling: key-only login only when `authorized_keys`
  exist (`DISABLE_PASSWORD_AUTH=auto`).
- Password policy: `login.defs` aging, `pwquality` complexity drop-in,
  `faillock` account lockout, retro-applied aging via `chage`.
- Kernel hardening through `/etc/sysctl.d/99-linux-hardening.conf` with
  docker-aware `ip_forward` handling.
- fail2ban SSH jail with systemd journal backend and bantime increment.
- Unattended security updates: `unattended-upgrades` (Debian) / `dnf-automatic` (RHEL).
- Per-check IDs inspired by CIS Benchmarks, with a scored audit summary.
- Concurrency lock, timestamped `/var/backups` and `/var/log` artifacts.
- Docker test suite covering Ubuntu 24.04, Debian 12 and Rocky Linux 9.
- GitHub Actions CI: shellcheck + bashate lint and the 3-distro test matrix.
