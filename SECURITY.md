# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x: (use 1.1.x — it fixes an SSH drop-in shadowing bug) |
| < 1.0   | :x:                |

## Reporting a vulnerability

This repository contains **no runtime application** — it is a Bash script that
hardens Linux servers, plus CI configuration. That said, if you find a flaw
that could weaken a hardened server (e.g. a misconfiguration the script writes,
a lockout risk, a command-injection in an option parser), please report it
responsibly:

1. **Do not open a public issue** for exploitable problems.
2. Use GitHub's private vulnerability reporting
   (*Security → Report a vulnerability*), or contact the maintainer directly.
3. Include: affected version, distro, reproduction steps, expected vs actual.

You will get an answer within **72 hours**. Fixes land as a patch release, and
credit is given in the changelog unless you prefer to stay anonymous.

## Design notes relevant to security

- The script **never disables SSH password auth blindly**: with the default
  `DISABLE_PASSWORD_AUTH=auto`, key-only mode is enabled only when at least one
  user already has an `authorized_keys` file — preventing self-lockout.
- Every sshd change is validated with `sshd -t` **before** a reload and
  reverted automatically if invalid.
- Every modified file is backed up under `/var/backups/linux-hardening/<ts>/`
  with its full path preserved.
- `--dry-run` performs zero filesystem changes (enforced and tested in CI with
  an `/etc` md5 snapshot diff).
- The managed sshd drop-in is written to `sshd_config.d/10-hardening.conf`
  deliberately: sshd honours the first value it encounters, and vendor configs
  such as `50-cloud-init.conf` / `60-cloudimg-settings.conf` would otherwise
  shadow a higher-numbered drop-in.
