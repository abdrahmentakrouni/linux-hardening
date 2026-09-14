#!/usr/bin/env bash
#===============================================================================
# lib/fail2ban.sh — brute-force protection with fail2ban
#
# Uses a managed jail drop-in (/etc/fail2ban/jail.d/99-hardening.local) with
# the systemd journal backend, which works out of the box on Debian 12 and
# RHEL 9 where /var/log/auth.log / authpriv syslog may not exist.
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

F2B_LOCAL="/etc/fail2ban/jail.d/99-hardening.local"

audit_fail2ban() {
  if ! command_exists fail2ban-client; then
    check fail F2B-01 "fail2ban is not installed"
    return 0
  fi

  if fail2ban-client ping >/dev/null 2>&1; then
    check pass F2B-01 "fail2ban daemon is running"
    if fail2ban-client status sshd >/dev/null 2>&1; then
      check pass F2B-02 "sshd jail is active"
    else
      check fail F2B-02 "sshd jail is NOT active"
    fi
  else
    check fail F2B-01 "fail2ban is installed but the daemon is NOT running"
    check warn F2B-02 "cannot verify sshd jail (daemon down)"
  fi

  if [[ -f $F2B_LOCAL ]]; then
    check pass F2B-03 "hardening jail config present ($F2B_LOCAL)"
  else
    check warn F2B-03 "no managed jail config found (apply writes one)"
  fi
}

apply_fail2ban() {
  if [[ $DISTRO_FAMILY == rhel ]]; then
    if ! rpm -q epel-release >/dev/null 2>&1; then
      pkg_refresh
      pkg_install epel-release
      if ! rpm -q epel-release >/dev/null 2>&1; then
        log_warn "could not enable EPEL automatically — install it manually, then re-run --apply"
      fi
    fi
  fi

  if ! command_exists fail2ban-client; then
    pkg_refresh
    if [[ $DISTRO_FAMILY == debian ]]; then
      pkg_install fail2ban python3-systemd
    else
      pkg_install fail2ban
    fi
  fi

  write_file "$F2B_LOCAL" 644 "fail2ban hardening jail" "# Managed by linux-hardening v${VERSION}
[DEFAULT]
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = ${FAIL2BAN_MAXRETRY}
findtime = ${FAIL2BAN_FINDTIME}
bantime = ${FAIL2BAN_BANTIME}
bantime.increment = true"

  svc enable --now fail2ban

  if [[ $RUN_MODE == apply ]] && command_exists fail2ban-client; then
    run_cmd "reloading fail2ban jails" fail2ban-client reload
  fi
}
