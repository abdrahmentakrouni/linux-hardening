#!/usr/bin/env bash
#===============================================================================
# lib/autoupdates.sh — unattended automatic security updates
#
#   Debian family : unattended-upgrades + 20auto-upgrades + systemd timers
#   RHEL family   : dnf-automatic with apply_updates=yes + systemd timer
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

check_timer() {
  # check_timer <unit> <check-id>
  local unit="$1" id="$2"
  if [[ ! -d /run/systemd/system ]]; then
    check warn "$id" "systemd is not running — cannot verify timer $unit"
    return 0
  fi
  if systemctl is-enabled "$unit" >/dev/null 2>&1 && systemctl is-active "$unit" >/dev/null 2>&1; then
    check pass "$id" "timer $unit is enabled and active"
  elif systemctl is-enabled "$unit" >/dev/null 2>&1; then
    check warn "$id" "timer $unit is enabled but not active"
  else
    check fail "$id" "timer $unit is NOT enabled"
  fi
}

audit_autoupdates() {
  if [[ $DISTRO_FAMILY == debian ]]; then
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
      check pass UPD-01 "unattended-upgrades is installed"
    else
      check fail UPD-01 "unattended-upgrades is NOT installed"
    fi
    if [[ -r /etc/apt/apt.conf.d/20auto-upgrades ]] \
       && grep -q 'Unattended-Upgrade[[:space:]]*"1"' /etc/apt/apt.conf.d/20auto-upgrades; then
      check pass UPD-02 "daily automatic upgrades are enabled (20auto-upgrades)"
    else
      check fail UPD-02 "20auto-upgrades is NOT configured for daily updates"
    fi
    check_timer apt-daily-upgrade.timer UPD-03
  else
    if rpm -q dnf-automatic >/dev/null 2>&1; then
      check pass UPD-01 "dnf-automatic is installed"
    else
      check fail UPD-01 "dnf-automatic is NOT installed"
    fi
    if [[ -r /etc/dnf/automatic.conf ]] \
       && grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes' /etc/dnf/automatic.conf; then
      check pass UPD-02 "apply_updates=yes (automatic.conf)"
    else
      check fail UPD-02 "apply_updates is NOT enabled in automatic.conf"
    fi
    check_timer dnf-automatic.timer UPD-03
  fi
}

apply_autoupdates() {
  if [[ $AUTO_UPDATES != true ]]; then
    log_info "AUTO_UPDATES=false — skipping automatic updates setup"
    return 0
  fi

  if [[ $DISTRO_FAMILY == debian ]]; then
    if ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
      pkg_refresh
      pkg_install unattended-upgrades
    fi
    write_file /etc/apt/apt.conf.d/20auto-upgrades 644 "enable daily unattended upgrades" "# Managed by linux-hardening v${VERSION} — do not edit
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";"
    svc enable apt-daily.timer
    svc enable apt-daily-upgrade.timer
  else
    if ! rpm -q dnf-automatic >/dev/null 2>&1; then
      pkg_refresh
      pkg_install dnf-automatic
    fi
    if [[ -f /etc/dnf/automatic.conf ]]; then
      set_kv_eq /etc/dnf/automatic.conf apply_updates yes "install updates automatically"
      set_kv_eq /etc/dnf/automatic.conf download_updates yes "download updates automatically"
    else
      log_warn "/etc/dnf/automatic.conf not found — cannot configure dnf-automatic"
    fi
    svc enable --now dnf-automatic.timer
  fi
}
