#!/usr/bin/env bash
#===============================================================================
# lib/sysctl.sh — kernel hardening via /etc/sysctl.d drop-in
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

SYSCTL_FILE="/etc/sysctl.d/99-linux-hardening.conf"

# key=target pairs; both audit and apply consume this single source of truth
declare -a SYSCTL_SETTINGS=(
  "fs.protected_hardlinks=1"
  "fs.protected_symlinks=1"
  "fs.protected_regular=2"
  "fs.protected_fifos=2"
  "kernel.randomize_va_space=2"
  "kernel.kptr_restrict=1"
  "kernel.dmesg_restrict=1"
  "kernel.unprivileged_bpf_disabled=1"
  "kernel.yama.ptrace_scope=1"
  "kernel.panic=10"
  "net.ipv4.tcp_syncookies=1"
  "net.ipv4.conf.all.rp_filter=1"
  "net.ipv4.conf.default.rp_filter=1"
  "net.ipv4.conf.all.accept_source_route=0"
  "net.ipv4.conf.default.accept_source_route=0"
  "net.ipv4.conf.all.accept_redirects=0"
  "net.ipv4.conf.default.accept_redirects=0"
  "net.ipv4.conf.all.secure_redirects=0"
  "net.ipv4.conf.all.send_redirects=0"
  "net.ipv4.conf.default.send_redirects=0"
  "net.ipv4.conf.all.log_martians=1"
  "net.ipv4.conf.default.log_martians=1"
  "net.ipv4.icmp_echo_ignore_broadcasts=1"
  "net.ipv4.icmp_ignore_bogus_error_responses=1"
  "net.ipv6.conf.all.accept_redirects=0"
  "net.ipv6.conf.default.accept_redirects=0"
  "net.ipv6.conf.all.accept_source_route=0"
)

docker_in_use() {
  command_exists docker || [[ -S /var/run/docker.sock ]]
}

audit_sysctl() {
  local kv key target current idx=0 id
  for kv in "${SYSCTL_SETTINGS[@]}"; do
    idx=$((idx + 1))
    id="$(printf 'SYS-%02d' "$idx")"
    key="${kv%%=*}"
    target="${kv#*=}"
    current="$(sysctl -n "$key" 2>/dev/null || true)"
    if [[ -z $current ]]; then
      check warn "$id" "$key — cannot read (kernel/container restriction)"
      continue
    fi
    if [[ $current == "$target" ]]; then
      check pass "$id" "$key = $current"
    else
      check fail "$id" "$key = $current (expected $target)"
    fi
  done

  local fwd
  fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || true)"
  if [[ $fwd == 1 && $IP_FORWARD != true && ! $(docker_in_use && echo 1 || echo 0) == 1 ]]; then
    check warn "SYS-99" "net.ipv4.ip_forward=1 — fine for routers/docker hosts, otherwise disable it"
  fi
}

apply_sysctl() {
  local content kv
  content="# Managed by linux-hardening v${VERSION} — kernel hardening parameters"
  for kv in "${SYSCTL_SETTINGS[@]}"; do
    content+=$'\n'"${kv%%=*} = ${kv#*=}"
  done
  write_file "$SYSCTL_FILE" 644 "kernel hardening sysctls" "$content"

  # ip forwarding is intentionally opt-in: forcing 0 breaks docker/router hosts
  if [[ $IP_FORWARD == true ]]; then
    run_cmd "sysctl: enabling net.ipv4.ip_forward (requested)" sysctl -w net.ipv4.ip_forward=1
  elif docker_in_use; then
    log_info "docker detected — leaving net.ipv4.ip_forward untouched"
  else
    run_cmd "sysctl: disabling net.ipv4.ip_forward" sysctl -w net.ipv4.ip_forward=0
  fi

  if [[ $RUN_MODE == apply ]]; then
    local err
    if err="$(sysctl -p "$SYSCTL_FILE" 2>&1)"; then
      log_ok "kernel parameters applied live"
    else
      log_warn "some sysctl keys could not be applied (kernel/container limits) — ${err}"
      log_info "they will apply cleanly on the next reboot"
    fi
  fi
}
