#!/usr/bin/env bash
#===============================================================================
# lib/firewall.sh — firewall hardening (ufw / firewalld / iptables fallback)
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

normalize_ports() {
  # "80,443" or "80 443" -> "80 443" (space separated, deduplicated order kept)
  printf '%s' "$ALLOW_PORTS" | tr ',' ' ' | tr -s ' ' | sed 's/^ //; s/ $//'
}

audit_firewall() {
  case $FW_BACKEND in
    ufw)
      if ! command_exists ufw; then
        check fail FW-00 "ufw is not installed"
        return 0
      fi
      if ufw status 2>/dev/null | grep -q "Status: active"; then
        check pass FW-01 "ufw firewall is active"
      else
        check fail FW-01 "ufw is installed but NOT active"
      fi
      if ufw status verbose 2>/dev/null | grep -q "deny (incoming)"; then
        check pass FW-02 "default incoming policy is 'deny'"
      else
        check fail FW-02 "default incoming policy is NOT 'deny'"
      fi
      if ufw status 2>/dev/null | grep -Eq "^[[:space:]]*${SSH_PORT}/tcp[[:space:]]+ALLOW"; then
        check pass FW-03 "SSH (tcp/${SSH_PORT}) is allowed"
      else
        check fail FW-03 "SSH (tcp/${SSH_PORT}) is NOT allowed — lockout risk"
      fi
      ;;
    firewalld)
      if ! command_exists firewall-cmd; then
        check fail FW-00 "firewalld (firewall-cmd) is not installed"
        return 0
      fi
      if firewall-cmd --state 2>/dev/null | grep -q running; then
        check pass FW-01 "firewalld is running"
      else
        check fail FW-01 "firewalld is installed but NOT running"
      fi
      local zone
      zone="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
      case $zone in
        public|drop|block|workstation)
          check pass FW-02 "default zone is '$zone' (implicit deny)" ;;
        trusted)
          check fail FW-02 "default zone is 'trusted' (allow everything!)" ;;
        "")
          check warn FW-02 "could not query default zone" ;;
        *)
          check warn FW-02 "unexpected default zone '$zone' — review it" ;;
      esac
      if firewall-cmd --permanent --zone="${zone:-public}" --list-services 2>/dev/null | grep -qw ssh \
         || firewall-cmd --list-services 2>/dev/null | grep -qw ssh; then
        check pass FW-03 "ssh service is allowed"
      else
        check fail FW-03 "ssh service is NOT allowed — lockout risk"
      fi
      ;;
    iptables)
      if ! command_exists iptables; then
        check fail FW-00 "no firewall tooling found (ufw/firewalld/iptables)"
        return 0
      fi
      local policy
      policy="$(iptables -S INPUT 2>/dev/null | head -1 || true)"
      if [[ $policy == *"-P INPUT DROP"* ]]; then
        check pass FW-02 "INPUT policy is DROP"
      else
        check fail FW-02 "INPUT policy is not DROP (${policy:-unknown})"
      fi
      if iptables -S INPUT 2>/dev/null | grep -q -- "--dport ${SSH_PORT}\b"; then
        check pass FW-03 "SSH (tcp/${SSH_PORT}) is allowed"
      else
        check fail FW-03 "SSH (tcp/${SSH_PORT}) is NOT allowed — lockout risk"
      fi
      check warn FW-01 "raw iptables in use — ufw or firewalld is recommended"
      ;;
    *)
      check fail FW-00 "no firewall tooling found (ufw/firewalld/iptables)"
      ;;
  esac
}

apply_firewall() {
  local ports p
  ports="$(normalize_ports)"

  case $FW_BACKEND in
    ufw)
      if ! command_exists ufw; then
        pkg_refresh
        pkg_install ufw
      fi
      run_cmd "ufw: default deny incoming"            ufw default deny incoming
      run_cmd "ufw: default allow outgoing"           ufw default allow outgoing
      run_cmd "ufw: allow SSH tcp/${SSH_PORT}"        ufw allow "${SSH_PORT}/tcp"
      for p in $ports; do
        run_cmd "ufw: allow tcp/${p}"                 ufw allow "${p}/tcp"
      done
      if [[ $FIREWALL_IPV6 != true ]]; then
        set_kv_eq /etc/default/ufw IPV6 no "disable ufw IPv6 rules"
      fi
      run_cmd "ufw: enable firewall"                  ufw --force enable
      ;;
    firewalld)
      if ! command_exists firewall-cmd; then
        pkg_refresh
        pkg_install firewalld
      fi
      svc enable --now firewalld
      run_cmd "firewalld: ensure ssh service is allowed"    firewall-cmd --permanent --add-service=ssh
      for p in $ports; do
        run_cmd "firewalld: allow port ${p}/tcp"            firewall-cmd --permanent --add-port="${p}/tcp"
      done
      run_cmd "firewalld: reload permanent rules"           firewall-cmd --reload
      ;;
    iptables)
      if ! command_exists iptables; then
        pkg_refresh
        pkg_install iptables
      fi
      ipt_add_rule() {
        if [[ $RUN_MODE == dry-run ]]; then
          log_dry "iptables: $*"
          return 0
        fi
        if iptables -C "$@" 2>/dev/null; then
          log_ok "iptables rule already present: $*"
          return 0
        fi
        run_cmd "iptables: add rule $*" iptables -A "$@"
      }
      ipt_add_rule INPUT -i lo -j ACCEPT
      ipt_add_rule INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      ipt_add_rule INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
      for p in $ports; do
        ipt_add_rule INPUT -p tcp --dport "$p" -j ACCEPT
      done
      run_cmd "iptables: set INPUT policy to DROP" iptables -P INPUT DROP

      # persistence so rules survive a reboot
      if [[ $DISTRO_FAMILY == rhel ]]; then
        pkg_install iptables-services
        run_cmd "persisting iptables rules" bash -c 'iptables-save > /etc/sysconfig/iptables'
        svc enable iptables
      else
        log_warn "install 'iptables-persistent' (or switch to ufw) to keep rules across reboots"
      fi
      ;;
    *)
      log_warn "no firewall backend available — firewall module skipped"
      ;;
  esac
}
