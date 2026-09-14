#!/usr/bin/env bash
#===============================================================================
# lib/ssh.sh — OpenSSH server hardening
#
# Writes a managed drop-in into /etc/ssh/sshd_config.d/ (Debian 10+, RHEL 8+)
# or falls back to editing sshd_config directly on older systems.
# Every change is validated with `sshd -t` BEFORE any restart, and reverted
# automatically if the resulting configuration is invalid.
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

SSHD_MAIN="/etc/ssh/sshd_config"
# First-match-wins: sshd uses the FIRST value it sees, and drop-ins are
# processed in lexical order. Ubuntu cloud images ship 50-cloud-init.conf and
# 60-cloudimg-settings.conf with 'PasswordAuthentication yes' — a 99- drop-in
# would come AFTER them and silently lose. A low number wins instead.
SSHD_DROPIN="/etc/ssh/sshd_config.d/10-hardening.conf"
SSHD_LEGACY_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"

sshd_available() {
  command_exists sshd || [[ -x /usr/sbin/sshd ]]
}

sshd_include_support() {
  grep -Eq '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$SSHD_MAIN" 2>/dev/null
}

compute_ssh_targets() {
  # Computes effective targets shared by audit + apply:
  #   RL_TARGET — PermitRootLogin value
  #   PA_TARGET — PasswordAuthentication value
  #   SSH_KEY_PRESENT — whether at least one user has authorized_keys
  RL_TARGET="prohibit-password"
  PA_TARGET="yes"
  SSH_KEY_PRESENT=false

  if [[ $DISABLE_ROOT_SSH == true ]]; then
    RL_TARGET="no"
  fi

  local home_dir ak
  local homes=("/root")
  while IFS= read -r home_dir; do
    if [[ -n $home_dir ]]; then homes+=("$home_dir"); fi
  done < <(awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $6}' /etc/passwd 2>/dev/null || true)

  for home_dir in "${homes[@]}"; do
    ak="${home_dir}/.ssh/authorized_keys"
    if [[ -s $ak ]]; then
      SSH_KEY_PRESENT=true
      break
    fi
  done

  case $DISABLE_PASSWORD_AUTH in
    true)
      PA_TARGET="no"
      ;;
    false)
      PA_TARGET="yes"
      ;;
    auto)
      if [[ $SSH_KEY_PRESENT == true ]]; then
        PA_TARGET="no"
      else
        PA_TARGET="yes"
        log_warn "no authorized_keys found — keeping SSH password auth ON (set DISABLE_PASSWORD_AUTH=true to force key-only)"
      fi
      ;;
  esac
}

ssh_dropin_content() {
  cat <<EOF
# Managed by linux-hardening v${VERSION} — local edits are overwritten on --apply
PermitRootLogin ${RL_TARGET}
PasswordAuthentication ${PA_TARGET}
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
UseDNS no
EOF
}

revert_ssh() {
  if sshd_include_support; then
    rm -f "$SSHD_DROPIN"
  else
    if [[ -f "${BACKUP_DIR}${SSHD_MAIN}" ]]; then
      cp "${BACKUP_DIR}${SSHD_MAIN}" "$SSHD_MAIN" || true
    fi
  fi
}

audit_ssh() {
  if ! sshd_available; then
    check warn SSH-00 "openssh-server is not installed — skipping ssh checks"
    return 0
  fi

  compute_ssh_targets
  SSHD_T="$(sshd -T 2>/dev/null || true)"

  sshd_eff_get() {
    local key="$1" val=""
    if [[ -n $SSHD_T ]]; then
      val="$(awk -v k="$key" '$1==k{print $2; exit}' <<<"$SSHD_T")"
    else
      if [[ -f $SSHD_DROPIN ]]; then
        val="$(grep -Ei "^[[:space:]]*${key}[[:space:]]" "$SSHD_DROPIN" 2>/dev/null | awk '{print $2; exit}' || true)"
      fi
      if [[ -z $val && -f $SSHD_MAIN ]]; then
        val="$(grep -Ei "^[[:space:]]*${key}[[:space:]]" "$SSHD_MAIN" 2>/dev/null | awk '{print $2; exit}' || true)"
      fi
    fi
    printf '%s' "$val"
    return 0
  }

  local v
  v="$(sshd_eff_get permitrootlogin)"
  case $v in
    "$RL_TARGET") check pass SSH-01 "PermitRootLogin=$v" ;;
    prohibit-password) check warn SSH-01 "PermitRootLogin=$v (target: $RL_TARGET)" ;;
    "") check warn SSH-01 "PermitRootLogin not found (default: prohibit-password)" ;;
    *) check fail SSH-01 "PermitRootLogin=$v (target: $RL_TARGET)" ;;
  esac

  v="$(sshd_eff_get passwordauthentication)"
  if [[ $v == "$PA_TARGET" ]]; then
    check pass SSH-02 "PasswordAuthentication=$v"
  else
    check fail SSH-02 "PasswordAuthentication=${v:-unknown} (target: $PA_TARGET)"
  fi

  v="$(sshd_eff_get pubkeyauthentication)"
  if [[ $v == yes ]]; then
    check pass SSH-03 "PubkeyAuthentication=yes"
  else
    check fail SSH-03 "PubkeyAuthentication=${v:-unknown} (expected yes)"
  fi

  v="$(sshd_eff_get maxauthtries)"
  if [[ $v =~ ^[0-9]+$ ]] && (( v <= 4 )); then
    check pass SSH-04 "MaxAuthTries=$v (<= 4)"
  else
    check fail SSH-04 "MaxAuthTries=${v:-unknown} (expected <= 4)"
  fi

  v="$(sshd_eff_get logingracetime)"
  if [[ $v =~ ^[0-9]+$ ]] && (( v <= 60 )); then
    check pass SSH-05 "LoginGraceTime=$v (<= 60)"
  else
    check fail SSH-05 "LoginGraceTime=${v:-unknown} (expected <= 60)"
  fi

  v="$(sshd_eff_get x11forwarding)"
  if [[ $v == no ]]; then
    check pass SSH-06 "X11Forwarding=no"
  else
    check fail SSH-06 "X11Forwarding=${v:-unknown} (expected no)"
  fi

  v="$(sshd_eff_get allowtcpforwarding)"
  if [[ $v == no ]]; then
    check pass SSH-07 "AllowTcpForwarding=no"
  else
    check warn SSH-07 "AllowTcpForwarding=${v:-unknown} (expected no; may be needed for tunnels)"
  fi

  v="$(sshd_eff_get permitemptypasswords)"
  if [[ $v == no ]]; then
    check pass SSH-08 "PermitEmptyPasswords=no"
  else
    check fail SSH-08 "PermitEmptyPasswords=${v:-unknown} (expected no)"
  fi

  if [[ -f $SSHD_DROPIN ]]; then
    check pass SSH-09 "managed drop-in present ($SSHD_DROPIN)"
  else
    check warn SSH-09 "no managed drop-in found (apply writes one)"
  fi
}

apply_ssh() {
  if ! sshd_available; then
    log_warn "openssh-server is not installed — ssh module skipped (install openssh-server first)"
    return 0
  fi

  compute_ssh_targets
  local content
  content="$(ssh_dropin_content)"

  # v1.0.x wrote 99-hardening.conf, which can be shadowed by earlier-numbered
  # vendor drop-ins (50-cloud-init.conf, 60-cloudimg-settings.conf). Remove our
  # legacy file so the new 10- drop-in is the single source of truth.
  if [[ -f $SSHD_LEGACY_DROPIN ]] \
     && grep -q "Managed by linux-hardening" "$SSHD_LEGACY_DROPIN" 2>/dev/null; then
    if [[ $RUN_MODE == apply ]]; then
      rm -f "$SSHD_LEGACY_DROPIN"
      log_info "removed legacy drop-in $SSHD_LEGACY_DROPIN (superseded by $SSHD_DROPIN)"
    else
      log_dry "would remove legacy drop-in $SSHD_LEGACY_DROPIN"
    fi
  fi

  if sshd_include_support; then
    write_file "$SSHD_DROPIN" 600 "sshd hardening drop-in" "$content"
  else
    log_info "no sshd_config.d include support — applying directives to $SSHD_MAIN directly"
    local key value
    while read -r key value; do
      if [[ -z $key || $key == \#* ]]; then continue; fi
      set_kv "$SSHD_MAIN" "$key" "$value" "ssh hardening"
    done <<<"$content"
  fi

  if [[ $RUN_MODE == apply ]]; then
    # host keys are required for sshd -t on fresh systems
    if ! ls /etc/ssh/ssh_host_* >/dev/null 2>&1; then
      run_cmd "generating missing SSH host keys" ssh-keygen -A
    fi

    # Debian/Ubuntu containers miss /run/sshd; without it sshd -t fails
    # and the auto-revert would discard the SSH hardening.
    if [[ ! -d /run/sshd && ! -d /var/empty/sshd ]]; then
      run_cmd "creating sshd privilege-separation directory (/run/sshd)" mkdir -p /run/sshd
    fi
    
    local err
    if err="$(sshd -t 2>&1)"; then
      log_ok "sshd configuration validated (sshd -t)"
    else
      log_error "sshd -t FAILED: ${err:-unknown} — reverting ssh changes"
      revert_ssh
      if err="$(sshd -t 2>&1)"; then
        log_ok "reverted — sshd configuration is valid again"
      else
        log_error "sshd configuration STILL invalid after revert: $err — manual fix required!"
      fi
      return 1
    fi

    # verify the EFFECTIVE configuration, not just the syntax: sshd uses the
    # first value it encounters, so an earlier-numbered drop-in could override
    # ours (e.g. vendor cloud-init configs).
    local eff_rl eff_pa
    eff_rl="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" {print $2; exit}' || true)"
    eff_pa="$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" {print $2; exit}' || true)"
    if [[ $eff_rl == "$RL_TARGET" && $eff_pa == "$PA_TARGET" ]]; then
      log_ok "effective config verified (PermitRootLogin=$eff_rl, PasswordAuthentication=$eff_pa)"
    else
      log_warn "effective sshd config differs from targets (PermitRootLogin=${eff_rl:-?}, PasswordAuthentication=${eff_pa:-?}) — check for conflicting files in sshd_config.d/"
    fi

    try_reload_service ssh sshd
    log_warn "keep your current SSH session open and test a NEW connection before logging out"
  fi
  return 0
}
