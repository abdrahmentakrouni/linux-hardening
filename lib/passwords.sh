#!/usr/bin/env bash
#===============================================================================
# lib/passwords.sh — password policy hardening
#
#   * /etc/login.defs        — aging policy (max/min days, warn age, min length)
#   * pwquality drop-in      — complexity requirements
#   * /etc/security/faillock — brute-force account lockout (deny=5, 15 min)
#   * chage                  — retro-applies aging to existing human users
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

PWQ_DROPIN="/etc/security/pwquality.conf.d/99-hardening.conf"
FAILLOCK_CONF="/etc/security/faillock.conf"

login_defs_get() {
  grep -E "^[[:space:]]*$1[[:space:]]" /etc/login.defs 2>/dev/null \
    | awk '{print $2; exit}' || true
}

pwquality_minlen() {
  local f val=""
  for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
    if [[ -f $f ]]; then
      val="$(grep -E '^[[:space:]]*minlen[[:space:]]*=' "$f" 2>/dev/null \
        | awk -F= '{gsub(/[[:space:]]/, "", $2); print $2; exit}' || true)"
      if [[ -n $val ]]; then printf '%s' "$val"; return 0; fi
    fi
  done
  printf '%s' "$val"
  return 0
}

pam_has_pwquality() {
  local pam_files=("/etc/pam.d/common-password" "/etc/pam.d/system-auth" "/etc/pam.d/password-auth" "/etc/pam.d/system-auth-ac")
  local f
  for f in "${pam_files[@]}"; do
    if [[ -f $f ]] && grep -q "pam_pwquality" "$f" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

pam_has_faillock() {
  local pam_files=("/etc/pam.d/common-auth" "/etc/pam.d/system-auth" "/etc/pam.d/password-auth" "/etc/pam.d/system-auth-ac")
  local f
  for f in "${pam_files[@]}"; do
    if [[ -f $f ]] && grep -q "pam_faillock" "$f" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

ensure_faillock_pam() {
  # Wire pam_faillock into PAM, Debian-first:
  #   1. drop a pam-configs profile + run pam-auth-update (the Debian way)
  #   2. VERIFY it actually landed — pam-auth-update can refuse silently
  #      ("local modifications", missing seen-db, ...)
  #   3. fallback: idempotent managed block appended to common-auth/account
  if pam_has_faillock; then
    return 0
  fi

  if [[ $DISTRO_FAMILY == debian && -d /usr/share/pam-configs ]]; then
    write_file /usr/share/pam-configs/hardening-faillock 644 "pam-configs faillock profile" "Name: Account lockout (faillock)
Default: yes
Priority: 256
Auth-Type: Primary
Auth:
  required pam_faillock.so preauth
  [default=die] pam_faillock.so authfail
Account-Type: Primary
Account:
  required pam_faillock.so"
    run_cmd "wiring faillock via pam-auth-update" pam-auth-update --package
  elif [[ $DISTRO_FAMILY == rhel ]] && command_exists authselect; then
    # RHEL 8+/Fedora: the supported way to enable pam_faillock
    run_cmd "enabling account lockout (authselect with-faillock)" authselect enable-feature with-faillock
    run_cmd "applying authselect changes" authselect apply-changes
  fi

  # verification step — pam-auth-update may exit 0 without doing anything
  if pam_has_faillock; then
    return 0
  fi

  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would append managed faillock block to /etc/pam.d/common-auth and common-account"
    return 0
  fi

  log_warn "pam-auth-update did not wire faillock — falling back to direct managed block"
  local ca="/etc/pam.d/common-auth" cac="/etc/pam.d/common-account"
  if [[ -f $ca ]] && ! grep -q "BEGIN linux-hardening faillock" "$ca"; then
    backup_file "$ca"
    sed -i '/^# here are the per-package modules/i # BEGIN linux-hardening faillock\nauth\trequired\tpam_faillock.so preauth\nauth\t[default=die]\tpam_faillock.so authfail\n# END linux-hardening faillock' "$ca"
    log_ok "appended managed faillock block to $ca"
  fi
  if [[ -f $cac ]] && ! grep -q "BEGIN linux-hardening faillock" "$cac"; then
    backup_file "$cac"
    sed -i '/^# here are the per-package modules/i # BEGIN linux-hardening faillock\naccount\trequired\tpam_faillock.so\n# END linux-hardening faillock' "$cac"
    log_ok "appended managed faillock block to $cac"
  fi
  pam_has_faillock
}

audit_passwords() {
  local v

  v="$(login_defs_get PASS_MAX_DAYS)"
  if [[ $v =~ ^[0-9]+$ ]] && (( v > 0 && v <= PASS_MAX_DAYS )); then
    check pass PW-01 "PASS_MAX_DAYS=$v (<= $PASS_MAX_DAYS)"
  else
    check fail PW-01 "PASS_MAX_DAYS=${v:-unset} (expected 1..$PASS_MAX_DAYS)"
  fi

  v="$(login_defs_get PASS_MIN_DAYS)"
  if [[ $v =~ ^[0-9]+$ ]] && (( v >= PASS_MIN_DAYS )); then
    check pass PW-02 "PASS_MIN_DAYS=$v (>= $PASS_MIN_DAYS)"
  else
    check fail PW-02 "PASS_MIN_DAYS=${v:-unset} (expected >= $PASS_MIN_DAYS)"
  fi

  v="$(login_defs_get PASS_WARN_AGE)"
  if [[ $v =~ ^[0-9]+$ ]] && (( v >= PASS_WARN_DAYS )); then
    check pass PW-03 "PASS_WARN_AGE=$v (>= $PASS_WARN_DAYS)"
  else
    check fail PW-03 "PASS_WARN_AGE=${v:-unset} (expected >= $PASS_WARN_DAYS)"
  fi

  v="$(pwquality_minlen)"
  if [[ $v =~ ^[0-9]+$ ]] && (( v >= PASS_MIN_LEN )); then
    check pass PW-04 "pwquality minlen=$v (>= $PASS_MIN_LEN)"
  else
    check fail PW-04 "pwquality minlen=${v:-unset} (expected >= $PASS_MIN_LEN)"
  fi

  if pam_has_pwquality; then
    check pass PW-05 "pam_pwquality is wired into PAM"
  else
    check fail PW-05 "pam_pwquality is NOT wired into PAM"
  fi

  if pam_has_faillock || [[ -s $FAILLOCK_CONF && $(grep -cE '^[[:space:]]*deny[[:space:]]*=' "$FAILLOCK_CONF" 2>/dev/null || true) -gt 0 ]]; then
    check pass PW-06 "account lockout (faillock) is configured"
  else
    check fail PW-06 "account lockout (faillock) is NOT configured"
  fi
}

apply_passwords() {
  # 1) aging policy for new passwords
  set_kv /etc/login.defs PASS_MAX_DAYS "$PASS_MAX_DAYS" "max password age"
  set_kv /etc/login.defs PASS_MIN_DAYS "$PASS_MIN_DAYS" "min password age"
  set_kv /etc/login.defs PASS_WARN_AGE "$PASS_WARN_DAYS" "expiry warning"
  set_kv /etc/login.defs PASS_MIN_LEN "$PASS_MIN_LEN" "min length (legacy hint)"

  # 2) password quality (complexity)
  if [[ $DISTRO_FAMILY == debian ]] && [[ ! -e /etc/security/pwquality.conf ]]; then
    pkg_refresh
    pkg_install libpam-pwquality
  elif [[ $DISTRO_FAMILY == rhel ]] && [[ ! -e /etc/security/pwquality.conf ]]; then
    pkg_refresh
    pkg_install libpwquality
  fi

  write_file "$PWQ_DROPIN" 644 "password complexity policy" "# Managed by linux-hardening v${VERSION}
minlen = ${PASS_MIN_LEN}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
dictcheck = 1
maxrepeat = 3"

  # 3) brute-force lockout
  write_file "$FAILLOCK_CONF" 644 "account lockout policy" "# Managed by linux-hardening v${VERSION}
deny = 5
unlock_time = 900"

  # 4) wire pam_faillock into PAM (Debian: pam-configs + verified fallback)
  ensure_faillock_pam

  # 5) retro-apply aging to existing human users (apply mode only)
  if [[ $RUN_MODE == apply ]]; then
    local u
    while IFS= read -r u; do
      if [[ -z $u ]]; then continue; fi
      run_cmd "enforcing password aging on user '$u'" \
        chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_DAYS" "$u"
    done < <(awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)
  fi
}
