#!/usr/bin/env bash
#===============================================================================
# tests/run-tests.sh — runs INSIDE a container (root) and validates that the
# hardening script behaves correctly end-to-end:
#
#   1. syntax of every shell file
#   2. --help / --version
#   3. audit mode runs and exits with a documented code
#   4. dry-run performs ZERO filesystem changes
#   5. apply writes the expected config files
#   6. apply is idempotent (second run is safe)
#   7. post-apply audit still runs
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

set -u

cd /app || exit 1

PASS=0
FAIL=0
rc=0

# Containers have no authorized_keys; auto mode would keep password auth
# ON by design (anti-lockout). The suite verifies the key-only path.
CI_CONF=/app/ci-hardening.conf
printf 'DISABLE_PASSWORD_AUTH=true\n' > "$CI_CONF"

ok() { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$*"; }
no() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$*"; }

echo "======================================================================="
echo " linux-hardening test suite — $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
echo "======================================================================="

echo "== 1. syntax checks =="
for f in harden.sh lib/*.sh tests/run-tests.sh; do
  if bash -n "$f" 2>/tmp/synerr; then
    ok "bash -n $f"
  else
    no "bash -n $f — $(cat /tmp/synerr)"
  fi
done

echo "== 2. help & version =="
if ./harden.sh --help 2>&1 | grep -q "Usage"; then
  ok "--help prints usage"
else
  no "--help does not print usage"
fi
if ./harden.sh --version 2>&1 | grep -qE "[0-9]+\.[0-9]+"; then
  ok "--version prints version"
else
  no "--version does not print a version"
fi

echo "== 3. audit (before hardening) =="
./harden.sh --audit --no-color >/tmp/audit-before.log 2>&1
rc=$?
case $rc in
  0|1|2) ok "audit completed with a documented exit code (rc=$rc)" ;;
  *)     no "audit crashed (rc=$rc)"; tail -5 /tmp/audit-before.log ;;
esac
if grep -q "^Summary:" /tmp/audit-before.log; then
  ok "audit prints a scorecard summary"
  grep "^Summary:" /tmp/audit-before.log | sed 's/^/         /'
else
  no "audit summary missing"
fi

echo "== 4. dry-run changes nothing =="
find /etc -xdev -type f -exec md5sum {} + 2>/dev/null | sort > /tmp/etc-before
if ./harden.sh --dry-run --yes --no-color >/tmp/dry.log 2>&1; then
  ok "dry-run completed cleanly"
else
  no "dry-run exited non-zero"
  tail -5 /tmp/dry.log
fi
if grep -q "DRY-RUN" /tmp/dry.log; then
  ok "dry-run logged the actions it would take"
else
  no "dry-run did not log DRY-RUN actions"
fi
find /etc -xdev -type f -exec md5sum {} + 2>/dev/null | sort > /tmp/etc-after
if diff -q /tmp/etc-before /tmp/etc-after >/dev/null 2>&1; then
  ok "no file under /etc was modified during dry-run"
else
  no "FILES CHANGED DURING DRY-RUN:"
  diff /tmp/etc-before /tmp/etc-after | head -10 | sed 's/^/         /'
fi

echo "== 5. apply writes the expected configuration =="
./harden.sh --apply --yes --no-color -c "$CI_CONF" >/tmp/apply.log 2>&1
rc=$?
case $rc in
  0|1) ok "apply completed (rc=$rc — warnings tolerated in containers)" ;;
  *)   no "apply failed hard (rc=$rc)"; tail -20 /tmp/apply.log ;;
esac

if [[ -f /etc/sysctl.d/99-linux-hardening.conf ]]; then
  ok "sysctl drop-in created"
else
  no "sysctl drop-in NOT created"
fi
if [[ -f /etc/security/pwquality.conf.d/99-hardening.conf ]]; then
  ok "pwquality drop-in created"
else
  no "pwquality drop-in NOT created"
fi
if grep -Eq "^PASS_MAX_DAYS[[:space:]]+90" /etc/login.defs; then
  ok "login.defs PASS_MAX_DAYS hardened to 90"
else
  no "login.defs PASS_MAX_DAYS not set"
fi
if [[ -f /etc/security/faillock.conf ]]; then
  ok "faillock account-lockout policy written"
else
  no "faillock.conf NOT written"
fi
if [[ -f /etc/fail2ban/jail.d/99-hardening.local ]]; then
  ok "fail2ban jail drop-in created"
else
  no "fail2ban jail drop-in NOT created"
fi

if command -v sshd >/dev/null 2>&1 || [[ -x /usr/sbin/sshd ]]; then
  if [[ -f /etc/ssh/sshd_config.d/10-hardening.conf ]]; then
    ok "sshd hardening drop-in created"
    if grep -qi "^PermitRootLogin no" /etc/ssh/sshd_config.d/10-hardening.conf; then
      ok "PermitRootLogin=no enforced"
    else
      no "PermitRootLogin not set to no in drop-in"
    fi
    if sshd -t >/dev/null 2>&1; then
      ok "sshd -t validates the hardened configuration"
    else
      no "sshd -t rejects the hardened configuration"
    fi
  else
    no "sshd present but hardening drop-in missing"
  fi
else
  ok "openssh-server absent — ssh module correctly skipped with a warning"
fi

echo "== 6. effective sshd config really hardened (first-match-wins check) =="
if command -v sshd >/dev/null 2>&1 || [[ -x /usr/sbin/sshd ]]; then
  eff_pa="$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" {print $2; exit}')"
  eff_rl="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" {print $2; exit}')"
  if [[ $eff_pa == no ]]; then
    ok "effective PasswordAuthentication=no (drop-in not shadowed by vendor configs)"
  else
    no "effective PasswordAuthentication=${eff_pa:-?} — drop-in is being shadowed!"
  fi
  if [[ $eff_rl == no ]]; then
    ok "effective PermitRootLogin=no"
  else
    no "effective PermitRootLogin=${eff_rl:-?}"
  fi
else
  ok "openssh-server absent — effective-config check skipped"
fi

echo "== 7. idempotency (second apply is safe) =="
./harden.sh --apply --yes --no-color -c "$CI_CONF" >/tmp/apply2.log 2>&1
rc=$?
case $rc in
  0|1) ok "second apply completed (rc=$rc)" ;;
  *)   no "second apply failed (rc=$rc)"; tail -20 /tmp/apply2.log ;;
esac

echo "== 8. audit (after hardening) =="
./harden.sh --audit --no-color >/tmp/audit-after.log 2>&1
rc=$?
case $rc in
  0|1|2) ok "post-apply audit completed (rc=$rc)" ;;
  *)     no "post-apply audit crashed (rc=$rc)" ;;
esac
grep "^Summary:" /tmp/audit-after.log | sed 's/^/         /' || true

echo "======================================================================="
printf 'RESULTS: %d passed, %d failed\n' "$PASS" "$FAIL"
echo "======================================================================="
if [[ $FAIL -eq 0 ]]; then exit 0; else exit 1; fi
