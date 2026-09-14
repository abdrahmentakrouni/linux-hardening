#!/usr/bin/env bash
#===============================================================================
# lib/audit.sh — check/report primitives used by the audit_* module functions
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

check() {
  # check <pass|warn|fail> <ID> <message>
  # Prints a single scored line and updates the global counters.
  local level="$1" id="$2" msg="$3"
  local symbol="" plain="" col=""

  case $level in
    pass) symbol="✔"; plain="PASS"; col=$C_GREEN;  PASS_COUNT=$((PASS_COUNT + 1)) ;;
    warn) symbol="⚠"; plain="WARN"; col=$C_YELLOW; WARN_COUNT=$((WARN_COUNT + 1)) ;;
    fail) symbol="✘"; plain="FAIL"; col=$C_RED;    FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    *)    die "internal error: unknown check level '$level'" ;;
  esac

  if [[ $COLOR == true ]]; then
    printf '  %s%s %s%s %-7s %s\n' "$col" "$symbol" "$C_RESET" "$plain" "$id" "$msg"
  else
    printf '  %s %-7s %s\n' "$plain" "$id" "$msg"
  fi
  if [[ -n $LOG_FILE ]]; then
    printf '  %s %-7s %s\n' "$plain" "$id" "$msg" >> "$LOG_FILE" || true
  fi
}

audit_summary() {
  # Prints the audit scorecard and exits with the documented exit code:
  #   0 = all checks passed, 1 = warnings only, 2 = at least one failure
  local total score=0
  total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
  if [[ $total -gt 0 ]]; then
    score=$((100 * PASS_COUNT / total))
  fi

  printf '\n'
  hr
  if [[ $COLOR == true ]]; then
    printf 'Summary: %s%d passed%s, %d warnings, %d failed — score %d%%\n' \
      "$C_BOLD" "$PASS_COUNT" "$C_RESET" "$WARN_COUNT" "$FAIL_COUNT" "$score"
  else
    printf 'Summary: %d passed, %d warnings, %d failed — score %d%%\n' \
      "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT" "$score"
  fi
  if [[ -n $LOG_FILE ]]; then
    printf 'Summary: %d passed, %d warnings, %d failed — score %d%%\n' \
      "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT" "$score" >> "$LOG_FILE" || true
  fi
  hr

  if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "HARDENING REQUIRED — $FAIL_COUNT check(s) failed (exit code 2)"
    log_info  "run 'sudo bash harden.sh --dry-run' to preview the changes"
    exit 2
  elif [[ $WARN_COUNT -gt 0 ]]; then
    log_warn "REVIEW RECOMMENDED — $WARN_COUNT warning(s) (exit code 1)"
    exit 1
  else
    log_ok "ALL CHECKS PASSED — system looks hardened (exit code 0)"
    exit 0
  fi
}
