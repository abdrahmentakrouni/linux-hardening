#!/usr/bin/env bash
#===============================================================================
#  linux-hardening — automated Linux server hardening
#
#  Hardens fresh Ubuntu/Debian and RHEL/Rocky/Alma servers in one shot:
#    * firewall (auto-detected: ufw / firewalld / iptables fallback)
#    * SSH hardening (validated with `sshd -t` before restart)
#    * password policy (login.defs + pwquality + faillock)
#    * kernel hardening via sysctl drop-in
#    * fail2ban brute-force protection
#    * unattended automatic security updates
#
#  Modes: --audit (read-only) | --dry-run (preview) | --apply (enforce)
#
#  Author  : Abderrahmen Takrouni
#  Project: https://github.com/abdrahmentakrouni/linux-hardening
#  License: MIT (see LICENSE)
#===============================================================================
set -o errexit
set -o errtrace
set -o pipefail
set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/audit.sh
source "$SCRIPT_DIR/lib/audit.sh"

declare -a ALL_MODULES=(firewall ssh passwords sysctl fail2ban autoupdates)

for _mod in "${ALL_MODULES[@]}"; do
  # shellcheck disable=SC1090
  source "$SCRIPT_DIR/lib/${_mod}.sh"
done

# --- configuration defaults (overridden by config files, then CLI) ---------------
# NOTE: these variables are consumed by the sourced lib/*.sh modules, which
# the linter analyses separately — hence the SC2034 suppression below.
# shellcheck disable=SC2034
SSH_PORT=22
# shellcheck disable=SC2034
ALLOW_PORTS="80,443"            # extra TCP ports to keep open, comma/space separated
# shellcheck disable=SC2034
FIREWALL_IPV6=true              # keep IPv6 enabled in ufw
# shellcheck disable=SC2034
DISABLE_ROOT_SSH=true           # PermitRootLogin no (false -> prohibit-password)
# shellcheck disable=SC2034
DISABLE_PASSWORD_AUTH="auto"    # true | false | auto (auto = off only if SSH keys exist)
# shellcheck disable=SC2034
PASS_MAX_DAYS=90
# shellcheck disable=SC2034
PASS_MIN_DAYS=7
# shellcheck disable=SC2034
PASS_WARN_DAYS=7
# shellcheck disable=SC2034
PASS_MIN_LEN=14
# shellcheck disable=SC2034
FAIL2BAN_MAXRETRY=5
# shellcheck disable=SC2034
FAIL2BAN_FINDTIME="10m"
# shellcheck disable=SC2034
FAIL2BAN_BANTIME="1h"
# shellcheck disable=SC2034
AUTO_UPDATES=true
# shellcheck disable=SC2034
IP_FORWARD=false                # set true for routers/docker hosts

# CLI overrides (applied after config files so flags always win)
CLI_PORT=""
CLI_PORTS=""
CLI_CONFIG=""

ONLY_MODULES=""
SKIP_MODULES=""

declare -a SELECTED_MODULES=()
declare -a MODULES_OK=()
declare -a MODULES_FAILED=()

usage() {
  cat <<EOF
linux-hardening v${VERSION} — automated Linux server hardening

Usage:
  sudo bash harden.sh <mode> [options]

Modes (choose one):
  --audit            read-only security checks + scored report (default)
  --dry-run          preview every change apply would make, touch nothing
  --apply            enforce hardening (modified files are backed up first)

Options:
  -y, --yes                assume yes; never prompt (for CI / automation)
  -c, --config FILE        extra config file (loaded last, overrides the rest)
  --port N                 SSH port to protect (default: 22)
  --allow-ports LIST       extra TCP ports to keep open (default: 80,443)
  --only a,b,c             run only these modules
  --skip a,b,c             skip these modules
  --no-color               disable colored output
  --log FILE               custom log file (default: /var/log/linux-hardening/)
  -v, --version            print version and exit
  -h, --help               show this help and exit

Modules:
  ${ALL_MODULES[*]}

Config files (later wins):
  1. built-in defaults
  2. ${SCRIPT_DIR}/config/harden.conf
  3. /etc/linux-hardening/harden.conf
  4. --config FILE

Exit codes (audit): 0 = all good, 1 = warnings, 2 = failures
Exit codes (apply): 0 = clean,     1 = completed with warnings
EOF
}

parse_args() {
  if [[ $# -eq 0 ]]; then
    log_info "no mode given — defaulting to --audit"
  fi
  while [[ $# -gt 0 ]]; do
    case $1 in
      --audit|--dry-run|--apply) RUN_MODE="${1#--}"; shift ;;
      -y|--yes)     ASSUME_YES=true; shift ;;
      -c|--config)  CLI_CONFIG="${2:?--config needs a file path}"; shift 2 ;;
      --port)       CLI_PORT="${2:?--port needs a number}"; shift 2 ;;
      --allow-ports) CLI_PORTS="${2:?--allow-ports needs a list}"; shift 2 ;;
      --only)       ONLY_MODULES="${2:?--only needs a module list}"; shift 2 ;;
      --skip)       SKIP_MODULES="${2:?--skip needs a module list}"; shift 2 ;;
      --no-color)   disable_color; shift ;;
      --log)        LOG_FILE="${2:?--log needs a file path}"; shift 2 ;;
      -v|--version) printf 'linux-hardening v%s\n' "$VERSION"; exit 0 ;;
      -h|--help)    usage; exit 0 ;;
      *)            usage >&2; die "unknown option: $1" ;;
    esac
  done
}

load_config() {
  local cf
  for cf in "${SCRIPT_DIR}/config/harden.conf" \
            "/etc/linux-hardening/harden.conf" \
            "${CLI_CONFIG:-}"; do
    if [[ -n $cf && -f $cf ]]; then
      log_info "loading config: $cf"
      # shellcheck disable=SC1090
      source "$cf"
    fi
  done
}

apply_cli_overrides() {
  if [[ -n $CLI_PORT ]]; then  SSH_PORT="$CLI_PORT"; fi
  if [[ -n $CLI_PORTS ]]; then
    # shellcheck disable=SC2034  # consumed by lib/firewall.sh
    ALLOW_PORTS="$CLI_PORTS"
  fi
  case $DISABLE_PASSWORD_AUTH in
    true|false|auto) ;;
    *) die "DISABLE_PASSWORD_AUTH must be true|false|auto (got: $DISABLE_PASSWORD_AUTH)" ;;
  esac
}

valid_module() {
  local m
  for m in "${ALL_MODULES[@]}"; do
    if [[ $m == "$1" ]]; then return 0; fi
  done
  return 1
}

in_csv() {
  # in_csv <value> <csv-list> — true when value is a member of the comma list
  local csv item
  csv="$(printf '%s' "$2" | tr -d '[:space:]')"
  if [[ -z $csv ]]; then return 1; fi
  # shellcheck disable=SC2086
  for item in ${csv//,/ }; do
    if [[ $item == "$1" ]]; then return 0; fi
  done
  return 1
}

validate_csv() {
  # every item of a --only/--skip list must be a known module
  local csv item
  csv="$(printf '%s' "$1" | tr -d '[:space:]')"
  if [[ -z $csv ]]; then return 0; fi
  # shellcheck disable=SC2086
  for item in ${csv//,/ }; do
    if ! valid_module "$item"; then
      die "unknown module '$item' (available: ${ALL_MODULES[*]})"
    fi
  done
}

select_modules() {
  validate_csv "$ONLY_MODULES"
  validate_csv "$SKIP_MODULES"
  local m
  for m in "${ALL_MODULES[@]}"; do
    if [[ -n ${ONLY_MODULES// /} ]] && ! in_csv "$m" "$ONLY_MODULES"; then continue; fi
    if [[ -n ${SKIP_MODULES// /} ]] && in_csv "$m" "$SKIP_MODULES"; then continue; fi
    SELECTED_MODULES+=("$m")
  done
  if [[ ${#SELECTED_MODULES[@]} -eq 0 ]]; then
    die "module selection is empty — check --only / --skip"
  fi
}

print_banner() {
  printf '%s\n' "${C_BOLD}linux-hardening v${VERSION} — automated server hardening${C_RESET}"
  hr
  log_info "mode      : $RUN_MODE"
  log_info "distro    : $DISTRO_NAME ($DISTRO_FAMILY family, pkg=$PKG_MGR)"
  log_info "firewall  : $FW_BACKEND"
  log_info "modules   : ${SELECTED_MODULES[*]}"
  log_info "ssh port  : $SSH_PORT"
  log_info "log file  : $LOG_FILE"
  hr
}

acquire_lock() {
  # /var/run is not guaranteed to exist (chroots, minimal containers) —
  # prefer /run and fall back to /tmp.
  local lock_file
  if [[ -d /run && -w /run ]]; then
    lock_file="/run/${PROJECT_NAME}.lock"
  else
    lock_file="/tmp/${PROJECT_NAME}.lock"
  fi
  exec 9>"$lock_file"
  if ! flock -n 9; then
    die "another instance appears to be running (lock: $lock_file)"
  fi
}

run_audit() {
  local m
  for m in "${SELECTED_MODULES[@]}"; do
    module_header "$m"
    "audit_${m}" || true
  done
  audit_summary
}

confirm_plan() {
  log_warn "you are about to MODIFY this server's security configuration"
  log_info "firewall backend : $FW_BACKEND"
  log_info "ssh port         : $SSH_PORT (root login disabled: $DISABLE_ROOT_SSH)"
  log_info "modules          : ${SELECTED_MODULES[*]}"
  log_info "backups under    : $BACKUP_DIR"
  confirm "proceed with --apply?"
}

run_change() {
  local m
  if [[ $RUN_MODE == apply ]]; then
    enable_backups
    acquire_lock
    confirm_plan
  else
    log_info "dry-run: NO changes will be made (use --apply to enforce)"
  fi

  # warnings emitted by the confirmation banner must not pollute the summary
  APPLY_WARNINGS=0

  for m in "${SELECTED_MODULES[@]}"; do
    module_header "$m"
    if "apply_${m}"; then
      MODULES_OK+=("$m")
    else
      MODULES_FAILED+=("$m")
      log_warn "module '$m' finished with errors (see above)"
    fi
  done

  print_change_summary
}

print_change_summary() {
  hr
  if [[ $RUN_MODE == apply ]]; then
    log_info "backups saved to : $BACKUP_DIR"
    log_info "modules completed: ${MODULES_OK[*]:-none}"
    if [[ ${#MODULES_FAILED[@]} -gt 0 ]]; then
      log_warn "modules with errors: ${MODULES_FAILED[*]}"
    fi
    if (( APPLY_WARNINGS > 0 )); then
      log_warn "completed with $APPLY_WARNINGS warning(s) — full log: $LOG_FILE"
      log_info "next step: re-run 'sudo bash harden.sh --audit' to verify"
      exit 1
    fi
    log_ok "all operations completed cleanly — full log: $LOG_FILE"
    log_info "next step: re-run 'sudo bash harden.sh --audit' to verify"
  else
    log_ok "dry-run complete — no changes were made (re-run with --apply to enforce)"
  fi
}

main() {
  parse_args "$@"
  load_config
  apply_cli_overrides
  select_modules        # validates --only/--skip names before anything else
  require_root

  # deterministic output for grep-based checks (locales differ across distros)
  export LC_ALL=C

  init_log "${LOG_FILE:-/var/log/${PROJECT_NAME}/${RUN_MODE}-${TS}.log}"
  detect_distro
  detect_firewall_backend
  print_banner

  case $RUN_MODE in
    audit)   run_audit ;;
    dry-run) run_change ;;
    apply)   run_change ;;
  esac
}

main "$@"
