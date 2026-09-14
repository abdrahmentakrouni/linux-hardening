#!/usr/bin/env bash
#===============================================================================
# lib/common.sh — shared helpers for linux-hardening
#
# Part of the linux-hardening project.
# Licensed under the MIT License (see LICENSE in the project root).
#===============================================================================

# --- shell safety -------------------------------------------------------------
set -o errexit
set -o errtrace
set -o pipefail
set -o nounset

# shellcheck disable=SC2034  # VERSION is consumed by the module files
VERSION="1.1.0"
PROJECT_NAME="linux-hardening"

# --- globals (defaults; harden.sh and config files may override) --------------
RUN_MODE="audit"          # audit | dry-run | apply
ASSUME_YES=false
COLOR=true
LOG_FILE=""
BACKUP_DIR=""
TS="$(date +%Y%m%d-%H%M%S)"
# Counts every warning emitted via log_warn (apply mode summary + exit code).
# shellcheck disable=SC2034  # APPLY_WARNINGS is consumed by harden.sh summary
APPLY_WARNINGS=0

DISTRO_ID="unknown"
DISTRO_NAME="unknown"
DISTRO_FAMILY="unknown"   # debian | rhel
PKG_MGR="unknown"         # apt | dnf | yum
FW_BACKEND="unknown"      # ufw | firewalld | iptables | none

# --- colors --------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\033[0;31m';   C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[0;33m'
  C_BLUE=$'\033[0;34m';  C_BOLD=$'\033[1m';     C_DIM=$'\033[2m'
  C_RESET=$'\033[0m'
else
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_DIM=""; C_RESET=""
fi

disable_color() {
  COLOR=false
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_DIM=""; C_RESET=""
}

# --- logging --------------------------------------------------------------------
# Every message goes to the terminal (optionally colored) and to the log file.
_log() { # $1=level  $2=color  $3=message
  local level="$1" color="$2" msg="$3"
  if [[ $COLOR == true ]]; then
    printf '%s[%s]%s %s\n' "$color" "$level" "$C_RESET" "$msg"
  else
    printf '[%s] %s\n' "$level" "$msg"
  fi
  if [[ -n $LOG_FILE ]]; then
    printf '[%s] %s\n' "$level" "$msg" >> "$LOG_FILE" || true
  fi
}
log_info()  { _log INFO    "$C_BLUE"   "$*"; }
log_ok()    { _log OK      "$C_GREEN"  "$*"; }
log_warn()  {
  _log WARN "$C_YELLOW" "$*"
  # shellcheck disable=SC2034  # incremented here, consumed by harden.sh
  APPLY_WARNINGS=$((APPLY_WARNINGS + 1))
}
log_error() { _log ERROR   "$C_RED"    "$*"; }
log_dry()   { _log DRY-RUN "$C_YELLOW" "$*"; }
log_debug() {
  if [[ ${DEBUG:-0} == 1 ]]; then _log DEBUG "$C_DIM" "$*"; fi
}
die() {
  log_error "$*"
  exit 1
}

hr() {
  local line="------------------------------------------------------------------------"
  printf '%s\n' "$line"
  if [[ -n $LOG_FILE ]]; then
    printf '%s\n' "$line" >> "$LOG_FILE" || true
  fi
}

module_header() {
  local title="---- [ module: $1 ] ----"
  if [[ $COLOR == true ]]; then
    printf '\n%s%s%s\n' "$C_BOLD" "$title" "$C_RESET"
  else
    printf '\n%s\n' "$title"
  fi
  if [[ -n $LOG_FILE ]]; then
    printf '\n%s\n' "$title" >> "$LOG_FILE" || true
  fi
}

# --- error trap -------------------------------------------------------------------
on_error() {
  local rc="$1"
  log_error "unexpected error (rc=$rc) near line $2 — see ${LOG_FILE:-<no log>}"
}
trap 'on_error $? $LINENO' ERR

# --- environment helpers -----------------------------------------------------------
command_exists() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  local uid
  uid="$(id -u)"
  if [[ $uid -ne 0 ]]; then
    die "this script must run as root (try: sudo $0)"
  fi
}

init_log() {
  local target="$1"
  if mkdir -p "$(dirname "$target")" 2>/dev/null && : > "$target" 2>/dev/null; then
    LOG_FILE="$target"
  else
    # degrade gracefully (read-only /var, restricted environment, ...)
    LOG_FILE=""
    printf '[WARN] cannot write log file %s — continuing without file logging\n' "$target" >&2
  fi
}

enable_backups() {
  BACKUP_DIR="/var/backups/${PROJECT_NAME}/${TS}"
  mkdir -p "$BACKUP_DIR"
  log_info "modified files will be backed up under: $BACKUP_DIR"
}

backup_file() {
  # Keep a copy of a file before modifying it (apply mode only).
  local f="$1"
  if [[ $RUN_MODE != apply ]]; then return 0; fi
  if [[ ! -f $f ]]; then return 0; fi
  if [[ -z $BACKUP_DIR ]]; then return 0; fi
  mkdir -p "$BACKUP_DIR"
  cp --parents "$f" "$BACKUP_DIR/"
  log_debug "backed up: $f"
}

# --- change helpers (dry-run aware) -------------------------------------------------
run_cmd() {
  # run_cmd <description> <command> [args...]
  # dry-run : only logs what would run
  # apply   : executes; failures are logged as warnings and counted, never fatal
  local desc="$1"
  shift
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "$desc"
    log_debug "cmd: $*"
    return 0
  fi
  log_info "$desc"
  local out rc
  if out="$("$@" 2>&1)"; then
    log_ok "done"
    if [[ -n $out ]]; then log_debug "$out"; fi
    return 0
  else
    rc=$?
    log_warn "command failed (rc=$rc): $* ${out:+— ${out}}"
    return 0
  fi
}

write_file() {
  # write_file <path> <perms> <description> <content>
  local path="$1" perms="$2" desc="$3" content="$4"
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would write $path ($desc)"
    log_debug "content: $content"
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  backup_file "$path"
  printf '%s\n' "$content" > "$path"
  chmod "$perms" "$path"
  log_ok "wrote $path ($desc)"
}

set_kv() {
  # set_kv <file> <key> <value> [description]
  # For space-separated configs (sshd_config, login.defs).
  # Replaces the first active/commented occurrence, appends if absent.
  local file="$1" key="$2" value="$3" desc="${4:-}"
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would set '$key $value' in $file"
    return 0
  fi
  if [[ ! -f $file ]]; then
    log_warn "$file not found — cannot set $key"
    return 0
  fi
  backup_file "$file"
  if grep -Eq "^[#[:space:]]*${key}[[:space:]]" "$file"; then
    sed -i -E "s|^[#[:space:]]*(${key})[[:space:]].*|\1 ${value}|" "$file"
  else
    printf '%s %s\n' "$key" "$value" >> "$file"
  fi
  log_ok "set '$key $value' in $file${desc:+ ($desc)}"
}

set_kv_eq() {
  # set_kv_eq <file> <key> <value> [description]
  # For 'key = value' configs (pwquality, dnf-automatic, /etc/default/ufw).
  local file="$1" key="$2" value="$3" desc="${4:-}"
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would set '$key = $value' in $file"
    return 0
  fi
  if [[ ! -f $file ]]; then
    log_warn "$file not found — cannot set $key"
    return 0
  fi
  backup_file "$file"
  if grep -Eq "^[#[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[#[:space:]]*(${key})[[:space:]]*=.*|\1 = ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >> "$file"
  fi
  log_ok "set '$key = $value' in $file${desc:+ ($desc)}"
}

# --- system detection ---------------------------------------------------------------
detect_distro() {
  # Parse /etc/os-release without sourcing it: sourcing would clobber our own
  # globals (Debian/Ubuntu ship VERSION=, VERSION_ID=... which we rely on).
  if [[ ! -r /etc/os-release ]]; then
    die "cannot detect distribution: /etc/os-release is missing"
  fi
  local id_val id_like pretty
  id_val="$(grep -E '^ID=' /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true)"
  id_like="$(grep -E '^ID_LIKE=' /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true)"
  pretty="$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true)"

  DISTRO_ID="${id_val:-unknown}"
  # shellcheck disable=SC2034  # DISTRO_NAME is consumed by harden.sh banner
  DISTRO_NAME="${pretty:-$DISTRO_ID}"

  case $DISTRO_ID in
    ubuntu|debian|linuxmint|kali|raspbian)
      DISTRO_FAMILY=debian; PKG_MGR=apt ;;
    rocky|almalinux|rhel|centos|fedora|ol|amzn|oracle)
      DISTRO_FAMILY=rhel ;;
    *)
      if [[ $id_like == *debian* ]]; then
        DISTRO_FAMILY=debian; PKG_MGR=apt
      elif [[ $id_like == *rhel* || $id_like == *fedora* || $id_like == *centos* ]]; then
        DISTRO_FAMILY=rhel
      else
        die "unsupported distribution: $DISTRO_ID (Debian and RHEL families are supported)"
      fi
      ;;
  esac

  if [[ $DISTRO_FAMILY == rhel ]]; then
    if command_exists dnf; then
      PKG_MGR=dnf
    elif command_exists yum; then
      PKG_MGR=yum
    else
      die "RHEL-family system detected but neither dnf nor yum is available"
    fi
  fi
}

detect_firewall_backend() {
  if command_exists ufw; then
    FW_BACKEND=ufw
  elif command_exists firewall-cmd; then
    FW_BACKEND=firewalld
  elif command_exists iptables; then
    FW_BACKEND=iptables
  else
    # shellcheck disable=SC2034  # FW_BACKEND is consumed by firewall.sh / harden.sh
    FW_BACKEND=none
  fi
}

# --- package & service helpers --------------------------------------------------------
pkg_refresh() {
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would refresh package index ($PKG_MGR)"
    return 0
  fi
  case $PKG_MGR in
    apt) run_cmd "refreshing apt package index" apt-get update -qq ;;
    dnf) run_cmd "refreshing dnf metadata" dnf -q makecache --refresh -y ;;
    yum) log_info "skipping package index refresh (yum)" ;;
  esac
}

pkg_install() {
  # pkg_install <package> [package...]
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would install packages ($PKG_MGR): $*"
    return 0
  fi
  case $PKG_MGR in
    apt) run_cmd "installing packages (apt): $*" env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf) run_cmd "installing packages (dnf): $*" dnf install -y "$@" ;;
    yum) run_cmd "installing packages (yum): $*" yum install -y "$@" ;;
    *)   log_warn "unknown package manager — skipping install of: $*" ;;
  esac
}

svc() {
  # systemctl wrapper that tolerates containers / missing systemd
  if [[ $RUN_MODE == dry-run ]]; then
    log_dry "would run: systemctl $*"
    return 0
  fi
  if [[ ! -d /run/systemd/system ]]; then
    log_warn "systemd is not running (container?) — skipping: systemctl $*"
    return 0
  fi
  if systemctl "$@" 2>/dev/null; then
    log_ok "systemctl $*"
  else
    log_warn "systemctl $* failed (non-fatal)"
  fi
  return 0
}

try_reload_service() {
  # try_reload_service <unit1> [unit2...] — reload the first unit that is active
  local unit
  for unit in "$@"; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      svc reload "$unit"
      return 0
    fi
  done
  log_info "no active service among: $* (nothing to reload)"
}

# --- interaction ------------------------------------------------------------------------
confirm() {
  if [[ $ASSUME_YES == true ]]; then return 0; fi
  if [[ ! -t 0 ]]; then
    die "no TTY available for confirmation — re-run with --yes to proceed non-interactively"
  fi
  local reply
  read -r -p "$1 [yes/N]: " reply
  if [[ $reply != yes && $reply != y ]]; then
    die "aborted by user"
  fi
}
