#!/bin/sh
# nfmini - minimal ufw-like iptables/ip6tables manager (POSIX sh)
# Debian 13 + Alpine 3.23 (no bash required)
# Manage: filter INPUT/OUTPUT (+ policy), nat PREROUTING (REDIRECT)
# Commands: add / del / hop / status

set -eu

IPT4="iptables"
IPT6="ip6tables"

log() { printf '%s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "Please run as root."; }
have() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
  if [ -f /etc/alpine-release ]; then
    echo "alpine"
  elif [ -f /etc/debian_version ]; then
    echo "debian"
  else
    echo "unknown"
  fi
}

ensure_iptables_installed() {
  if have "$IPT4" && have "$IPT6"; then
    return 0
  fi

  os="$(detect_os)"
  case "$os" in
    debian)
      have apt-get || die "apt-get not found (expected Debian)."
      export DEBIAN_FRONTEND=noninteractive
      log "[*] Installing iptables + iptables-persistent (netfilter-persistent)..."
      apt-get update -y
      apt-get install -y iptables iptables-persistent >/dev/null
      ;;
    alpine)
      have apk || die "apk not found (expected Alpine)."
      log "[*] Installing iptables (+ OpenRC scripts if needed)..."
      apk add --no-cache iptables >/dev/null
      if [ ! -e /etc/init.d/iptables ]; then
        apk add --no-cache iptables-openrc >/dev/null 2>&1 || true
      fi
      ;;
    *)
      die "Unsupported OS. Please install iptables/ip6tables manually."
      ;;
  esac

  have "$IPT4" || die "iptables still missing after install."
  have "$IPT6" || die "ip6tables still missing after install."
}

# --- persistence (improved for Alpine) ---
persist_rules_alpine() {
  # Always save to files used by OpenRC iptables scripts.
  mkdir -p /etc/iptables >/dev/null 2>&1 || true
  if have iptables-save; then
    iptables-save > /etc/iptables/rules-save 2>/dev/null || true
  fi
  if have ip6tables-save; then
    ip6tables-save > /etc/iptables/rules6-save 2>/dev/null || true
  fi

  # If OpenRC is present, enable + start services so reboot restores.
  if have rc-update && have rc-service; then
    if [ -e /etc/init.d/iptables ]; then
      rc-update add iptables default >/dev/null 2>&1 || true
      rc-service iptables start >/dev/null 2>&1 || true
      rc-service iptables save >/dev/null 2>&1 || true
    fi
    if [ -e /etc/init.d/ip6tables ]; then
      rc-update add ip6tables default >/dev/null 2>&1 || true
      rc-service ip6tables start >/dev/null 2>&1 || true
      rc-service ip6tables save >/dev/null 2>&1 || true
    fi
  fi
}

persist_rules_debian() {
  if have netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
  else
    mkdir -p /etc/iptables >/dev/null 2>&1 || true
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  fi
}

persist_rules() {
  os="$(detect_os)"
  case "$os" in
    alpine) persist_rules_alpine ;;
    debian) persist_rules_debian ;;
    *) ;;
  esac
}

default_iface() {
  if [ "${IFACE:-}" != "" ]; then
    echo "$IFACE"
    return 0
  fi
  if have ip; then
    iface="$(ip route 2>/dev/null | awk '/^default /{print $5; exit}')"
    if [ "$iface" = "" ]; then
      iface="$(ip link 2>/dev/null | awk -F': ' '/^[0-9]+: [^lo]/{print $2; exit}' | cut -d'@' -f1)"
    fi
    [ "$iface" != "" ] && { echo "$iface"; return 0; }
  fi
  echo "eth0"
}

# ---------- filter rule helpers ----------
ipt_check_add_filter() {
  cmd="$1"; chain="$2"; shift 2
  if "$cmd" -C "$chain" "$@" >/dev/null 2>&1; then
    return 0
  fi
  "$cmd" -A "$chain" "$@"
}

ipt_check_del_all_filter() {
  cmd="$1"; chain="$2"; shift 2
  while "$cmd" -C "$chain" "$@" >/dev/null 2>&1; do
    "$cmd" -D "$chain" "$@"
  done
}

chain_has_rules() {
  cmd="$1"; chain="$2"
  "$cmd" -S "$chain" 2>/dev/null | awk '/^-A /{found=1} END{exit(found?0:1)}'
}

init_firewall_one() {
  cmd="$1"; icmpp="$2"; fam="$3"

  "$cmd" -F INPUT || true
  "$cmd" -F OUTPUT || true

  "$cmd" -P INPUT DROP
  "$cmd" -P FORWARD DROP
  "$cmd" -P OUTPUT ACCEPT

  ipt_check_add_filter "$cmd" INPUT -i lo -j ACCEPT
  ipt_check_add_filter "$cmd" INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ipt_check_add_filter "$cmd" INPUT -p "$icmpp" -j ACCEPT

  # DHCP safety net
  if [ "$fam" = "4" ]; then
    ipt_check_add_filter "$cmd" INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT
  else
    ipt_check_add_filter "$cmd" INPUT -p udp -m udp --sport 547 --dport 546 -j ACCEPT
  fi
}

ensure_initialized() {
  if chain_has_rules "$IPT4" INPUT; then
    return 0
  fi
  log "[*] Initializing baseline (DROP INPUT/FORWARD, ACCEPT OUTPUT, allow lo+established+icmp + DHCP v4/v6)..."
  init_firewall_one "$IPT4" "icmp" "4"
  init_firewall_one "$IPT6" "ipv6-icmp" "6"
}

# ---------- spec parsing ----------
# Output globals: PORTSPEC, PROTOS, FAMS
parse_spec() {
  spec_raw="$1"
  spec="$(printf '%s' "$spec_raw" | tr -d '[:space:]')"
  [ "$spec" != "" ] || die "Empty spec."

  portpart="${spec%%/*}"
  rest=""
  case "$spec" in */*) rest="${spec#*/}" ;; esac

  PROTOS="tcp udp"
  FAMS="4 6"

  if [ "$rest" != "" ]; then
    oldIFS="$IFS"
    IFS='/'
    # split tokens into $@
    # shellcheck disable=SC2086
    set -- $rest
    IFS="$oldIFS"

    for tok in "$@"; do
      [ "$tok" = "" ] && continue
      case "$tok" in
        tcp|udp) PROTOS="$tok" ;;
        4|6) FAMS="$tok" ;;
        *) die "Unknown token '$tok' in '$spec_raw' (use tcp/udp and/or 4/6)." ;;
      esac
    done
  fi

  case "$portpart" in
    *-*) start="${portpart%-*}"; end="${portpart#*-}" ;;
    *)   start="$portpart"; end="" ;;
  esac

  case "$start" in ""|*[!0-9]*) die "Invalid port in '$spec_raw'." ;; esac
  if [ "$end" != "" ]; then
    case "$end" in ""|*[!0-9]*) die "Invalid port range in '$spec_raw'." ;; esac
  fi

  [ "$start" -ge 1 ] && [ "$start" -le 65535 ] || die "Port out of range in '$spec_raw'."
  if [ "$end" != "" ]; then
    [ "$end" -ge 1 ] && [ "$end" -le 65535 ] || die "Port out of range in '$spec_raw'."
    [ "$start" -le "$end" ] || die "Range start > end in '$spec_raw'."
    PORTSPEC="${start}:${end}"
  else
    PORTSPEC="$start"
  fi
}

fam_has4() { case " $FAMS " in *" 4 "*) return 0;; *) return 1;; esac; }
fam_has6() { case " $FAMS " in *" 6 "*) return 0;; *) return 1;; esac; }

# ---------- add/del ----------
add_ports() {
  ensure_initialized
  for spec in "$@"; do
    parse_spec "$spec"
    for p in $PROTOS; do
      if fam_has4; then
        ipt_check_add_filter "$IPT4" INPUT -p "$p" -m conntrack --ctstate NEW -m "$p" --dport "$PORTSPEC" -j ACCEPT
      fi
      if fam_has6; then
        ipt_check_add_filter "$IPT6" INPUT -p "$p" -m conntrack --ctstate NEW -m "$p" --dport "$PORTSPEC" -j ACCEPT
      fi
    done
    log "[+] opened: $spec  (proto=$PROTOS, fam=$FAMS)"
  done
  persist_rules
}

del_ports() {
  if [ "$#" -eq 0 ]; then
    log "[*] Clearing INPUT/OUTPUT and allowing all inbound/outbound (policies ACCEPT) for v4+v6..."
    for cmd in "$IPT4" "$IPT6"; do
      "$cmd" -F INPUT || true
      "$cmd" -F OUTPUT || true
      "$cmd" -P INPUT ACCEPT || true
      "$cmd" -P OUTPUT ACCEPT || true
      "$cmd" -P FORWARD ACCEPT || true
    done
    persist_rules
    return 0
  fi

  for spec in "$@"; do
    parse_spec "$spec"
    for p in $PROTOS; do
      if fam_has4; then
        ipt_check_del_all_filter "$IPT4" INPUT -p "$p" -m conntrack --ctstate NEW -m "$p" --dport "$PORTSPEC" -j ACCEPT
      fi
      if fam_has6; then
        ipt_check_del_all_filter "$IPT6" INPUT -p "$p" -m conntrack --ctstate NEW -m "$p" --dport "$PORTSPEC" -j ACCEPT
      fi
    done
    log "[-] removed: $spec  (proto=$PROTOS, fam=$FAMS)"
  done
  persist_rules
}

# ---------- hop (nat PREROUTING REDIRECT) ----------
hop_add() {
  to="$1"; fromspec="$2"; iface="${3:-$(default_iface)}"
  case "$to" in ""|*[!0-9]*) die "Invalid to_port '$to'." ;; esac
  [ "$to" -ge 1 ] && [ "$to" -le 65535 ] || die "to_port out of range."

  parse_spec "$fromspec"

  for p in $PROTOS; do
    if fam_has4; then
      if ! "$IPT4" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to" >/dev/null 2>&1; then
        "$IPT4" -t nat -A PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to"
      fi
    fi

    if fam_has6; then
      if ! "$IPT6" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to" >/dev/null 2>&1; then
        "$IPT6" -t nat -A PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to" >/dev/null 2>&1 || true
      fi
    fi
  done

  log "[+] hop add: ${fromspec} -> ${to} (iface=$iface, proto=$PROTOS, fam=$FAMS)"
  persist_rules
}

hop_del() {
  if [ "$#" -eq 0 ]; then
    log "[*] hop del (no args): flushing nat PREROUTING for v4+v6..."
    "$IPT4" -t nat -F PREROUTING || true
    "$IPT6" -t nat -F PREROUTING || true
    persist_rules
    return 0
  fi

  to="$1"; fromspec="$2"; iface="${3:-$(default_iface)}"
  case "$to" in ""|*[!0-9]*) die "Invalid to_port '$to'." ;; esac
  [ "$to" -ge 1 ] && [ "$to" -le 65535 ] || die "to_port out of range."

  parse_spec "$fromspec"

  for p in $PROTOS; do
    if fam_has4; then
      while "$IPT4" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to" >/dev/null 2>&1; do
        "$IPT4" -t nat -D PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to"
      done
    fi

    if fam_has6; then
      while "$IPT6" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to" >/dev/null 2>&1; do
        "$IPT6" -t nat -D PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" -j REDIRECT --to-ports "$to" >/dev/null 2>&1 || break
      done
    fi
  done

  log "[-] hop del: ${fromspec} -> ${to} (iface=$iface, proto=$PROTOS, fam=$FAMS)"
  persist_rules
}

hop_status() {
  echo "== hop status (IPv4 nat PREROUTING) =="
  "$IPT4" -t nat -L PREROUTING -n --line-numbers 2>/dev/null | awk 'NR==1||NR==2||/REDIRECT/'
  echo
  echo "== hop status (IPv6 nat PREROUTING) =="
  "$IPT6" -t nat -L PREROUTING -n --line-numbers 2>/dev/null | awk 'NR==1||NR==2||/REDIRECT/' || true
}

status_all() {
  echo "== IPv4 filter (full) =="
  "$IPT4" -S 2>/dev/null || true
  echo
  echo "== IPv6 filter (full) =="
  "$IPT6" -S 2>/dev/null || true
  echo
  hop_status
  echo
  os="$(detect_os)"
  if [ "$os" = "alpine" ]; then
    echo "== Alpine persistence files =="
    [ -f /etc/iptables/rules-save ] && echo "v4 saved: /etc/iptables/rules-save" || echo "v4 saved: (missing) /etc/iptables/rules-save"
    [ -f /etc/iptables/rules6-save ] && echo "v6 saved: /etc/iptables/rules6-save" || echo "v6 saved: (missing) /etc/iptables/rules6-save"
    if have rc-update; then
      echo "== OpenRC enabled services (grep iptables) =="
      rc-update show 2>/dev/null | grep -E '(^|\s)(ip6tables|iptables)($|\s)' || true
    else
      echo "== OpenRC not detected (containers often have no OpenRC), reboot won't restore iptables automatically =="
    fi
  fi
}

usage() {
  cat <<'EOF'
Usage:
  ./iptables.sh add [SPEC ...]
      SPEC: PORT[-PORT][/proto][/family]
      examples:
        ./iptables.sh add 50101
        ./iptables.sh add 50101/tcp
        ./iptables.sh add 50101/tcp/6
        ./iptables.sh add 51010-51111/udp/4

  ./iptables.sh del [SPEC ...]
      If no SPEC: flush INPUT/OUTPUT and set policies ACCEPT for v4+v6.

  ./iptables.sh hop add <TO_PORT> <FROMSPEC> [iface]
      examples:
        ./iptables.sh hop add 51010 51011-51111
        ./iptables.sh hop add 51010 51011/udp
        ./iptables.sh hop add 51010 51011-51111/udp/4

  ./iptables.sh hop del [<TO_PORT> <FROMSPEC> [iface]]
      If no args: flush nat PREROUTING for v4+v6.

  ./iptables.sh hop status
  ./iptables.sh status
EOF
}

main() {
  need_root
  ensure_iptables_installed

  cmd="${1:-}"
  shift || true

  case "$cmd" in
    add)
      if [ "$#" -eq 0 ]; then
        printf "Enter specs to open (e.g. 40404/tcp, 51011, 51010-51111/udp/4, 50101/tcp/6):\n> " >&2
        IFS= read -r line || exit 1
        line="$(printf '%s' "$line" | tr ',' ' ')"
        # shellcheck disable=SC2086
        set -- $line
        [ "$#" -gt 0 ] || die "No specs provided."
      fi
      add_ports "$@"
      ;;
    del)
      del_ports "$@"
      ;;
    hop)
      sub="${1:-}"; shift || true
      case "$sub" in
        add) [ "$#" -ge 2 ] || die "hop add needs: <to_port> <fromspec> [iface]"; hop_add "$@" ;;
        del)
          if [ "$#" -eq 0 ]; then
            hop_del
          else
            [ "$#" -ge 2 ] || die "hop del needs: <to_port> <fromspec> [iface] (or no args to flush)"
            hop_del "$@"
          fi
          ;;
        status) hop_status ;;
        *) die "Unknown hop subcommand. Use: hop add|del|status" ;;
      esac
      ;;
    status) status_all ;;
    ""|-h|--help|help) usage ;;
    *) die "Unknown command '$cmd'. Use: add|del|hop|status" ;;
  esac
}

main "$@"
