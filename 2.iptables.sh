#!/bin/sh
# nfmini - minimal ufw-like iptables/ip6tables manager (POSIX sh)
# Debian 13 + Alpine 3.23 (no bash required)
# Manage: filter INPUT/OUTPUT (+ policy), nat PREROUTING (REDIRECT)
# Commands: add / del / hop / status
#
# Spec format (add/del):
#   PORT[-PORT][/proto][/family]
#   examples:
#     50101            => tcp+udp, v4+v6
#     50101/tcp        => tcp, v4+v6
#     50101/tcp/6      => tcp, v6 only
#     51010-51111/udp/4=> udp, v4 only
#
# Spec format (hop fromspec):
#   PORT[-PORT][/proto][/family]
#   examples:
#     51011-51111      => tcp+udp, v4+v6
#     51011/udp        => udp only, v4+v6
#     51011-51111/udp/4=> udp only, v4 only

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
      die "Unsupported OS (need Debian or Alpine). Please install iptables/ip6tables manually."
      ;;
  esac

  have "$IPT4" || die "iptables still missing after install."
  have "$IPT6" || die "ip6tables still missing after install."
}

persist_rules() {
  os="$(detect_os)"
  case "$os" in
    debian)
      if have netfilter-persistent; then
        netfilter-persistent save >/dev/null 2>&1 || true
      else
        mkdir -p /etc/iptables >/dev/null 2>&1 || true
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
      fi
      ;;
    alpine)
      if have rc-service && [ -e /etc/init.d/iptables ]; then
        rc-service iptables save >/dev/null 2>&1 || true
      fi
      if have rc-service && [ -e /etc/init.d/ip6tables ]; then
        rc-service ip6tables save >/dev/null 2>&1 || true
      fi
      ;;
    *)
      ;;
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
  # $1=cmd, $2=chain, rest=rule
  cmd="$1"; chain="$2"; shift 2
  if "$cmd" -C "$chain" "$@" >/dev/null 2>&1; then
    return 0
  fi
  "$cmd" -A "$chain" "$@"
}

ipt_check_del_all_filter() {
  # $1=cmd, $2=chain, rest=rule
  cmd="$1"; chain="$2"; shift 2
  while "$cmd" -C "$chain" "$@" >/dev/null 2>&1; do
    "$cmd" -D "$chain" "$@"
  done
}

chain_has_rules() {
  # $1=cmd, $2=chain
  cmd="$1"; chain="$2"
  "$cmd" -S "$chain" 2>/dev/null | awk '/^-A /{found=1} END{exit(found?0:1)}'
}

init_firewall_one() {
  # $1=cmd, $2=icmp_proto (icmp|ipv6-icmp)
  cmd="$1"; icmpp="$2"

  "$cmd" -F INPUT || true
  "$cmd" -F OUTPUT || true

  "$cmd" -P INPUT DROP
  "$cmd" -P FORWARD DROP
  "$cmd" -P OUTPUT ACCEPT

  ipt_check_add_filter "$cmd" INPUT -i lo -j ACCEPT
  ipt_check_add_filter "$cmd" INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ipt_check_add_filter "$cmd" INPUT -p "$icmpp" -j ACCEPT
}

ensure_initialized() {
  # baseline init if IPv4 INPUT has no rules
  if chain_has_rules "$IPT4" INPUT; then
    return 0
  fi
  log "[*] No existing INPUT rules detected; initializing baseline (DROP INPUT/FORWARD, ACCEPT OUTPUT, allow lo+established+icmp)..."
  init_firewall_one "$IPT4" "icmp"
  init_firewall_one "$IPT6" "ipv6-icmp"
}

# ---------- spec parsing ----------
# Output globals:
#   PORTSPEC: "x" or "x:y"
#   PROTOS: "tcp udp" or "tcp" or "udp"
#   FAMS: "4 6" or "4" or "6"
parse_spec() {
  spec_raw="$1"
  spec="$(printf '%s' "$spec_raw" | tr -d '[:space:]')"
  [ "$spec" != "" ] || die "Empty spec."

  # split by '/'
  portpart="${spec%%/*}"
  rest=""
  case "$spec" in
    */*) rest="${spec#*/}" ;;
  esac

  # defaults
  PROTOS="tcp udp"
  FAMS="4 6"

  # parse rest tokens (0..2 tokens, accept any order)
  if [ "$rest" != "" ]; then
    # rest may contain one or more '/'
    t1="${rest%%/*}"
    t2=""
    case "$rest" in
      */*) t2="${rest#*/}" ;;
    esac

    apply_token() {
      tok="$1"
      [ "$tok" = "" ] && return 0
      case "$tok" in
        tcp|udp)
          PROTOS="$tok"
          ;;
        4|6)
          FAMS="$tok"
          ;;
        *)
          die "Unknown token '$tok' in '$spec_raw' (use tcp/udp and/or 4/6)."
          ;;
      esac
    }

    apply_token "$t1"
    apply_token "$t2"
  fi

  # parse port/range
  case "$portpart" in
    *-*)
      start="${portpart%-*}"
      end="${portpart#*-}"
      ;;
    *)
      start="$portpart"
      end=""
      ;;
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

fam_has4() { echo "$FAMS" | grep -q '4'; }
fam_has6() { echo "$FAMS" | grep -q '6'; }

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
  # If no args: flush INPUT/OUTPUT and allow all inbound/outbound for BOTH families.
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
# NOTE: iptables -t nat must be before -A/-C/-D (can't use filter wrapper)
hop_add() {
  # hop add <to_port> <fromspec> [iface]
  to="$1"; fromspec="$2"; iface="${3:-$(default_iface)}"
  case "$to" in ""|*[!0-9]*) die "Invalid to_port '$to'." ;; esac
  [ "$to" -ge 1 ] && [ "$to" -le 65535 ] || die "to_port out of range."

  parse_spec "$fromspec"  # fromspec controls proto + family; proto default tcp+udp, fam default 4+6

  for p in $PROTOS; do
    if fam_has4; then
      if ! "$IPT4" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to" >/dev/null 2>&1; then
        "$IPT4" -t nat -A PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to"
      fi
    fi

    if fam_has6; then
      # best-effort: some envs lack ip6 nat; failures are non-fatal
      if ! "$IPT6" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to" >/dev/null 2>&1; then
        "$IPT6" -t nat -A PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to" >/dev/null 2>&1 || true
      fi
    fi
  done

  log "[+] hop add: ${fromspec} -> ${to} (iface=$iface, proto=$PROTOS, fam=$FAMS)"
  persist_rules
}

hop_del() {
  # hop del [<to_port> <fromspec> [iface]]
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
      while "$IPT4" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to" >/dev/null 2>&1; do
        "$IPT4" -t nat -D PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to"
      done
    fi

    if fam_has6; then
      while "$IPT6" -t nat -C PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to" >/dev/null 2>&1; do
        "$IPT6" -t nat -D PREROUTING -i "$iface" -p "$p" -m "$p" --dport "$PORTSPEC" \
          -j REDIRECT --to-ports "$to" >/dev/null 2>&1 || break
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
  echo "== IPv4 filter INPUT policy/rules =="
  "$IPT4" -S INPUT 2>/dev/null || true
  echo
  echo "== IPv6 filter INPUT policy/rules =="
  "$IPT6" -S INPUT 2>/dev/null || true
  echo
  hop_status
}

usage() {
  cat <<'EOF'
Usage:
  nfmini add [SPEC ...]
      SPEC: PORT[-PORT][/proto][/family]
      examples:
        nfmini add 50101
        nfmini add 50101/tcp
        nfmini add 50101/tcp/6
        nfmini add 51010-51111/udp/4
      If no SPEC provided, enters interactive mode.

  nfmini del [SPEC ...]
      If no SPEC: flush INPUT/OUTPUT and set policies ACCEPT (allow all inbound/outbound) for v4+v6.

  nfmini hop add <TO_PORT> <FROMSPEC> [iface]
      FROMSPEC: PORT[-PORT][/proto][/family]
      examples:
        nfmini hop add 51010 51011-51111          (tcp+udp, v4+v6)
        nfmini hop add 51010 51011/udp            (udp only, v4+v6)
        nfmini hop add 51010 51011-51111/udp/4    (udp only, v4 only)
        IFACE=eth0 nfmini hop add 51010 51011/udp/6

  nfmini hop del [<TO_PORT> <FROMSPEC> [iface]]
      If no args: flush nat PREROUTING for v4+v6.

  nfmini hop status
  nfmini status
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
        add)
          [ "$#" -ge 2 ] || die "hop add needs: <to_port> <fromspec> [iface]"
          hop_add "$@"
          ;;
        del)
          if [ "$#" -eq 0 ]; then
            hop_del
          else
            [ "$#" -ge 2 ] || die "hop del needs: <to_port> <fromspec> [iface]  (or no args to flush)"
            hop_del "$@"
          fi
          ;;
        status)
          hop_status
          ;;
        *)
          die "Unknown hop subcommand. Use: hop add|del|status"
          ;;
      esac
      ;;
    status)
      status_all
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      die "Unknown command '$cmd'. Use: add|del|hop|status"
      ;;
  esac
}

main "$@"
