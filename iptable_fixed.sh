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
      # Enable the restore-on-boot service right after install.
      if have systemctl; then
        systemctl enable netfilter-persistent >/dev/null 2>&1 || true
      fi
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

# Fallback: install a minimal systemd unit that restores rules on every boot.
# Used only when iptables-persistent / netfilter-persistent is absent.
_install_restore_service_debian() {
  local svc='/etc/systemd/system/iptables-nfmini.service'
  cat > "$svc" <<'UNIT'
[Unit]
Description=Restore iptables/ip6tables rules (nfmini fallback)
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'test -f /etc/iptables/rules.v4 && iptables-restore  < /etc/iptables/rules.v4 || true'
ExecStart=/bin/sh -c 'test -f /etc/iptables/rules.v6 && ip6tables-restore < /etc/iptables/rules.v6 || true'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload            >/dev/null 2>&1 || true
  systemctl enable  iptables-nfmini >/dev/null 2>&1 || true
  systemctl start   iptables-nfmini >/dev/null 2>&1 || true
  log "[*] Installed + enabled fallback restore service: iptables-nfmini.service"
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
  # Step 1: always write raw rule files (rules.v4 / rules.v6).
  mkdir -p /etc/iptables >/dev/null 2>&1 || true
  iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

  # Step 2: ask netfilter-persistent to resave (idempotent).
  if have netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
  fi

  # Step 3: ensure a restore-on-boot service is enabled.
  # Without this the rules survive the current session only.
  if have systemctl; then
    if systemctl cat netfilter-persistent.service >/dev/null 2>&1; then
      # iptables-persistent package is present — use its service.
      systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
    else
      # No package service found — drop in our own minimal unit.
      _install_restore_service_debian
    fi
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

# Return space-separated list of non-loopback interfaces that are NOT
# the default-route interface (i.e. secondary VNICs / extra NICs).
_list_secondary_ifaces() {
  primary="$(default_iface)"
  ifaces=""
  if have ip; then
    for iface in $(ip -o link show up 2>/dev/null                    | awk -F': ' '{print $2}'                    | cut -d'@' -f1                    | grep -v '^lo$'); do
      [ "$iface" != "$primary" ] && ifaces="$ifaces $iface"
    done
  fi
  printf '%s' "$ifaces"
}

# Emit a warning if secondary VNICs are present and the caller is
# using the auto-detected primary interface.
_warn_secondary_vnic() {
  sec="$(_list_secondary_ifaces)"
  [ -n "$sec" ] || return 0
  log "WARNING: secondary VNIC interface(s) detected:$sec"
  log "WARNING: hop rule was applied only to primary iface '$(default_iface)'."
  log "WARNING: To redirect traffic on a secondary VNIC use:"
  log "WARNING:   ./iptable.sh hop add <to> <from> <iface>   # specific iface"
  log "WARNING:   ./iptable.sh hop add <to> <from> any        # all interfaces"
}

# Low-level PREROUTING check/add/del that handles iface='any'.
# Usage: _nat_check CMD TABLE CHAIN IFACE PROTO PORTSPEC TO
_nat_op() {
  op="$1"; cmd="$2"; iface="$3"; shift 3
  # build the rule args without -i when iface=any
  if [ "$iface" = "any" ]; then
    rule_args="$*"
  else
    rule_args="-i $iface $*"
  fi
  # $cmd is always a plain command name (iptables / ip6tables) — safe to eval
  case "$op" in
    check) eval "$cmd -t nat -C PREROUTING $rule_args" >/dev/null 2>&1 ;;
    add)
      if ! eval "$cmd -t nat -C PREROUTING $rule_args" >/dev/null 2>&1; then
        eval "$cmd -t nat -A PREROUTING $rule_args"
      fi ;;
    del)
      while eval "$cmd -t nat -C PREROUTING $rule_args" >/dev/null 2>&1; do
        eval "$cmd -t nat -D PREROUTING $rule_args" || break
      done ;;
  esac
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
  to="$1"; fromspec="$2"
  # Accept explicit iface, or "any" (no -i filter), or auto-detect primary.
  # For secondary VNICs always pass the interface name or "any" explicitly.
  if [ "${3:-}" != "" ]; then
    iface="$3"
  else
    iface="$(default_iface)"
    _warn_secondary_vnic   # warn when secondary VNICs exist
  fi

  case "$to" in ""|*[!0-9]*) die "Invalid to_port '$to'." ;; esac
  [ "$to" -ge 1 ] && [ "$to" -le 65535 ] || die "to_port out of range."

  parse_spec "$fromspec"

  for p in $PROTOS; do
    rule="-p $p -m $p --dport $PORTSPEC -j REDIRECT --to-ports $to"
    if fam_has4; then
      _nat_op add "$IPT4" "$iface" $rule
    fi
    if fam_has6; then
      # ip6tables NAT is not supported on all kernels — soft-fail
      _nat_op add "$IPT6" "$iface" $rule 2>/dev/null || true
    fi
  done

  log "[+] hop add: ${fromspec} -> ${to}  (iface=${iface}, proto=${PROTOS}, fam=${FAMS})"
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

  to="$1"; fromspec="$2"
  if [ "${3:-}" != "" ]; then
    iface="$3"
  else
    iface="$(default_iface)"
    _warn_secondary_vnic
  fi

  case "$to" in ""|*[!0-9]*) die "Invalid to_port '$to'." ;; esac
  [ "$to" -ge 1 ] && [ "$to" -le 65535 ] || die "to_port out of range."

  parse_spec "$fromspec"

  for p in $PROTOS; do
    rule="-p $p -m $p --dport $PORTSPEC -j REDIRECT --to-ports $to"
    if fam_has4; then
      _nat_op del "$IPT4" "$iface" $rule
    fi
    if fam_has6; then
      _nat_op del "$IPT6" "$iface" $rule 2>/dev/null || true
    fi
  done

  log "[-] hop del: ${fromspec} -> ${to}  (iface=${iface}, proto=${PROTOS}, fam=${FAMS})"
  persist_rules
}

hop_status() {
  echo "== hop status (IPv4 nat PREROUTING) =="
  "$IPT4" -t nat -L PREROUTING -n --line-numbers 2>/dev/null | awk 'NR==1||NR==2||/REDIRECT/'
  echo
  echo "== hop status (IPv6 nat PREROUTING) =="
  "$IPT6" -t nat -L PREROUTING -n --line-numbers 2>/dev/null | awk 'NR==1||NR==2||/REDIRECT/' || true
  echo
  echo "== active interfaces =="
  primary="$(default_iface)"
  printf "  primary (default route): %s\n" "$primary"
  sec="$(_list_secondary_ifaces)"
  if [ -n "$sec" ]; then
    for iface in $sec; do
      ip4="$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | tr '\n' ' ')"
      printf "  secondary VNIC:          %-12s  %s\n" "$iface" "$ip4"
    done
    echo "  TIP: use 'hop add <to> <from> <iface>' or 'hop add <to> <from> any'"
  else
    echo "  no secondary VNICs detected"
  fi
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
  if [ "$os" = "debian" ] && have systemctl; then
    echo "== Debian persistence service status =="
    for svc in netfilter-persistent.service iptables-nfmini.service; do
      if systemctl cat "$svc" >/dev/null 2>&1; then
        enabled="$(systemctl is-enabled "$svc" 2>/dev/null)"; [ -n "$enabled" ] || enabled="unknown"
        active="$(systemctl is-active   "$svc" 2>/dev/null)"; [ -n "$active"  ] || active="unknown"
        printf "  %-38s enabled=%-10s active=%s\n" "$svc" "$enabled" "$active"
      fi
    done
    echo "  rule files:"
    for f in /etc/iptables/rules.v4 /etc/iptables/rules.v6; do
      if [ -f "$f" ]; then printf "    %s (%d bytes)\n" "$f" "$(wc -c < "$f")";
      else printf "    %s (missing)\n" "$f"; fi
    done
    echo
  fi
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

  ./iptables.sh hop add <TO_PORT> <FROMSPEC> [iface|any]
      iface: specific interface (e.g. eth0, enp1s0)
             omit = auto-detect primary VNIC (warns if secondary VNICs exist)
             any  = no interface filter, matches ALL interfaces incl. secondary VNICs
      examples:
        ./iptables.sh hop add 51010 51011-51111            # primary iface only
        ./iptables.sh hop add 51010 51011/udp any          # ALL ifaces (secondary VNIC safe)
        ./iptables.sh hop add 51010 51011-51111/udp/4 enp1s0  # specific secondary VNIC
        ./iptables.sh hop add 51010 51011/tcp/6 any        # IPv6, all ifaces

  ./iptables.sh hop del [<TO_PORT> <FROMSPEC> [iface|any]]
      If no args: flush nat PREROUTING for v4+v6.
      iface/any must match exactly what was used in hop add.

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

