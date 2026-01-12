#!/bin/sh
set -eu

APP_NAME="simplefw"

need_root() {
  if [ "$(id -u)" != "0" ]; then
    echo "请用 root 运行：sudo $0 ..."
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
  OS_ID="unknown"
  OS_LIKE=""
  OS_VER=""
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_VER="${VERSION_ID:-}"
  fi
}

install_pkgs() {
  if have_cmd iptables && have_cmd ip6tables; then
    return 0
  fi

  echo "检测到 iptables/ip6tables 未安装，开始自动安装..."

  case "$OS_ID" in
    debian|ubuntu)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y iptables iptables-persistent
      ;;
    alpine)
      apk update
      apk add --no-cache iptables ip6tables 2>/dev/null || apk add --no-cache iptables
      ;;
    *)
      case "$OS_LIKE" in
        *debian*)
          export DEBIAN_FRONTEND=noninteractive
          apt-get update -y
          apt-get install -y iptables iptables-persistent
          ;;
        *alpine*)
          apk update
          apk add --no-cache iptables ip6tables 2>/dev/null || apk add --no-cache iptables
          ;;
        *)
          echo "不支持的系统：OS_ID=$OS_ID OS_LIKE=$OS_LIKE。请手动安装 iptables/ip6tables。"
          exit 1
          ;;
      esac
      ;;
  esac

  if ! have_cmd iptables || ! have_cmd ip6tables; then
    echo "安装后仍未找到 iptables/ip6tables，请检查系统包或 PATH。"
    exit 1
  fi
}

apply_base_rules_one() {
  ipt="$1"
  "$ipt" -F
  "$ipt" -X

  "$ipt" -P INPUT DROP
  "$ipt" -P FORWARD DROP
  "$ipt" -P OUTPUT ACCEPT

  "$ipt" -A INPUT -i lo -j ACCEPT
  "$ipt" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

is_base_ready() {
  ipt="$1"
  "$ipt" -S 2>/dev/null | head -n 1 | grep -q "^-P INPUT DROP$"
}

ensure_base_rules() {
  if ! is_base_ready iptables; then
    echo "未检测到 IPv4 基础默认策略，先初始化..."
    apply_base_rules_one iptables
  fi
  if ! is_base_ready ip6tables; then
    echo "未检测到 IPv6 基础默认策略，先初始化..."
    apply_base_rules_one ip6tables
  fi
}

# 解析 spec：
# - 单端口：51011 或 40404/tcp
# - 范围：51010:51111/udp
# 输出：START END PROTO MODE
# MODE=single|range
normalize_port_spec() {
  spec="$1"
  portpart=""
  proto=""

  case "$spec" in
    */*)
      portpart=${spec%/*}
      proto=${spec#*/}
      ;;
    *)
      portpart=$spec
      proto=""
      ;;
  esac

  if [ -z "$proto" ]; then
    printf "端口 %s 未指定协议，选择 [tcp/udp/both] (默认 tcp): " "$portpart"
    read proto || proto=""
    [ -z "$proto" ] && proto="tcp"
  fi
  proto=$(printf "%s" "$proto" | tr 'A-Z' 'a-z')
  case "$proto" in
    tcp|udp|both) ;;
    *)
      echo "无效协议：$proto（仅支持 tcp/udp/both）"
      exit 1
      ;;
  esac

  case "$portpart" in
    *:*)
      start=${portpart%:*}
      end=${portpart#*:}
      ;;
    *)
      start=$portpart
      end=$portpart
      ;;
  esac

  # 校验 start/end
  case "$start" in ''|*[!0-9]*) echo "无效端口：$spec"; exit 1;; esac
  case "$end"   in ''|*[!0-9]*) echo "无效端口：$spec"; exit 1;; esac

  if [ "$start" -lt 1 ] || [ "$start" -gt 65535 ] || [ "$end" -lt 1 ] || [ "$end" -gt 65535 ]; then
    echo "无效端口范围：$spec"
    exit 1
  fi
  if [ "$start" -gt "$end" ]; then
    echo "端口范围起止错误：$start:$end（start 不能大于 end）"
    exit 1
  fi

  mode="single"
  [ "$start" != "$end" ] && mode="range"

  echo "$start $end $proto $mode"
}

# 检查规则是否存在（single: --dport；range: -m multiport --dports start:end）
rule_exists() {
  ipt="$1"
  start="$2"
  end="$3"
  proto="$4"
  mode="$5"

  if [ "$mode" = "single" ]; then
    "$ipt" -C INPUT -p "$proto" --dport "$start" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null
  else
    "$ipt" -C INPUT -p "$proto" -m multiport --dports "$start:$end" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null
  fi
}

add_rule_one() {
  ipt="$1"
  start="$2"
  end="$3"
  proto="$4"
  mode="$5"

  if rule_exists "$ipt" "$start" "$end" "$proto" "$mode"; then
    if [ "$mode" = "single" ]; then
      echo "[$ipt] 已存在：允许 INPUT $start/$proto"
    else
      echo "[$ipt] 已存在：允许 INPUT $start:$end/$proto"
    fi
    return 0
  fi

  if [ "$mode" = "single" ]; then
    "$ipt" -A INPUT -p "$proto" --dport "$start" -m conntrack --ctstate NEW -j ACCEPT
    echo "[$ipt] 已添加：允许 INPUT $start/$proto"
  else
    "$ipt" -A INPUT -p "$proto" -m multiport --dports "$start:$end" -m conntrack --ctstate NEW -j ACCEPT
    echo "[$ipt] 已添加：允许 INPUT $start:$end/$proto"
  fi
}

del_rule_one() {
  ipt="$1"
  start="$2"
  end="$3"
  proto="$4"
  mode="$5"
  removed=0

  if [ "$mode" = "single" ]; then
    while "$ipt" -D INPUT -p "$proto" --dport "$start" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; do
      removed=$((removed + 1))
    done
    if [ "$removed" -gt 0 ]; then
      echo "[$ipt] 已删除 $removed 条：INPUT $start/$proto"
    else
      echo "[$ipt] 未找到规则：INPUT $start/$proto"
    fi
  else
    while "$ipt" -D INPUT -p "$proto" -m multiport --dports "$start:$end" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; do
      removed=$((removed + 1))
    done
    if [ "$removed" -gt 0 ]; then
      echo "[$ipt] 已删除 $removed 条：INPUT $start:$end/$proto"
    else
      echo "[$ipt] 未找到规则：INPUT $start:$end/$proto"
    fi
  fi
}

persist_rules() {
  case "$OS_ID" in
    debian|ubuntu)
      if have_cmd netfilter-persistent; then
        netfilter-persistent save
        if have_cmd systemctl; then
          systemctl enable netfilter-persistent >/dev/null 2>&1 || true
        fi
        echo "已持久化（Debian）：netfilter-persistent save"
      else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
        echo "已持久化（Debian 兜底）：/etc/iptables/rules.v4 + rules.v6"
      fi
      ;;
    alpine)
      mkdir -p /etc/iptables
      iptables-save > /etc/iptables/rules-save
      ip6tables-save > /etc/iptables/rules6-save
      if have_cmd rc-update; then
        rc-update add iptables default >/dev/null 2>&1 || true
        rc-update add ip6tables default >/dev/null 2>&1 || true
      fi
      echo "已持久化（Alpine）：/etc/iptables/rules-save + rules6-save（并尝试启用 iptables/ip6tables）"
      ;;
    *)
      if have_cmd netfilter-persistent; then
        netfilter-persistent save
        if have_cmd systemctl; then
          systemctl enable netfilter-persistent >/dev/null 2>&1 || true
        fi
        echo "已持久化：netfilter-persistent save"
      else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
        echo "已持久化：/etc/iptables/rules.v4 + rules.v6（通用兜底）"
      fi
      ;;
  esac
}

cmd_add() {
  spec="${1:-}"
  if [ -z "$spec" ]; then
    printf "请输入要开放的端口（如 40404/tcp 或 51011 或 51010:51111/udp）： "
    read spec
  fi

  ensure_base_rules

  set -- $(normalize_port_spec "$spec")
  start="$1"
  end="$2"
  proto="$3"
  mode="$4"

  if [ "$proto" = "both" ]; then
    add_rule_one iptables  "$start" "$end" tcp "$mode"
    add_rule_one iptables  "$start" "$end" udp "$mode"
    add_rule_one ip6tables "$start" "$end" tcp "$mode"
    add_rule_one ip6tables "$start" "$end" udp "$mode"
  else
    add_rule_one iptables  "$start" "$end" "$proto" "$mode"
    add_rule_one ip6tables "$start" "$end" "$proto" "$mode"
  fi

  persist_rules
}

cmd_del() {
  spec="${1:-}"
  if [ -z "$spec" ]; then
    printf "请输入要删除的端口规则（如 40404/tcp 或 51011 或 51010:51111/udp）： "
    read spec
  fi

  ensure_base_rules

  set -- $(normalize_port_spec "$spec")
  start="$1"
  end="$2"
  proto="$3"
  mode="$4"

  if [ "$proto" = "both" ]; then
    del_rule_one iptables  "$start" "$end" tcp "$mode"
    del_rule_one iptables  "$start" "$end" udp "$mode"
    del_rule_one ip6tables "$start" "$end" tcp "$mode"
    del_rule_one ip6tables "$start" "$end" udp "$mode"
  else
    del_rule_one iptables  "$start" "$end" "$proto" "$mode"
    del_rule_one ip6tables "$start" "$end" "$proto" "$mode"
  fi

  persist_rules
}

cmd_status() {
  echo "=== $APP_NAME status ==="
  echo "OS: $OS_ID $OS_VER"
  echo

  echo "--- IPv4 (iptables) policies (first lines) ---"
  iptables -S | sed -n '1,20p'
  echo
  echo "--- IPv4 INPUT rules ---"
  iptables -L INPUT -n -v --line-numbers
  echo
  echo "--- IPv4 OUTPUT rules ---"
  iptables -L OUTPUT -n -v --line-numbers
  echo

  echo "--- IPv6 (ip6tables) policies (first lines) ---"
  ip6tables -S | sed -n '1,20p'
  echo
  echo "--- IPv6 INPUT rules ---"
  ip6tables -L INPUT -n -v --line-numbers
  echo
  echo "--- IPv6 OUTPUT rules ---"
  ip6tables -L OUTPUT -n -v --line-numbers
  echo
}

usage() {
  cat <<EOF
用法：
  $0 add [PORT[/PROTO]]
  $0 del [PORT[/PROTO]]
  $0 status

支持：
  - 单端口：40404/tcp, 51011, 53/both
  - 连续端口范围：51010:51111/udp（同样支持 /tcp 或 /both）

示例：
  $0 add 51010:51111/udp
  $0 del 51010:51111/udp
EOF
}

main() {
  need_root
  detect_os
  install_pkgs

  cmd="${1:-}"
  shift 2>/dev/null || true

  case "$cmd" in
    add)    cmd_add "${1:-}" ;;
    del)    cmd_del "${1:-}" ;;
    status) cmd_status ;;
    ""|-h|--help|help) usage ;;
    *)
      echo "未知命令：$cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
