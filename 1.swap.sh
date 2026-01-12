#!/bin/sh
set -eu

SWAPFILE="${SWAPFILE:-/swapfile}"

say(){ printf "%s\n" "$*"; }

need_root() {
  if [ "$(id -u)" != "0" ]; then
    say "❌ 请用 root 运行：sudo -i 或 su -"
    exit 1
  fi
}

ensure_tools() {
  # mkswap / swapon / swapoff / fallocate 在 util-linux
  if ! command -v mkswap >/dev/null 2>&1 || ! command -v swapon >/dev/null 2>&1; then
    say "==> 安装 util-linux（提供 mkswap/swapon/swapoff）"
    apk add --no-cache util-linux
  fi
}

is_swap_active() {
  # returns 0 if SWAPFILE currently active
  [ -f /proc/swaps ] && awk 'NR>1{print $1}' /proc/swaps | grep -qx "$SWAPFILE"
}

remove_fstab_entry() {
  if [ -f /etc/fstab ]; then
    # 删除包含 swapfile 且 type=swap 的行
    # BusyBox sed 用 -i
    sed -i "\|^[[:space:]]*$SWAPFILE[[:space:]]\+.*[[:space:]]swap[[:space:]]|d" /etc/fstab || true
  fi
}

append_fstab_entry() {
  # 避免重复写入
  if [ ! -f /etc/fstab ] || ! grep -qE "^[[:space:]]*$SWAPFILE[[:space:]]+.*[[:space:]]swap[[:space:]]" /etc/fstab; then
    echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  fi
}

parse_size_to_bytes() {
  # input like 1G/512M/2048 (MB)/2g/256m
  in="$1"
  in="$(echo "$in" | tr -d ' ')"
  if echo "$in" | grep -qiE '^[0-9]+[gG]$'; then
    n="$(echo "$in" | sed 's/[gG]//')"
    echo $((n * 1024 * 1024 * 1024))
  elif echo "$in" | grep -qiE '^[0-9]+[mM]$'; then
    n="$(echo "$in" | sed 's/[mM]//')"
    echo $((n * 1024 * 1024))
  elif echo "$in" | grep -qE '^[0-9]+$'; then
    # 纯数字：按 MB
    n="$in"
    echo $((n * 1024 * 1024))
  else
    return 1
  fi
}

human_mib() {
  # bytes -> MiB (rounded)
  b="$1"
  echo $(( (b + 1024*1024 - 1) / (1024*1024) ))
}

create_swapfile() {
  bytes="$1"
  mib="$(human_mib "$bytes")"

  # 如果已存在，先提示/覆盖
  if [ -e "$SWAPFILE" ]; then
    say "⚠️ $SWAPFILE 已存在，将先尝试关闭并删除后重建。"
    delete_swap || true
  fi

  say "==> 创建 swapfile: $SWAPFILE (${mib}MiB)"

  # 优先 fallocate（更快），失败再用 dd
  if command -v fallocate >/dev/null 2>&1; then
    if ! fallocate -l "${mib}M" "$SWAPFILE" 2>/dev/null; then
      say "⚠️ fallocate 失败，改用 dd 创建（会慢一些）"
      dd if=/dev/zero of="$SWAPFILE" bs=1M count="$mib" status=progress
    fi
  else
    dd if=/dev/zero of="$SWAPFILE" bs=1M count="$mib" status=progress
  fi

  chmod 600 "$SWAPFILE"

  # btrfs 特殊情况提示（不强行处理，避免误操作）
  if command -v stat >/dev/null 2>&1; then
    fstype="$(stat -f -c %T "$(dirname "$SWAPFILE")" 2>/dev/null || true)"
    case "$fstype" in
      btrfs)
        say "⚠️ 检测到可能是 btrfs：swapfile 需要额外设置（如禁用 CoW / 设置 nocow），否则 swapon 可能失败。"
        ;;
    esac
  fi

  mkswap "$SWAPFILE" >/dev/null
  swapon "$SWAPFILE"

  append_fstab_entry

  say "✅ swap 已启用并写入 /etc/fstab"
  show_status
}

delete_swap() {
  say "==> 删除 swap"

  if is_swap_active; then
    swapoff "$SWAPFILE" || true
    say "✅ 已 swapoff: $SWAPFILE"
  else
    say "ℹ️ swap 未处于 active 状态（或不是 $SWAPFILE）。"
  fi

  remove_fstab_entry

  if [ -e "$SWAPFILE" ]; then
    rm -f "$SWAPFILE"
    say "✅ 已删除文件: $SWAPFILE"
  else
    say "ℹ️ 未找到文件: $SWAPFILE"
  fi

  show_status
}

show_status() {
  say "==> 当前 swap 状态："
  (swapon --show 2>/dev/null || true)
  say "---"
  (free -h 2>/dev/null || true)
}

usage() {
  cat <<EOF
用法：
  $0 add <SIZE>      添加 swap（SIZE 支持 1G / 512M / 2048(默认MB)）
  $0 del             删除 swap（关闭 + 移除 fstab + 删除 $SWAPFILE）
  $0 status          查看 swap 状态

环境变量：
  SWAPFILE=/swapfile (默认) 可自定义 swapfile 路径

示例：
  $0 add 1G
  $0 add 1024
  SWAPFILE=/data/swapfile $0 add 2G
  $0 del
EOF
}

main() {
  need_root
  ensure_tools

  cmd="${1:-}"
  case "$cmd" in
    add)
      size="${2:-}"
      if [ -z "$size" ]; then
        say "❌ 缺少 SIZE，例如：$0 add 1G"
        exit 1
      fi
      bytes="$(parse_size_to_bytes "$size")" || {
        say "❌ SIZE 格式不对：$size （支持 1G / 512M / 2048(默认MB)）"
        exit 1
      }
      create_swapfile "$bytes"
      ;;
    del|delete|remove)
      delete_swap
      ;;
    status)
      show_status
      ;;
    -h|--help|help|"")
      usage
      ;;
    *)
      say "❌ 未知命令：$cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
