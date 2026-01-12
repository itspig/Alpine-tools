#!/bin/sh
set -eu

SWAPFILE="${SWAPFILE:-/swapfile}"

say(){ printf "%s\n" "$*"; }
warn(){ printf "⚠️  %s\n" "$*" >&2; }
die(){ printf "❌ %s\n" "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" = "0" ] || die "请用 root 运行：sudo -i 或 su -"
}

ensure_tools() {
  # mkswap / swapon / swapoff / fallocate 在 util-linux
  if ! command -v mkswap >/dev/null 2>&1 || ! command -v swapon >/dev/null 2>&1; then
    say "==> 安装 util-linux（提供 mkswap/swapon/swapoff/fallocate）"
    apk add --no-cache util-linux >/dev/null
  fi
}

is_openrc() {
  command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1
}

is_swap_active() {
  [ -r /proc/swaps ] && awk 'NR>1{print $1}' /proc/swaps | grep -qx "$SWAPFILE"
}

remove_fstab_entry() {
  [ -f /etc/fstab ] || return 0
  # 删除包含 swapfile 且 type=swap 的行
  sed -i "\|^[[:space:]]*$SWAPFILE[[:space:]]\+.*[[:space:]]swap[[:space:]]|d" /etc/fstab 2>/dev/null || true
}

append_fstab_entry() {
  # 避免重复写入
  if [ ! -f /etc/fstab ] || ! grep -qE "^[[:space:]]*$SWAPFILE[[:space:]]+.*[[:space:]]swap[[:space:]]" /etc/fstab; then
    echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  fi
}

enable_swap_on_boot() {
  # Alpine + OpenRC：必须 rc-update add swap 才会开机 swapon -a   [oai_citation:2‡Alpine Linux](https://wiki.alpinelinux.org/wiki/Swap?utm_source=chatgpt.com)
  if is_openrc; then
    rc-update add swap boot >/dev/null 2>&1 || true
    # localmount 通常已在 boot；加一次无害
    rc-update add localmount boot >/dev/null 2>&1 || true
  else
    warn "未检测到 OpenRC（容器/自定义 init 常见）。这种环境重启后不会自动跑服务；请在启动脚本里手动 swapon -a 或 swapon $SWAPFILE。"
  fi
}

parse_size_to_mib() {
  # 支持：1G / 512M / 2048(默认MB) / 2g / 256m
  in="$(echo "${1:-}" | tr -d ' ')"
  [ -n "$in" ] || return 1
  if echo "$in" | grep -qiE '^[0-9]+[gG]$'; then
    n="$(echo "$in" | sed 's/[gG]//')"
    echo $((n * 1024))
  elif echo "$in" | grep -qiE '^[0-9]+[mM]$'; then
    n="$(echo "$in" | sed 's/[mM]//')"
    echo "$n"
  elif echo "$in" | grep -qE '^[0-9]+$'; then
    # 纯数字：按 MB
    echo "$in"
  else
    return 1
  fi
}

show_status() {
  say "==> 当前 swap 状态："
  swapon --show 2>/dev/null || true
  say "---"
  free -h 2>/dev/null || true
  say "---"
  if [ -f /etc/fstab ]; then
    say "==> /etc/fstab 中与 swapfile 相关条目："
    grep -nE "^[[:space:]]*$SWAPFILE[[:space:]]+.*[[:space:]]swap[[:space:]]" /etc/fstab || true
  fi
  if is_openrc; then
    say "==> OpenRC 启动项（swap）："
    rc-update show 2>/dev/null | grep -E '^swap' || true
  fi
}

create_swapfile() {
  mib="$1"

  if [ -e "$SWAPFILE" ]; then
    warn "$SWAPFILE 已存在：将先尝试 swapoff + 删除后重建"
    delete_swap || true
  fi

  say "==> 创建 swapfile: $SWAPFILE (${mib}MiB)"

  # 创建文件
  if command -v fallocate >/dev/null 2>&1; then
    if ! fallocate -l "${mib}M" "$SWAPFILE" 2>/dev/null; then
      warn "fallocate 失败，改用 dd（可能较慢）"
      dd if=/dev/zero of="$SWAPFILE" bs=1M count="$mib" status=progress
    fi
  else
    dd if=/dev/zero of="$SWAPFILE" bs=1M count="$mib" status=progress
  fi

  chmod 600 "$SWAPFILE"

  # 格式化并启用
  mkswap "$SWAPFILE" >/dev/null
  append_fstab_entry
  enable_swap_on_boot

  # 先直接启用一次
  if ! swapon "$SWAPFILE" 2>/dev/null; then
    warn "swapon $SWAPFILE 失败。常见原因：overlayfs/btrfs/nocow/文件系统不支持 swapfile。将回滚删除该文件并清理 fstab。"
    remove_fstab_entry
    rm -f "$SWAPFILE" || true
    die "swap 启用失败，已回滚。"
  fi

  # 再执行 swapon -a 验证 fstab 路径可用
  swapon -a 2>/dev/null || true

  say "✅ swap 已启用，并已配置开机自动启用（如有 OpenRC）"
  show_status
}

fix_persist() {
  say "==> 修复：确保重启后 swap 自动启用"
  [ -e "$SWAPFILE" ] || die "未找到 $SWAPFILE（先用：$0 add 1G 创建）"

  append_fstab_entry
  enable_swap_on_boot

  # 尝试启用
  if is_swap_active; then
    say "✅ 当前 swap 已是 active，无需再次 swapon"
  else
    if swapon -a 2>/dev/null; then
      say "✅ 已执行 swapon -a（基于 /etc/fstab）"
    else
      warn "swapon -a 失败，尝试 swapon $SWAPFILE"
      swapon "$SWAPFILE" || die "swapon 失败：请检查文件系统是否支持 swapfile（容器/overlayfs/btrfs 常见问题）"
    fi
  fi

  show_status
}

delete_swap() {
  say "==> 删除 swap（关闭 + 移除 fstab + 删除文件以释放磁盘）"

  if is_swap_active; then
    swapoff "$SWAPFILE" || true
    say "✅ 已 swapoff: $SWAPFILE"
  else
    say "ℹ️ swap 未处于 active 状态（或不是 $SWAPFILE）"
  fi

  remove_fstab_entry

  if [ -e "$SWAPFILE" ]; then
    rm -f "$SWAPFILE"
    say "✅ 已删除文件: $SWAPFILE（磁盘空间已释放）"
  else
    say "ℹ️ 未找到文件: $SWAPFILE"
  fi

  show_status
}

usage() {
  cat <<EOF
用法：
  $0 add <SIZE>     创建并启用 swapfile（SIZE 支持 1G / 512M / 2048(默认MB)）
  $0 fix            修复“重启后不生效”（补写 fstab + rc-update add swap + swapon -a）
  $0 del            关闭 swap + 移除 fstab + 删除 $SWAPFILE（释放磁盘）
  $0 status         查看 swap 状态

环境变量：
  SWAPFILE=/swapfile   (默认) 可自定义 swapfile 路径

示例：
  $0 add 1G
  $0 fix
  $0 del
  SWAPFILE=/data/swapfile $0 add 2G
EOF
}

main() {
  need_root
  ensure_tools

  cmd="${1:-}"
  case "$cmd" in
    add)
      size="${2:-}"
      mib="$(parse_size_to_mib "$size")" || die "SIZE 格式不对：$size（支持 1G / 512M / 2048(默认MB)）"
      create_swapfile "$mib"
      ;;
    fix)
      fix_persist
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
      die "未知命令：$cmd（用 $0 help 查看）"
      ;;
  esac
}

main "$@"
