#────────────────────────────── C17 kernelnet ──────────────────────────────
# 模块: 62-c17-kernelnet.sh
# 定位:上下文层 —— 内核、命名空间与网络数据面;解释 C3/C4/C5 的观测范围

check_c17() {
  hdr "C17 kernelnet · 内核、命名空间与网络数据面"

  if [ "$PLATFORM" = macos ]; then
    report INFO kernel/scope "macOS 当前主机网络视图;Linux netns/cgroup/LSM/seccomp 不适用,不据此推断未受沙箱限制"
    _ifs=$(ifconfig -l 2>/dev/null)
    if [ -n "$_ifs" ]; then
      report INFO kernel/ifaces "可见网络接口: $_ifs(utun 为隧道,不单凭接口名推断物理位置)"
    else
      report SKIP kernel/ifaces "(ifconfig 不可用/无权限)"
    fi
    if [ -n "$ROUTE_IFACE" ]; then
      report INFO kernel/routes "到探测目标的路由接口 $ROUTE_IFACE;网关 $(mask_ip "${ROUTE_GW:-未知}")"
    else
      report SKIP kernel/routes "(route 查询不可用/无路由)"
    fi
    _forward=$(sysctl -n net.inet.ip.forwarding 2>/dev/null)
    case "$_forward" in
      0|1) report INFO kernel/ip-forward "IPv4 转发=$_forward(仅拓扑角色)" ;;
      *) report SKIP kernel/ip-forward "(sysctl 不可读)" ;;
    esac
    report INFO kernel/firewall "PF 活动规则/应用防火墙/Network Extension 状态由 proxy 类采集(单项运行请用 --section proxy)"
    return
  fi

  # ── LSM ──
  _lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)
  if [ -n "$_lsm" ]; then
    report INFO kernel/lsm "LSM: $_lsm"
  elif [ -d /sys/fs/selinux ]; then
    report INFO kernel/lsm "SELinux(lsm 列表不可读,sysfs 已挂载)"
  elif [ -d /sys/kernel/security/apparmor ]; then
    report INFO kernel/lsm "AppArmor"
  else
    report SKIP kernel/lsm "(/sys/kernel/security 不可读)"
  fi

  # ── cgroup 版本 ──
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    report INFO kernel/cgroup "cgroup v2(controllers: $(head -c 100 /sys/fs/cgroup/cgroup.controllers 2>/dev/null)…)"
  elif [ -d /sys/fs/cgroup/systemd ] || [ -d /sys/fs/cgroup/blkio ]; then
    report INFO kernel/cgroup "cgroup v1"
  else
    report SKIP kernel/cgroup "(不可判定)"
  fi

  # ── seccomp(沙箱/容器旁证) ──
  _sc=$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status 2>/dev/null)
  case "${_sc:-}" in
    2) report INFO kernel/seccomp "Seccomp 过滤模式(容器/沙箱常见 —— 部分系统调用受限)" ;;
    *) report INFO kernel/seccomp "Seccomp=${_sc:-未知}(未过滤)" ;;
  esac

  # ── 网络命名空间对比(观测范围声明) ──
  _sns=$(ls -Li /proc/self/ns/net 2>/dev/null | awk '{print $1}')
  _p1ns=$(ls -Li /proc/1/ns/net 2>/dev/null | awk '{print $1}')
  if [ -n "$_sns" ] && [ -n "$_p1ns" ]; then
    if [ "$_sns" = "$_p1ns" ]; then
      report INFO kernel/netns "与 PID 1 同网络命名空间(本报告网络观测 = 宿主 netns)"
    else
      report INFO kernel/netns "与 PID 1 不同网络命名空间(隔离环境 —— 出口/路由/连接观测仅代表当前 netns)"
      NETNS_ISOLATED=1
    fi
  else
    report SKIP kernel/netns "(namespace 句柄不可读 —— /proc/1/ns 需 root,非特权运行常见)"
  fi

  # ── 接口物理性 ──
  _phys=""; _virt=""
  for _d in /sys/class/net/*; do
    [ -e "$_d" ] || continue
    _n=${_d##*/}
    [ "$_n" = "lo" ] && continue
    if [ -e "$_d/device" ]; then _phys="$_phys $_n"; else _virt="$_virt $_n"; fi
  done
  report INFO kernel/ifaces "接口分类:${_phys:+物理:$_phys}${_virt:+ 虚拟:$_virt}"

  # ── 路由全貌 ──
  if [ -r /proc/net/route ]; then
    _rl=$(wc -l < /proc/net/route | tr -d ' ')
    report INFO kernel/routes "main 表 $((_rl-1)) 条路由(多路由表/policy routing 需 iproute2)"
  fi
  if [ -r /proc/net/if_inet6 ]; then
    _r6=$(wc -l < /proc/net/if_inet6 | tr -d ' ')
    [ "$_r6" -gt 0 ] && report INFO kernel/route6 "IPv6 接口前缀 $_r6 条(if_inet6;完整 v6 路由/多表/VRF 归属需 iproute2+root)"
  fi
  # 数据面分层存在性声明(nftables/iptables;规则明细需 root,此处仅声明可见层)
  if [ -r /proc/net/ip_tables_names ] && [ -n "$(cat /proc/net/ip_tables_names 2>/dev/null)" ]; then
    report INFO kernel/iptables "iptables 表: $(cat /proc/net/ip_tables_names 2>/dev/null | tr '\n' ' ')(规则明细需 root)"
  fi
  if have nft && nft list tables >/dev/null 2>&1; then
    report INFO kernel/nftables "nftables 表 $(nft list tables 2>/dev/null | wc -l | tr -d ' ') 个(透明代理可在 nft 层;规则明细需 root)"
  fi
  if have ip; then
    _rules=$(ip rule list 2>/dev/null | grep -cvE '^(0|32766|32767):')
    if [ "${_rules:-0}" -gt 0 ]; then
      report INFO kernel/policy-routing "存在 $_rules 条非默认策略路由(代理栈/多 WAN/VRF 常见;数据面归属见 path/proxy 类)"
    fi
  fi

  # ── IP 转发(router/subnet-router 角色) ──
  if [ -r /proc/sys/net/ipv4/ip_forward ]; then
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
      report INFO kernel/ip-forward "IPv4 转发已启用(router/subnet-router/容器宿主角色;非地域信号)"
    fi
  fi
}
