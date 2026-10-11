#────────────────────────────── C5 proxy ──────────────────────────────
# 模块: 54-c5-proxy.sh

check_c5() {
  hdr "C5 proxy · 代理、隧道、分流与覆盖网络"

  _ps=$(ps_filtered)

  # ── env 代理变量(掩码凭据) ──
  _pe=0
  for _v in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
    eval "_val=\${$_v:-}"
    if [ -n "$_val" ]; then
      report INFO proxy/env "$_v=$(printf '%s' "$_val" | sed 's|\(//[^@/]*\)@|//<凭据已掩码>@|')"
      _pe=1
    fi
  done
  [ "$_pe" = 0 ] && report CLEAN proxy/env "无代理环境变量"

  # ── 接口分类 ──
  _vpn=""; _cni=""
  if [ "$PLATFORM" = macos ]; then _ifnames=$(ifconfig -l 2>/dev/null)
  else _ifnames=$(ls /sys/class/net 2>/dev/null); fi
  for _i in $_ifnames; do
    case "$_i" in
      lo|eth*|ens*|enp*|eno*|enx*|wlan*|wlp*|wwan*|wwp*|bond*|br0|usb*) : ;;
      utun*|tun*|tap*|wg*|tailscale*|zt*|nordlynx*|ppp*|CloudflareWARP*|warp*) _vpn="$_vpn $_i" ;;
      docker*|veth*|br-*|cni*|cali*|flannel*|weave*|kube*|virbr*|dummy*|podman*) _cni="$_cni $_i" ;;
    esac
  done
  [ -n "$_vpn" ] && report INFO proxy/vpn-iface "VPN/隧道接口:$_vpn"
  [ -n "$_cni" ] && report INFO proxy/cni-iface "容器/桥接接口:$_cni"
  for _i in $_vpn; do
    case "$_i" in ppp*) report SUSPICIOUS proxy/pppoe "PPPoE 会话接口 $_i(拨号线路特征)" ;; esac
  done
  case "$ROUTE_IFACE" in
    utun*|tun*|tap*|wg*|ppp*|tailscale*)
      report INFO proxy/default-route "默认路由经隧道接口 $ROUTE_IFACE(出口探测经此接口)" ;;
    *) report INFO proxy/default-route "默认路由接口: ${ROUTE_IFACE:-未知}" ;;
  esac

  # ── 代理栈进程 ──
  _pproc=$(printf '%s' "$_ps" | grep -oE "$PROXY_PROC_RE" | sort -u | tr '\n' ' ')
  [ -n "$_pproc" ] && report INFO proxy/stack-proc "代理栈进程(active): $_pproc"

  # ── clash/mihomo 订阅节点命名 ──
  for _d in "$HOME/.config/clash" "$HOME/.config/mihomo" "$HOME/.config/clash-verge" /etc/clash /etc/mihomo; do
    [ -d "$_d" ] || continue
    _n=$(grep -rhoE '沪|京|深|穗|蓉|港|IPLC|IEPL|家宽|专线|回国' "$_d" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${_n:-0}" -gt 0 ]; then
      report SUSPICIOUS proxy/clash-nodes "$_d 配置含国内订阅节点命名特征 x$_n(沪/港/IPLC/家宽等)"
    fi
  done

  # ── 透明代理/分流规则(需 root;无权限时跳过) ──
  if [ "$PLATFORM" = macos ]; then
    mac_check_firewall
  elif have iptables && iptables -t nat -L -n >/dev/null 2>&1; then
    if iptables -t nat -L -n 2>/dev/null | grep -qE 'REDIRECT|TPROXY'; then
      report SUSPICIOUS proxy/transparent "iptables NAT 表含 REDIRECT/TPROXY(透明代理/分流)"
    fi
    if iptables -L -n 2>/dev/null | grep -qiE 'chnroute|china'; then
      report SUSPICIOUS proxy/chnroute "iptables 含 CN 直连分流规则集(chnroute)"
    fi
  else
    report SKIP proxy/iptables "(缺权限或未安装 iptables,透明代理规则无法核查)"
  fi
  if have nft && nft list ruleset >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -qE 'redirect|tproxy'; then
      report SUSPICIOUS proxy/transparent "nftables 含 redirect/tproxy(透明代理/分流)"
    fi
  fi

  # ── DNS 分流配置 ──
  for _f in /etc/dnsmasq.conf /etc/dnsmasq.d /etc/smartdns/smartdns.conf; do
    [ -e "$_f" ] || continue
    if grep -rqE '114\.114\.114\.114|223\.5\.5\.5|119\.29\.29\.29' "$_f" 2>/dev/null; then
      report SUSPICIOUS proxy/dns-split "$_f 国内域名指向国内公共 DNS(分流配置)"
    fi
  done

  # ── Tailscale(local-daemon 只读) ──
  if ls /sys/class/net 2>/dev/null | grep -qx 'tailscale0' || printf '%s' "$_ps" | grep -q 'tailscaled'; then
    report INFO proxy/tailscale "Tailscale 运行中(Mesh 内虚拟地址不做地理归属)"
    OVERLAY_BREAKS="$OVERLAY_BREAKS Tailscale-mesh"
    case "$ROUTE_IFACE" in tailscale*) report INFO proxy/tailscale "默认路由经 tailscale0 —— 正在使用 exit node" ;; esac
    if have tailscale; then
      _tsst=$(tailscale status 2>/dev/null)
      if printf '%s' "$_tsst" | grep -q 'exit node'; then
        report INFO proxy/tailscale "status 含 exit node 条目(提供或使用 exit node)"
      fi
      _tpn=$(printf '%s' "$_tsst" | grep -cE '^[a-z0-9_.-]+@[a-z0-9_.-]+:' || true)
      if [ "${_tpn:-0}" -gt 0 ]; then
        _tdir=$(printf '%s' "$_tsst" | grep -c 'direct' || true)
        report INFO proxy/tailscale "mesh peers $_tpn 个(其中 direct 连接 ${_tdir:-0} 个,余经 DERP 中继;地址不输出)—— 中继后对端位置不可直接观察"
      fi
    fi
  fi

  # ── cloudflared / WARP ──
  if printf '%s' "$_ps" | grep -q 'cloudflared'; then
    _n=0
    for _f in /etc/cloudflared/config.yml "$HOME/.cloudflared/config.yml"; do
      if [ -r "$_f" ]; then _x=$(grep -c 'hostname:' "$_f" 2>/dev/null) || true; _x=${_x:-0}; _n=$((_n+_x)); fi
    done
    report INFO proxy/cloudflared "cloudflared 出站 Tunnel 运行中(ingress $_n 条;凭据不读取;不改变默认出口,不作 VPN 证据)"
    OVERLAY_BREAKS="$OVERLAY_BREAKS Cloudflare-Tunnel(入站)"
  fi
  if printf '%s' "$_ps" | grep -q 'warp-svc' || [ -d /var/lib/CloudflareWARP ]; then
    case "$ROUTE_IFACE" in
      CloudflareWARP*|warp*) report INFO proxy/warp "Cloudflare WARP 运行中,默认路由经 WARP 接口(出口探测实际走 WARP)" ;;
      *) report INFO proxy/warp "Cloudflare WARP 客户端存在(默认路由未经过 WARP;可能仅 DNS 接管/备用;enrollment 数据不读取)" ;;
    esac
  fi

  # ── 通用 mesh / 反向隧道 / proxychains ──
  _mesh=$(printf '%s' "$_ps" | grep -oE 'zerotier-one|nebula|netbird|strongswan|openvpn' | sort -u | tr '\n' ' ')
  [ -n "$_mesh" ] && report INFO proxy/mesh "mesh/VPN daemon(active): $_mesh"
  _rt=$(printf '%s' "$_ps" | grep -oE 'autossh|frpc|frps|ngrok' | sort -u | tr '\n' ' ')
  [ -n "$_rt" ] && report INFO proxy/reverse-tunnel "反向隧道进程(active): $_rt(入站来源被隧道遮蔽,操作者链路不可直接观察)"
  for _f in /etc/proxychains.conf "$HOME/.proxychains/proxychains.conf"; do
    [ -r "$_f" ] && report INFO proxy/proxychains "proxychains 配置存在($_f)"
  done
}
