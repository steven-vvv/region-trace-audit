#────────────────────────────── C4 path ──────────────────────────────
# 模块: 53-c4-path.sh

check_c4() {
  hdr "C4 path · 链路、路由与本地网络"

  # ── 网关 MAC OUI(启发式,弱证据;VPS 虚拟网关自然不命中) ──
  _mac=""; _arp_available=0
  if [ "$PLATFORM" = macos ] && [ -n "$ROUTE_GW" ]; then
    if _arp=$(arp -n "$ROUTE_GW" 2>/dev/null); then
      _arp_available=1
      _mac=$(printf '%s\n' "$_arp" | awk '{for(i=1;i<NF;i++) if($i=="at" && $(i+1) ~ /^[0-9a-fA-F:]+$/) print $(i+1)}' |
        awk -F: 'NF==6 {for(i=1;i<=6;i++){if(length($i)==1)$i="0"$i}; print toupper($1":"$2":"$3":"$4":"$5":"$6)}')
    fi
  elif [ -n "$ROUTE_GW" ] && [ -r /proc/net/arp ]; then
    _arp_available=1
    _mac=$(awk -v g="$ROUTE_GW" '$1==g{print toupper($4); exit}' /proc/net/arp 2>/dev/null)
  fi
  if [ "$_arp_available" = 1 ]; then
    if [ -n "$_mac" ]; then
      _oui=$(printf '%s' "$_mac" | cut -d: -f1-3)
      case " $GW_OUI_CN_LIST " in
        *" $_oui "*)
          report SUSPICIOUS path/gw-oui "默认网关 MAC OUI=$_oui 命中国内网络设备厂商表(启发式,弱证据)" ;;
        *)
          report INFO path/gw-oui "网关 $(mask_ip "$ROUTE_GW") 的 ARP 项 OUI=$_oui(未命中国内设备表)" ;;
      esac
    else
      report SKIP path/gw-oui "(ARP 表无网关条目)"
    fi
  else
    report SKIP path/gw-oui "(无默认网关/ARP 缓存不可读;macOS 使用 arp -n,隧道接口可能无 ARP)"
  fi

  # ── MTU ──
  _mtu=""
  if [ "$PLATFORM" = macos ] && [ -n "$ROUTE_IFACE" ]; then
    _mtu=$(ifconfig "$ROUTE_IFACE" 2>/dev/null | awk 'NR==1{for(i=1;i<NF;i++)if($i=="mtu")print $(i+1)}')
  elif [ -n "$ROUTE_IFACE" ] && [ -r "/sys/class/net/$ROUTE_IFACE/mtu" ]; then
    _mtu=$(cat "/sys/class/net/$ROUTE_IFACE/mtu" 2>/dev/null)
  fi
  if [ -n "$_mtu" ]; then
    case "$_mtu" in
      1492|1488|1480) report SUSPICIOUS path/mtu "出口接口 $ROUTE_IFACE MTU=$_mtu(PPPoE 线路特征)" ;;
      *) report INFO path/mtu "出口接口 $ROUTE_IFACE MTU=$_mtu" ;;
    esac
  fi

  # ── CGNAT ──
  case "$ROUTE_SRC" in
    100.6[4-9].*|100.7[0-9].*|100.8[0-9].*|100.9[0-9].*|100.1[01][0-9].*|100.12[0-7].*)
      report SUSPICIOUS path/cgnat "本机源地址 $ROUTE_SRC 位于 CGNAT 段 100.64.0.0/10(运营商级 NAT,国内移动网络常见)" ;;
  esac

  # ── traceroute CN 骨干检测(active-probe) ──
  if [ "$OFFLINE" = 1 ]; then
    report SKIP path/trace "(--offline:跳过外联探测)"
    return
  fi
  # stdbuf -oL:强制行缓冲 —— tracepath 管道下为块缓冲,被看门狗强杀会丢失已输出内容
  _pre=""
  have stdbuf && _pre="stdbuf -oL"
  _tr=""
  if have traceroute; then _tr="traceroute -n -q 1 -w 1 -m 18"
  elif have tracepath; then _tr="tracepath -n -m 15"
  elif have busybox && busybox traceroute 2>&1 | head -n 1 | grep -qi usage; then _tr="busybox traceroute -n -q 1 -w 1 -m 18"
  fi
  if [ -z "$_tr" ]; then
    report SKIP path/trace "(缺 traceroute/tracepath)"
    return
  fi
  # 注:GNU timeout 与 tracepath 信号处理不兼容(实测空输出),
  # 改用「后台运行 + 看门狗强杀」限时;CN 骨干通常出现在近端 hop,部分结果即可判定
  _run_bounded() { # $1=限时秒 其余=命令
    _secs=$1; shift
    "$@" 2>/dev/null &
    _tp=$!
    ( sleep "$_secs" && kill -9 "$_tp" 2>/dev/null ) &
    _wd=$!
    wait "$_tp" 2>/dev/null
    kill -9 "$_wd" 2>/dev/null
    wait "$_wd" 2>/dev/null
  }
  _hops=""
  for _a in 1.1.1.1 8.8.8.8; do
    _hops="$_hops $(_run_bounded 12 $_pre $_tr "$_a" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v "^$_a$")"
  done
  _pub=""; _seen=""
  for _h in $_hops; do
    case " $_seen " in *" $_h "*) continue ;; esac
    _seen="$_seen $_h"
    ip_is_private "$_h" && continue
    _pub="$_pub $_h"
  done
  _npub=$(printf '%s' "$_pub" | wc -w | tr -d ' ')
  if [ "${_npub:-0}" -lt 2 ]; then
    report SKIP path/trace "(沿途公网 hop 不足($_npub 个),无法判定)"
    return
  fi
  _body="["; _f1=1
  for _i in $_pub; do [ "$_f1" = 1 ] && _f1=0 || _body="$_body,"; _body="$_body\"$_i\""; done
  _body="$_body]"
  _r=$(http_post "http://ip-api.com/batch?fields=status,query,countryCode,as" "$_body")
  if [ -z "$_r" ]; then
    report SKIP path/trace "(批量 GeoIP 查询失败)"
    return
  fi
  _sum=$(printf '%s' "$_r" | awk '{
    gsub(/\},[ ]*\{/, "\n"); n=split($0, recs, /\n/)
    cn=0; cnips=""; hk=0; other=0
    for(i=1;i<=n;i++){
      r=recs[i]
      if (r !~ /"status":"success"/) continue
      cc=""; if (match(r, /"countryCode":"[A-Z][A-Z]"/)) cc=substr(r, RSTART+16, 2)
      as=""; if (match(r, /"as":"[^"]*"/)) as=substr(r, RSTART+6, RLENGTH-7)
      ip=""; if (match(r, /"query":"[^"]*"/)) ip=substr(r, RSTART+9, RLENGTH-10)
      if (cc=="CN" || as ~ /^AS(4134|4808|4837|9808|9929|58453|23724|4538)([^0-9]|$)/ || ip ~ /^202\.97\./ || ip ~ /^219\.158\./) {
        cn++
        if (cn<=3) cnips=cnips" "ip
      } else if (cc=="HK" || cc=="MO") hk++
      else other++
    }
    printf "%d %d %d %s\n", cn, hk, other, cnips
  }')
  set -- $_sum
  _cn=$1; _hk=$2; _oth=$3; _cni=$(shift 3; printf '%s' "$*" | sed 's/^ //')
  case "$_cn" in ''|*[!0-9]*) _cn=0 ;; esac
  if [ "$_cn" -gt 0 ]; then
    report EXPOSED path/trace-cn "路由经过中国骨干网:$(printf '%s' "$_cni" | tr ' ' ',') 等 $_cn 个 hop(AS4134 电信/4808·4837 联通/9808 移动/CMI/CERNET/202.97·219.158 段)—— 物理链路经过中国大陆"
  else
    report CLEAN path/trace-cn "沿途 $_oth 个公网 hop,无 CN 骨干网痕迹"
  fi
  _hk_n=0
  case "${_hk:-0}" in ''|*[!0-9]*) ;; *) _hk_n=$_hk ;; esac
  [ "$_hk_n" -gt 0 ] && report INFO path/trace-hk "路径经香港中转($_hk_n 个 hop,亚太路由常见)"
}
