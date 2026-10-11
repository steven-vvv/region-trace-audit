#────────────────────────────── C3 egress ──────────────────────────────
# 模块: 52-c3-egress.sh

check_c3() {
  hdr "C3 egress · 出口与 GeoIP(active-probe)"

  if [ "$OFFLINE" = 1 ]; then
    report SKIP egress/all "(--offline:跳过外联探测)"
    return
  fi
  if [ -z "$HTTP_TOOL" ]; then
    report SKIP egress/all "(缺 curl/wget)"
    return
  fi

  _ann=""; [ -n "$NET_ANNOT" ] && _ann=" · $NET_ANNOT"

  # ── IPv4 出口(主源 ip-api + 备源 ipinfo 双源交叉) ──
  _j=$(http_get "http://ip-api.com/json/?fields=status,message,country,countryCode,org,as,reverse,hosting,proxy,query,timezone")
  _cc=$(jf countryCode "$_j"); _ip=$(jf query "$_j")
  if [ -n "$_cc" ]; then
    _j2=$(http_get "https://ipinfo.io/json")
    _cc2=$(jf country "$_j2")
    _conf="单源"
    if [ -n "$_cc2" ]; then
      if [ "$_cc" = "$_cc2" ]; then _conf="双源一致"; else _conf="双源不一致($_cc/$_cc2)"; fi
    fi
    _kind=$([ "$(jf hosting "$_j")" = "true" ] && printf 'IDC/机房' || printf '非机房')
    [ "$(jf proxy "$_j")" = "true" ] && _kind="$_kind(被标记为代理)"
    report INFO egress/ipv4 "出口 IPv4 $(mask_ip "$_ip") · $(jf country "$_j")($_cc) · $(jf org "$_j" | cut -c1-36) · $_kind · 置信度: $_conf$_ann"
    EGRESS_CC=$_cc; EGRESS_TZ=$(jf timezone "$_j")
    case "$_cc" in
      CN|HK|MO)
        if [ "$_cc" = "$_cc2" ]; then
          report EXPOSED egress/ipv4-country "出口 IPv4 位于$(cnname "$_cc") —— 网络位置实锤(双源一致)"
        elif [ -n "$_cc2" ]; then
          report SUSPICIOUS egress/ipv4-country "主源判出口位于$(cnname "$_cc")但备源(ipinfo)判 $_cc2 —— 双源不一致,证据降级(单源结果可被链路篡改,建议复核)"
        else
          report SUSPICIOUS egress/ipv4-country "出口 IPv4 位于$(cnname "$_cc")(仅单源命中,无交叉确认;证据降级)"
        fi ;;
    esac
    _rev=$(jf reverse "$_j")
    if [ -n "$_rev" ]; then
      if printf '%s' "$_rev" | grep -qiE 'chinanet|china[- ]?telecom|china[- ]?unicom|china[- ]?mobile|cmcc|crtc|cstnet'; then
        report EXPOSED egress/rdns "出口 rDNS 含 CN 运营商命名($_rev)"
      elif printf '%s' "$_rev" | grep -qiE '\.(cn|hk)$'; then
        report EXPOSED egress/rdns "出口 rDNS 为 .cn/.hk 后缀($_rev)"
      fi
    fi
  else
    # 备源接管
    _j2=$(http_get "https://ipinfo.io/json")
    _ip=$(jf ip "$_j2"); _cc=$(jf country "$_j2")
    if [ -n "$_cc" ]; then
      report INFO egress/ipv4 "出口 IPv4 $(mask_ip "$_ip") · $_cc(备源 ipinfo) · $(jf org "$_j2" | cut -c1-36)$_ann"
      EGRESS_CC=$_cc; EGRESS_TZ=$(jf timezone "$_j2")
      case "$_cc" in
        CN|HK|MO) report EXPOSED egress/ipv4-country "出口 IPv4 位于$(cnname "$_cc") —— 网络位置实锤" ;;
      esac
    else
      report SKIP egress/ipv4 "(GeoIP 查询失败)"
    fi
  fi

  # ── IPv6 出口(双栈遗漏检测) ──
  _v6=$(http_get6 "https://api64.ipify.org")
  case "$_v6" in
    *:*)
      _g6=$(geoip1 "$_v6")
      if [ "${_g6%%|*}" = "ERR" ] || [ -z "${_g6%%|*}" ]; then
        report SKIP egress/ipv6 "(IPv6 出口 GeoIP 查询失败)"
      else
        _cc6=${_g6%%|*}; EGRESS_CC6=$_cc6
        report INFO egress/ipv6 "出口 IPv6 $(mask_ip "$_v6") · $(printf '%s' "$_g6" | cut -d'|' -f2)($_cc6)$_ann"
        case "$_cc6" in
          CN|HK|MO) report EXPOSED egress/ipv6-country "出口 IPv6 位于$(cnname "$_cc6")" ;;
        esac
        if [ -n "$_cc" ] && [ "$_cc6" != "$_cc" ]; then
          case "${_cc}${_cc6}" in
            *CN*|*HK*|*MO*) report EXPOSED egress/dual-stack "v4($_cc) 与 v6($_cc6) 出口不一致且含陆港澳 —— 双栈分流痕迹" ;;
            *) report SUSPICIOUS egress/dual-stack "v4/v6 出口国家不一致($_cc/$_cc6,分流或配置错配)" ;;
          esac
        fi
      fi ;;
    *.*) report INFO egress/ipv6 "IPv6 公网出口不可用(api64 回落至 v4)" ;;
    *)   report SKIP egress/ipv6 "(IPv6 出口探测失败)" ;;
  esac

  # ── 连接图谱 GeoIP(--deep-geo) ──
  if [ "$DEEP_GEO" = 1 ]; then
    deep_geo_scan
  else
    report SKIP egress/deep-geo "(默认关闭;--deep-geo 可对 known_hosts 与活跃连接对端做 GeoIP)"
  fi
}

deep_geo_scan() {
  _peers=""
  [ "$PLATFORM" != macos ] && [ -r /proc/net/tcp ] && _peers=$(awk '$4=="01"{split($3,r,":"); print r[1]}' /proc/net/tcp 2>/dev/null | tr '\n' ' ')
  # tcp6:仅纳入 v4-mapped 对端(ip-api 批量仅支持 IPv4;原生 v6 对端不外发,注记见输出)
  [ "$PLATFORM" != macos ] && [ -r /proc/net/tcp6 ] && _peers="$_peers $(awk 'function d(x){v=0;for(i=1;i<=length(x);i++){v=v*16+index("0123456789ABCDEF",substr(x,i,1))-1}return v} $4=="01"{split($3,r,":"); if (substr(r[1],1,16)=="0000000000000000" && substr(r[1],17,8)=="FFFF0000") print d(substr(r[1],31,2))"."d(substr(r[1],29,2))"."d(substr(r[1],27,2))"."d(substr(r[1],25,2))}' /proc/net/tcp6 2>/dev/null | tr '\n' ' ')"
  if [ "$PLATFORM" = macos ]; then
    mac_socket_context
    _mp=$(printf '%s\n' "$MAC_SOCKETS" | awk -F'|' '$3=="ESTABLISHED" {print $5}')
    while IFS= read -r _ep; do
      [ -n "$_ep" ] || continue
      _mi=$(mac_endpoint_ip "$_ep")
      # The existing batch provider accepts IPv4 only; do not send IPv6 as hex IPv4.
      case "$_mi" in *:*) ;; *.*) _peers="$_peers $_mi" ;; esac
    done <<EOF_MAC_PEERS
$_mp
EOF_MAC_PEERS
  fi
  _kh="$HOME/.ssh/known_hosts"
  if [ -r "$_kh" ]; then
    _peers="$_peers $(awk '{print $1}' "$_kh" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | head -n 30 | tr '\n' ' ')"
  fi
  _uniq=""; _n=0
  for _h in $_peers; do
    _ip=""
    case "$_h" in
      *.*) _ip=$_h ;;
      *) [ ${#_h} -eq 8 ] && _ip=$(hex2ip "$_h") ;;
    esac
    [ -z "$_ip" ] && continue
    case " $_uniq " in *" $_ip "*) continue ;; esac
    ip_is_private "$_ip" && continue
    _uniq="$_uniq $_ip"; _n=$((_n+1))
    [ "$_n" -ge 90 ] && break
  done
  if [ "$_n" -eq 0 ]; then
    report SKIP egress/deep-geo "(无待查公网对端)"
    return
  fi
  _body="["; _f1=1
  for _i in $_uniq; do [ "$_f1" = 1 ] && _f1=0 || _body="$_body,"; _body="$_body\"$_i\""; done
  _body="$_body]"
  _r=$(http_post "http://ip-api.com/batch?fields=status,countryCode" "$_body")
  if [ -z "$_r" ]; then
    report SKIP egress/deep-geo "(批量查询失败)"
    return
  fi
  _sum=$(printf '%s' "$_r" | awk -v ips="$(printf '%s' "$_uniq" | tr '\n' ' ')" '{
    gsub(/\},[ ]*\{/, "\n"); n=split($0, recs, /\n/)
    ni=split(ips, IP, " ")
    cn=0; other=0; reg=""
    for(i=1;i<=n;i++){
      if (recs[i] !~ /"status":"success"/) continue
      cc=""
      if (match(recs[i], /"countryCode":"[A-Z][A-Z]"/)) cc=substr(recs[i], RSTART+16, 2)
      if (i<=ni && IP[i]!="") reg=reg " " IP[i] "=" cc
      if (cc ~ /^(CN|HK|MO)$/) cn++; else other++
    }
    printf "%d %d\n%s\n", cn, other, reg
  }')
  _dgreg=$(printf '%s' "$_sum" | sed -n '2p')
  [ -n "$_dgreg" ] && DG_IPCC="$_dgreg"
  _cn=$(printf '%s' "$_sum" | sed -n '1p' | awk '{print $1}')
  _ot=$(printf '%s' "$_sum" | sed -n '1p' | awk '{print $2}')
  case "$_cn" in ''|*[!0-9]*) _cn=0 ;; esac
  case "$_ot" in ''|*[!0-9]*) _ot=0 ;; esac
  if [ "$_cn" -gt 0 ]; then
    report SUSPICIOUS egress/deep-geo "活跃连接/known_hosts 中 $_cn 个对端 IP 归属陆港澳(共查 $((_cn+_ot)) 个,仅统计 IPv4;亦可能为正常业务)"
  else
    report CLEAN egress/deep-geo "已查 $((_cn+_ot)) 个对端 IP,无陆港澳归属(仅统计 IPv4)"
  fi
}
