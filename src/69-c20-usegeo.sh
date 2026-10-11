#────────────────────────────── C20 usegeo ──────────────────────────────
# 模块: 69-c20-usegeo.sh
# 定位:实际使用地区融合视图 —— 消费 C1–C19 全局证据,输出会话链/出口/链路断点/家族融合
# 原则:冲突链保留(两端都报),不强行归因;中继后不可观察 → 链断点声明

check_c20() {
  hdr "C20 usegeo · 实际使用地区融合视图"

  # ── u1/u2:会话链(本地 seat / 远程入口 / 控制端) ──
  _v=""
  _v="$_v- 当前本地交互会话:${SESS_LOCAL_N:-未知} 个(seat/console)"
  _nrem=0; _remlist=""
  for _h in ${SESS_REMOTES:-}; do
    _nrem=$((_nrem+1))
    _remlist="$_remlist $(mask_ip "$_h")"
  done
  if [ "$_nrem" -gt 0 ]; then
    if [ "$DEEP_GEO" = 1 ]; then
      _v="$_v
- 当前远程交互会话:$_nrem 个(来源已脱敏:$_remlist;GeoIP 已随 --deep-geo 连接图谱查询,命中见下)"
    else
      _v="$_v
- 当前远程交互会话:$_nrem 个(来源已脱敏:$_remlist;GeoIP:自身会话见下,其余归 --deep-geo)"
    fi
  else
    _v="$_v
- 当前远程交互会话:登录记录中未识别(不排除不可见会话)"
  fi
  if [ -n "${SELF_PEER_CC:-}" ]; then
    case "$SELF_PEER_CC" in
      CN|HK|MO) _v="$_v
  · 自身会话控制端位于$(cnname "$SELF_PEER_CC")(controller-net 实锤,已列暴露)" ;;
      *) _v="$_v
  · 自身会话控制端 GeoIP:$(cnname "$SELF_PEER_CC" 2>/dev/null || printf '%s' "$SELF_PEER_CC")" ;;
    esac
  elif [ -n "${SELF_PEER:-}" ]; then
    _v="$_v
  · 自身会话控制端 $(mask_ip "$SELF_PEER")(GeoIP 未查/offline)"
  else
    _v="$_v
  · 当前采集进程未提供 SSH 对端环境变量(不代表主机无 SSH 会话)"
  fi
  if [ "$PLATFORM" = macos ] && [ "${MAC_SSH_PEER_N:-0}" -gt 0 ]; then
    _v="$_v
  · 可见 sshd 进程的活动 TCP 对端 ${MAC_SSH_PEER_N} 个(可含转发,不计入交互登录数量)"
  fi
  # deep-geo 会话对端命中
  _dghit=""
  for _h in ${SESS_REMOTES:-}; do
    case " ${DG_IPCC:-} " in
      *" $_h="*) _cc=$(printf '%s' " $DG_IPCC " | sed "s/.* ${_h}=\\([A-Z][A-Z]\\) .*/\\1/" | awk '{print $1}')
        case "${_cc:-}" in
          CN|HK|MO) _dghit="$_dghit $(mask_ip "$_h")=$(cnname "$_cc")" ;;
        esac ;;
    esac
  done
  has_text "$_dghit" && _v="$_v
  · deep-geo:远程会话对端命中陆港澳:$_dghit"
  if [ "$DEEP_GEO" = 1 ] && ! has_text "$_dghit" && [ "$_nrem" -gt 0 ]; then
    _v="$_v
  · deep-geo:远程会话对端无陆港澳命中"
  fi

  # ── 出口(netns 注记) ──
  _v="$_v
- 被审计工作负载出口:IPv4 $(cnname "${EGRESS_CC:-XX}" 2>/dev/null || printf '%s' "${EGRESS_CC:-未测}")"
  [ -n "${EGRESS_CC6:-}" ] && _v="$_v · IPv6 $(cnname "$EGRESS_CC6" 2>/dev/null || printf '%s' "$EGRESS_CC6")"
  case "${EGRESS_TZ:-}" in "") ;; *) _v="$_v(出口时区 $EGRESS_TZ)" ;; esac
  [ "${NETNS_ISOLATED:-0}" = 1 ] && _v="$_v;注意:与 PID1 netns 隔离,观测仅代表当前 netns"

  # ── u4:物理接入网络(--radio) ──
  _v="$_v
- 物理接入网络(--radio):${RADIO_ACCESS:-未启用或不可用}"

  # ── u3:链路断点声明 ──
  _bp="${OVERLAY_BREAKS:-}"
  [ "${NETNS_ISOLATED:-0}" = 1 ] && _bp="$_bp 容器/独立 netns"
  if [ -r "$HOME/.ssh/config" ]; then
    _pjn=$(grep -ciE '^[[:space:]]*(proxyjump|proxycommand)' "$HOME/.ssh/config" 2>/dev/null || true)
    [ "${_pjn:-0}" -gt 0 ] && _bp="$_bp ssh ProxyJump/ProxyCommand x$_pjn(跳板链)"
  fi
  has_text "$RD_CONNECTED" && _bp="$_bp 远控会话(${RD_CONNECTED})"
  if has_text "$_bp"; then
    _v="$_v
- 链路断点:$(printf '%s' "$_bp" | sed 's/^ *//')—— 实际操作者位置在这些链路后不可直接观察,保留全部旁证"
  else
    _v="$_v
- 链路断点:未识别(不代表不存在中继)"
    [ "$PLATFORM" = macos ] && _v="$_v;macOS socket 归属限于 lsof 可见进程,远控 TCP 传输不等同交互控制"
  fi

  # ── u7:家族融合与冲突链 ──
  # 独立家族:controller-net(会话控制端)/ host-egress(出口)/ host-config(时区/locale/作息/日历)/ local-access-net(--radio)
  _fam=""
  case "${SELF_PEER_CC:-}" in CN|HK|MO) _fam="$_fam controller-net" ;; esac
  case "${EGRESS_CC:-}" in CN|HK|MO) _fam="$_fam host-egress" ;; esac
  case "${TZ_CLASS:-}" in CN|HKMO) _fam="$_fam host-config(时区)" ;; esac
  [ "${LOCALE_ZH:-0}" = 1 ] && _fam="$_fam host-config(locale)"
  [ "${TZ_INFER_E8:-no}" = yes ] && [ "${TZ_CLASS:-}" != CN ] && [ "${TZ_CLASS:-}" != HKMO ] && \
    _fam="$_fam host-config(作息)"
  case "$RADIO_ACCESS_CC" in CN|HK|MO) _fam="$_fam local-access-net" ;; esac
  _nf=$(printf '%s' "$_fam" | wc -w | tr -d ' ')

  # 冲突链:出口非陆港澳 vs 配置/作息指向陆港澳(两端都保留,已分别列可疑/暴露)
  _conflict=""
  case "${EGRESS_CC:-}" in
    ""|CN|HK|MO) ;;
    *)
      case "${TZ_CLASS:-}" in CN|HKMO) _conflict="海外出口($EGRESS_CC)+ 陆港澳时区" ;; esac
      [ -z "$_conflict" ] && [ "${TZ_INFER_E8:-no}" = yes ] && _conflict="海外出口($EGRESS_CC)+ 作息东亚段指向东八"
      [ -z "$_conflict" ] && [ "${SELF_PEER_CC:-}" = x ] && _conflict="dummy" ;;
  esac
  if [ "$_nf" -ge 2 ]; then
    _v="$_v
- 融合判定:$_nf 条独立证据家族指向陆港澳(${_fam# })—— 多层一致,置信提升"
    # 融合升级:≥2 个非纯文化家族(链路/配置/行为级)一致 → 视同实锤级聚合判定
    _nfhard=$(printf '%s' "$_fam" | tr ' ' '\n' | grep -v '^$' | grep -vc 'host-config(locale)' || true)
    if [ "${_nfhard:-0}" -ge 2 ]; then
      report EXPOSED usegeo/fusion "$_nf 条独立证据家族(含链路/配置/行为级,非纯文化信号)一致指向陆港澳 —— 融合判定视同实锤"
      _v="$_v
  · 融合升级:非纯文化家族 ≥2,已按暴露级聚合上报"
    fi
  elif [ "$_nf" = 1 ]; then
    _v="$_v
- 融合判定:1 条证据家族指向陆港澳(${_fam# }),单层信号"
  else
    _v="$_v
- 融合判定:未发现指向陆港澳的证据家族"
  fi
  if [ -n "${_conflict:-}" ] && [ "$_conflict" != dummy ]; then
    _v="$_v
  · 冲突链:$_conflict —— 两端均已保留上报,不用单一结论覆盖"
  fi

  # ── 会话入口类型汇总(u1 path 分类) ──
  [ -n "${SESS_ENTRIES:-}" ] && _v="$_v
- 入口类型:$(printf '%s' "$SESS_ENTRIES" | tr '\n' ' ')"

  USEGEO_VIEW="$_v"
  report INFO usegeo/view "实际使用地区视图已生成(见汇总区;证据家族 $_nf 条)"
}
