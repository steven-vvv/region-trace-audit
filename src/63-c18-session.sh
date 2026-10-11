#────────────────────────────── C18 session ──────────────────────────────
# 模块: 63-c18-session.sh
# 定位:活跃会话图与远程入口分类(path 标注);活跃对端供 C20/deep-geo 消费

check_c18() {
  hdr "C18 session · 用户、会话与远程入口"

  _ps=$(ps_filtered)
  _n_sess=0; _lc=""

  # ── 会话图:logind 优先,who/utmp 回退 ──
  if have loginctl; then
    _lc=$(loginctl list-sessions --no-legend 2>/dev/null)
  fi
  if [ -n "${_lc:-}" ]; then
    while read -r _sid _uid _user _seat _tty _rest; do
      [ -z "${_sid:-}" ] && continue
      case "$_sid" in ''|*[!0-9]*) continue ;; esac
      _n_sess=$((_n_sess+1))
      _show=$(loginctl show-session "$_sid" 2>/dev/null)
      _remote=$(printf '%s' "$_show" | sed -n 's/^Remote=//p' | head -n 1)
      _stype=$(printf '%s' "$_show" | sed -n 's/^Type=//p' | head -n 1)
      _rhost=$(printf '%s' "$_show" | sed -n 's/^RemoteHost=//p' | head -n 1)
      _cls="local"; [ "$_remote" = "yes" ] && _cls="remote"
      _rh=""
      if [ -n "$_rhost" ] && [ "$_rhost" != "n/a" ]; then
        _rh=" 来源 $(mask_ip "$_rhost")"
        case " $SESS_REMOTES " in *" $_rhost "*) ;; *) SESS_REMOTES="$SESS_REMOTES $_rhost" ;; esac
      fi
      if [ "$_cls" = local ]; then SESS_LOCAL_N=$((SESS_LOCAL_N+1)); fi
      report INFO "session/S-$_sid" "uid=$_uid(${_user:-?}) type=${_stype:-?} ${_cls}${_rh}"
    done <<EOF
$_lc
EOF
  elif have who && who 2>/dev/null | grep -q .; then
    _wl=$(who 2>/dev/null)
    while IFS= read -r _line; do
      _user=$(printf '%s\n' "$_line" | awk '{print $1}')
      _tty=$(printf '%s\n' "$_line" | awk '{print $2}')
      [ -z "$_user" ] && continue
      _n_sess=$((_n_sess+1))
      _rhost=$(printf '%s\n' "$_line" | sed -n 's/.*(\([^()]*\))[[:space:]]*$/\1/p')
      if [ -n "$_rhost" ] && [ "$_rhost" != ':0' ]; then
        _cls="remote(来源 $(mask_ip "$_rhost"))"
        case " $SESS_REMOTES " in *" $_rhost "*) ;; *) SESS_REMOTES="$SESS_REMOTES $_rhost" ;; esac
      else
        _cls="local"
        SESS_LOCAL_N=$((SESS_LOCAL_N+1))
      fi
      report INFO "session/$_tty" "用户 $_user tty=$_tty $_cls"
    done <<EOF
$_wl
EOF
  fi
  if [ "$PLATFORM" = macos ] && [ "$SESS_LOCAL_N" = 0 ] && mac_console_user >/dev/null; then
    SESS_LOCAL_N=1; _n_sess=$((_n_sess+1))
    report INFO session/console "macOS console 用户已登录(scutil;不读取屏幕/输入内容)"
  fi
  SESS_N=$_n_sess
  if [ "$_n_sess" = 0 ]; then
    report SKIP session/graph "(logind/who 均不可用或无会话记录 —— 容器/服务环境常见)"
  else
    report INFO session/count "$_n_sess 个登录会话(以上;来源值已脱敏,完整值用 --reveal)"
  fi

  # ── 活跃 SSH 对端(/proc/net/tcp,本地端口 = sshd 监听端口) ──
  _ssh_ports="22"
  if [ -r /etc/ssh/sshd_config ]; then
    for _p in $(sed -n 's/^[[:space:]]*Port[[:space:]]*\([0-9][0-9]*\).*/\1/p' /etc/ssh/sshd_config 2>/dev/null); do
      case " $_ssh_ports " in *" $_p "*) ;; *) _ssh_ports="$_ssh_ports $_p" ;; esac
    done
  fi
  for _p in $(printf '%s' "${_ps:-}" | grep 'sshd' | grep -oE '\-p [0-9]+' | awk '{print $2}' | sort -u); do
    case " $_ssh_ports " in *" $_p "*) ;; *) _ssh_ports="$_ssh_ports $_p" ;; esac
  done
  # 端口自举:sshd_config 不可读(加固机常见)时,经自身 SSH_CONNECTION 对端反推 sshd 监听端口
  # (对端 IP 的 ESTABLISHED 条目 → 本地端口;v4 与 tcp6 v4-mapped 两种形态都匹配)
  if [ -n "${SSH_CONNECTION:-}" ]; then
    _sp_ip=$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')
    case "$_sp_ip" in
      [0-9]*.[0-9]*.[0-9]*.[0-9]*)
        # /proc/net/tcp 地址为小端:显示 hex = d.c.b.a
        _sp_h4=$(printf '%s' "$_sp_ip" | awk -F. '{printf "%02X%02X%02X%02X", $4,$3,$2,$1}')
        _sp_h6=$_sp_h4
        for _tf in /proc/net/tcp /proc/net/tcp6; do
          [ -r "$_tf" ] || continue
          _sp_m6=""
          [ "$_tf" = /proc/net/tcp6 ] && _sp_m6="0000000000000000FFFF0000$_sp_h6"
          for _lp in $(awk -v r4="$_sp_h4" -v r6="$_sp_m6" '$4=="01"{split($3,R,":"); if (R[1]==r4 || (r6!="" && R[1]==r6)){split($2,L,":"); print L[2]}}' "$_tf" 2>/dev/null); do
            _pd=$(printf '%d' "0x$_lp" 2>/dev/null) || continue
            case " $_ssh_ports " in *" $_pd "*) ;; *) _ssh_ports="$_ssh_ports $_pd" ;; esac
          done
        done ;;
    esac
  fi
  _self_port=$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $4}')
  case "$_self_port" in ''|*[!0-9]*) ;; *) _ssh_ports="$_ssh_ports $_self_port" ;; esac
  if [ "$PLATFORM" = macos ]; then
    mac_check_ssh
  else
  # 对端采集:tcp + tcp6(v4-mapped 归一为 IPv4;原生 v6 保留展示/GeoIP 由 HTTPS 源支持)
  _peers=""
  for _tf in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$_tf" ] || continue
    _v6f=0; [ "$_tf" = /proc/net/tcp6 ] && _v6f=1
    _peers="$_peers $(awk -v ports="$_ssh_ports" -v v6="$_v6f" '
      BEGIN{ n=split(ports,P," "); for(i=1;i<=n;i++) WantP[P[i]+0]=1 }  # 端口表为十进制;lp 经 h2d 后同为十进制
      function h2d(x, v,c,j){v=0;for(j=1;j<=length(x);j++){c=substr(x,j,1);v=v*16+index("0123456789ABCDEF",toupper(c))-1}return v}
      function dec6(h, g,sg,bs,out){ out=""; for(g=0;g<8;g++){ sg=substr(h,g*4+1,4); bs=substr(sg,3,2) substr(sg,1,2); sub(/^0+/,"",bs); if(bs=="")bs="0"; out=out (g?":":"") bs } return out }
      $4=="01"{
        split($2,L,":"); lp=h2d(L[2]); if(!(lp in WantP)) next
        split($3,R,":")
        if (v6) {
          # v4-mapped(::ffff:a.b.c.d):前 16 hex 为 0 + FFFF0000 + 小端 v4
          if (substr(R[1],1,16)=="0000000000000000" && substr(R[1],17,8)=="FFFF0000")
            print h2d(substr(R[1],31,2))"."h2d(substr(R[1],29,2))"."h2d(substr(R[1],27,2))"."h2d(substr(R[1],25,2))
          else print dec6(R[1])
        } else print h2d(substr(R[1],7,2))"."h2d(substr(R[1],5,2))"."h2d(substr(R[1],3,2))"."h2d(substr(R[1],1,2))
      }' "$_tf" 2>/dev/null | sort -u | tr '\n' ' ')"
  done
  # 会话绑定(强归属):自有 sshd 会话进程的 socket inode → 对端精确绑定
  # (sshd 特权分离后子进程以会话用户运行,其 /proc/<pid>/fd 对本人可读;他人会话不可读 → 降级为端口级)
  _inos=""
  for _sp in $(printf '%s' "${_ps:-}" | grep -E "sshd(-session)?: ${CUR_USER:-x}@" | awk '{print $2}'); do
    for _ino in $(ls -l "/proc/$_sp/fd" 2>/dev/null | grep -oE 'socket:\[[0-9]+\]' | tr -d 'socket:[]'); do
      case " $_inos " in *" $_ino "*) ;; *) _inos="$_inos $_ino" ;; esac
    done
  done
  _bound=""
  if has_text "$_inos"; then
    for _tf in /proc/net/tcp /proc/net/tcp6; do
      [ -r "$_tf" ] || continue
      _v6f=0; [ "$_tf" = /proc/net/tcp6 ] && _v6f=1
      _bound="$_bound $(awk -v inos="$_inos" -v v6="$_v6f" '
        BEGIN{ n=split(inos,I," "); for(i=1;i<=n;i++) Ino[I[i]]=1 }
        function h2d(x, v,c,j){v=0;for(j=1;j<=length(x);j++){c=substr(x,j,1);v=v*16+index("0123456789ABCDEF",toupper(c))-1}return v}
        function dec6(h, g,sg,bs,out){ out=""; for(g=0;g<8;g++){ sg=substr(h,g*4+1,4); bs=substr(sg,3,2) substr(sg,1,2); sub(/^0+/,"",bs); if(bs=="")bs="0"; out=out (g?":":"") bs } return out }
        $4=="01" && ($10 in Ino){
          # socket 归属 sshd 会话进程即过滤器,不依赖端口表(应对 sshd_config 不可读/socket unit 场景)
          split($3,R,":")
          if (v6) {
            if (substr(R[1],1,16)=="0000000000000000" && substr(R[1],17,8)=="FFFF0000")
              print h2d(substr(R[1],31,2))"."h2d(substr(R[1],29,2))"."h2d(substr(R[1],27,2))"."h2d(substr(R[1],25,2))
            else print dec6(R[1])
          } else print h2d(substr(R[1],7,2))"."h2d(substr(R[1],5,2))"."h2d(substr(R[1],3,2))"."h2d(substr(R[1],1,2))
        }' "$_tf" 2>/dev/null | sort -u | tr '\n' ' ')"
    done
  fi
  _portonly=""
  for _p in $_peers; do
    case " $_bound " in *" $_p "*) ;; *) _portonly="$_portonly $_p" ;; esac
  done
  if has_text "$_bound"; then
    _mp=""; for _p in $_bound; do _mp="$_mp $(mask_ip "$_p")"; done
    report INFO session/ssh-peers "活跃 SSH 会话对端(socket inode 绑定到 sshd 会话进程,强归属):$_mp;GeoIP:自身会话见下,其余归 --deep-geo"
  fi
  if has_text "$_portonly"; then
    _mp=""; for _p in $_portonly; do _mp="$_mp $(mask_ip "$_p")"; done
    report INFO session/ssh-peers-port "疑似 SSH 端口对端(未绑定到可读会话进程:他人会话/端口复用可能):$_mp"
  fi
  if ! has_text "$_bound" && ! has_text "$_portonly"; then
    if [ -r /proc/net/tcp ] || [ -r /proc/net/tcp6 ]; then
      report CLEAN session/ssh-peers "无活跃 SSH 连接(端口级按 $_ssh_ports 匹配;sshd_config 不可读时端口表可能不全)"
    else
      report SKIP session/ssh-peers "(无可读 Linux socket 表;macOS 未实现 SSH socket 归属采集,不据此认定无连接)"
    fi
  fi

  fi

  # ── 当前自身会话对端 GeoIP(外联最小集:即「操作者从哪连入」) ──
  _selfpeer=$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $1}')
  SELF_PEER=$_selfpeer
  if [ -n "$_selfpeer" ]; then
    if [ "$OFFLINE" != 1 ] && [ -n "$HTTP_TOOL" ]; then
      _g=$(geoip1 "$_selfpeer"); SELF_PEER=$_selfpeer; SELF_PEER_CC=${_g%%|*}
      case "${_g%%|*}" in
        CN|HK|MO) report EXPOSED session/self-peer "当前 SSH 会话控制端位于$(cnname "${_g%%|*}")(controller-net —— 操作者网络实锤)" ;;
        ERR)      report SKIP session/self-peer "(控制端 GeoIP 查询失败)" ;;
        *)        report INFO session/self-peer "当前 SSH 会话控制端 GeoIP:$(printf '%s' "$_g" | cut -d'|' -f2)(${_g%%|*})" ;;
      esac
    else
      report SKIP session/self-peer "(--offline 或缺 HTTP 工具;控制端 $(mask_ip "$_selfpeer"))"
    fi
  else
    report INFO session/self-peer "当前无 SSH 会话(本地/服务上下文)"
  fi

  # ── 入口类型识别(进程四态中的 active) ──
  if printf '%s' "${_ps:-}" | grep -q 'vscode-server'; then
    report INFO session/entry "VS Code Remote 服务运行中(入口类型:IDE remote)"
    SESS_ENTRIES="$SESS_ENTRIES IDE-remote"
  fi
  _wt=$(printf '%s' "${_ps:-}" | grep -oE 'ttyd|wetty|gotty|shellinabox|code-server|openvscode|jupyter' | sort -u | tr '\n' ' ')
  if has_text "$_wt"; then
    report INFO session/entry "web terminal/IDE 运行中: $_wt(入口类型:web)"
    SESS_ENTRIES="$SESS_ENTRIES web-terminal($(printf '%s' "$_wt" | sed 's/ *$//'))"
  fi
  if printf '%s' "${_ps:-}" | grep -q 'amazon-ssm-agent'; then
    report INFO session/entry "AWS SSM agent 运行中(入口类型:cloud-console,操作者源 IP 通常不可见)"
    SESS_ENTRIES="$SESS_ENTRIES cloud-console(SSM)"
  fi
  _mux=$(printf '%s' "${_ps:-}" | grep -oE '(^|/|[[:space:]])(tmux|screen)([[:space:]]|$)' | sed 's|.*/||; s/^[[:space:]]*//; s/[[:space:]]*$//' | sort -u | tr '\n' ' ')
  has_text "$_mux" && report INFO session/mux "终端复用器运行中: $_mux"
  # 仅统计会话进程,排除 listener(sshd: /usr/sbin/…);
  # 兼容 OpenSSH 9.8+ 的 sshd-session: user@pts/N 命名
  _ssh_sess=$(printf '%s' "${_ps:-}" | grep -cE 'sshd(-session)?: [^/[:space:]]+@' || true)
  if [ "${_ssh_sess:-0}" -gt 0 ]; then
    report INFO session/ssh-active "sshd 活跃会话 x${_ssh_sess}(user@pts 形态)"
  elif [ -z "$_ps" ]; then
    report SKIP session/ssh-active "(进程快照不可用)"
  else
    report CLEAN session/ssh-active "无 sshd 活跃会话(仅 listener 或未运行)"
  fi

  # ── 最近登录记录(wtmp 可读时;只计数,不展示来源) ──
  if have last && last -n 10 2>/dev/null | grep -q '^[a-zA-Z]'; then
    _total=$(last -n 10 2>/dev/null | grep -cE 'pts/|tty[0-9]' || true)
    _still=$(last -n 10 2>/dev/null | grep -c 'still logged in' || true)
    report INFO session/lastlog "last 可读:最近 10 条记录中 $_total 条终端登录、$_still 条仍在线(来源明细属敏感,默认不展示)"
  else
    report SKIP session/lastlog "(last 不可用/wtmp 不可读)"
  fi

  # ── 用户级持久化(与会话同 UID 的服务) ──
  if [ -d "$HOME/.config/systemd/user" ]; then
    _uu=$(ls "$HOME/.config/systemd/user" 2>/dev/null | head -n 6 | tr '\n' ' ')
    has_text "$_uu" && report INFO session/user-units "用户级 systemd unit: $_uu"
  fi
}
