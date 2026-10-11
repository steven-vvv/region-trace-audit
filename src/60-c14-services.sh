#────────────────────────────── C14 services ──────────────────────────────
# 模块: 60-c14-services.sh

check_c14() {
  hdr "C14 services · 进程、端口与服务(四态:installed/enabled/listening/active)"

  _ps=$(ps_filtered)
  if [ -n "$_ps" ]; then
    # 国内软件进程(运行中 = active)
    _ap=$(printf '%s' "$_ps" | grep -vE 'grep|region-trace' | grep -icE "$CN_APP_PROC_RE" || true)
    if [ "${_ap:-0}" -gt 0 ]; then
      report SUSPICIOUS services/cn-app-proc "国内软件进程运行中 x$_ap(active 态)"
    else
      report CLEAN services/cn-app-proc "无国内软件进程"
    fi
    # 代理栈进程(INFO,交 C5 深判)
    _pp=$(printf '%s' "$_ps" | grep -vE 'grep|region-trace' | grep -icE "$PROXY_PROC_RE" || true)
    if [ "${_pp:-0}" -gt 0 ]; then
      report INFO services/proxy-proc "代理栈进程运行中 x$_pp(clash/v2ray/xray… 拓扑角色判定属 C5)"
    fi
    # 命令行含非 ASCII(排除自身进程树,防自匹配)
    _cp=$(printf '%s' "$_ps" | LC_ALL=C grep -c '[^ -~]' || true)
    if [ "${_cp:-0}" -gt 0 ]; then
      report SUSPICIOUS services/proc-nonascii "$_cp 条进程命令行含非 ASCII(可能为中文路径)"
    else
      report CLEAN services/proc-nonascii "无非 ASCII 进程命令行(已排除自身进程树)"
    fi
  else
    report SKIP services/procs "(ps 不可用)"
  fi

  # 监听端口:macOS netstat / Linux proc;采集失败不得报 0 个。
  _ports=""; _ports_ok=0
  if [ "$PLATFORM" = macos ]; then
    if _sockets=$(netstat -an -p tcp 2>/dev/null); then
      _ports=$(printf '%s\n' "$_sockets" | awk '$1 ~ /^tcp/ && $6=="LISTEN" {n=split($4,a,"."); if(a[n] ~ /^[0-9]+$/) print a[n]}' | sort -un | tr '\n' ' ')
      _ports_ok=1
    fi
  elif [ -r /proc/net/tcp ] || [ -r /proc/net/tcp6 ]; then
    _ports=$(for _f in /proc/net/tcp /proc/net/tcp6; do
      [ -r "$_f" ] || continue
      awk '$4=="0A"{split($2,a,":");h=a[2];d=0;for(i=1;i<=length(h);i++){d=d*16+index("0123456789ABCDEF",toupper(substr(h,i,1)))-1};print d}' "$_f"
    done | sort -un | tr '\n' ' ')
    _ports_ok=1
  fi
  if [ "$_ports_ok" = 1 ]; then
    _pl=$(printf '%s' "$_ports" | wc -w | tr -d ' ')
    _phit=""
    for _p in $_ports; do
      case " $PROXY_PORT_LIST " in *" $_p "*) _phit="${_phit:+$_phit }$_p" ;; esac
    done
    if [ -n "$_phit" ]; then
      report INFO services/proxy-ports "监听端口命中代理栈常用端口: $_phit(listening 态,交 C5)"
    fi
    report INFO services/listen-ports "共监听 ${_pl:-0} 个端口(localhost+全网)"
  else
    report SKIP services/listen-ports "(TCP 监听表不可读:macOS netstat / Linux proc)"
  fi

  # systemd 服务
  if [ "$PLATFORM" = macos ]; then
    report INFO services/manager "macOS 使用 launchd;服务标签见 macos 类(单项运行请另查 --section macos)"
  elif have systemctl && systemctl list-unit-files >/dev/null 2>&1; then
    _se=$(systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1,$2}' | grep -iE "$CN_APP_PROC_RE|$CLOUD_AGENT_PROC_RE" | head -n 6 | tr '\n' ' ')
    if has_text "$_se"; then
      report INFO services/systemd-cn "systemd 服务命中: $(printf '%s' "$_se" | cut -c1-100)(enabled 态见列表)"
    else
      report CLEAN services/systemd-cn "systemd 服务无国内软件命中"
    fi
  else
    report SKIP services/systemd "(无 systemd/不可用 —— 容器常见)"
  fi

  # macOS crontab distinguishes absent, readable/nonmatching, and access failures.
  if [ "$PLATFORM" = macos ]; then
    _cron=$(LC_ALL=C crontab -l 2>&1); _cron_rc=$?
    if [ "$_cron_rc" = 0 ]; then
      if printf '%s\n' "$_cron" | grep -qE "$CN_DOMAIN_RE"; then
        report SUSPICIOUS services/cron "当前用户 cron 任务含国内域名引用(不输出任务内容)"
      else
        report CLEAN services/cron "当前用户可读 crontab 无国内域名引用"
      fi
    else
      case "$_cron" in
        *'no crontab for '*) report INFO services/cron "当前用户未配置 crontab(launchd 任务另查 macos 类)" ;;
        *) report SKIP services/cron "(当前用户 crontab 不可读或命令不可用)" ;;
      esac
    fi
    _cron=""
  else
  # cron
  _cron_hit=0
  if have crontab; then
    if crontab -l 2>/dev/null | grep -qE "$CN_DOMAIN_RE"; then _cron_hit=1; fi
  fi
  if [ -d /etc/cron.d ]; then
    grep -rhE "$CN_DOMAIN_RE" /etc/cron.d 2>/dev/null | grep -q . && _cron_hit=1
  fi
  if [ "$_cron_hit" = 1 ]; then
    report SUSPICIOUS services/cron "cron 任务含国内域名引用"
  else
    report SKIP services/cron "(cron 不可读或无命中)"
  fi

  fi

  # k8s pod 判定
  if [ -d /var/run/secrets/kubernetes.io/serviceaccount ]; then
    report INFO services/k8s "检出 K8s ServiceAccount 挂载(运行于 pod;cluster DNS/TZ 注入见 dns/locale 类)"
  elif [ -n "$KUBERNETES_SERVICE_HOST" ]; then
    report INFO services/k8s "KUBERNETES_SERVICE_HOST 已设置(可能为 pod/节点)"
  fi
}
