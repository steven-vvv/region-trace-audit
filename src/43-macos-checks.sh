# Native macOS collection beyond the platform baseline. All commands are read-only.

mac_check_ssh() {
  mac_socket_context
  _ms_peers=$(printf '%s\n' "$MAC_SOCKETS" | awk -F'|' '$2 ~ /^sshd(-session)?$/ && $3=="ESTABLISHED" {print $5}' | sort -u)
  _ms_n=0; _ms_masked=""
  while IFS= read -r _endpoint; do
    [ -n "$_endpoint" ] || continue
    _peer=$(mac_endpoint_ip "$_endpoint")
    _ms_n=$((_ms_n+1)); _ms_masked="$_ms_masked $(mask_ip "$_peer")"
  done <<EOF_PEERS
$_ms_peers
EOF_PEERS
  # sshd also owns forwarded sockets; do not turn them into interactive logins.
  MAC_SSH_PEER_N=$_ms_n
  if [ "$_ms_n" -gt 0 ]; then
    report INFO session/ssh-peers "macOS lsof 绑定到 sshd 进程的活动 TCP 对端 $_ms_n 个:$_ms_masked(可含转发连接;非自身对端 GeoIP 需 --deep-geo)"
  elif [ "$MAC_SOCKETS_OK" = 1 ]; then
    report INFO session/ssh-peers "可见 TCP socket 中未发现 sshd 活动连接(lsof;其他用户/root 进程可能不可见)"
  else
    report SKIP session/ssh-peers "(lsof 未返回可读 TCP socket;可能无连接或权限受限,不能证明无 SSH)"
  fi
  # Numeric kernel socket table supplies a weaker fallback even if owners are hidden.
  _ms_net=$(netstat -an -p tcp 2>/dev/null) || _ms_net=""
  _ms_port=$(printf '%s\n' "$_ms_net" | awk -v ports="$_ssh_ports" '
    BEGIN{split(ports,p," "); for(i in p)want[p[i]]=1}
    $1~/^tcp/ && $6=="ESTABLISHED" {n=split($4,a,"."); if(a[n] in want)count++}
    END{print count+0}')
  [ "$_ms_port" -gt 0 ] && report INFO session/ssh-peers-port "内核表中 $_ms_port 条 TCP 连接的本地端口命中 SSH 配置(未绑定进程,不能排除端口复用)"
}

mac_check_firewall() {
  _pf_info=$(pfctl -s info 2>&1); _pf_rc=$?
  if [ "$_pf_rc" = 0 ]; then
    _pf_state=$(printf '%s\n' "$_pf_info" | awk '/^Status:/ {print $2; exit}')
    report INFO proxy/pf "PF 状态: ${_pf_state:-已读取}(读取根规则及所有可读 anchor,不修改规则)"
    _pf_rules=$(pfctl -s nat 2>/dev/null && pfctl -a '*' -s nat 2>/dev/null); _pf_nat_rc=$?
    _pf_filter=$(pfctl -s rules 2>/dev/null && pfctl -a '*' -s rules 2>/dev/null); _pf_filter_rc=$?
    if [ "$_pf_nat_rc" = 0 ] && [ "$_pf_filter_rc" = 0 ]; then
      _pf_redir=$(printf '%s\n' "$_pf_rules" | grep -cE '^[[:space:]]*(rdr|nat|binat)([[:space:]]|-)' || true)
      _pf_cn=$(printf '%s\n%s\n' "$_pf_rules" "$_pf_filter" | grep -ciE 'chnroute|china|geoip.?cn' || true)
      report INFO proxy/pf-rules "可读 PF anchor 中 NAT/重定向规则 $_pf_redir 条(拓扑信息,不输出规则明文)"
      [ "$_pf_cn" -gt 0 ] && report SUSPICIOUS proxy/chnroute "PF 规则含 CN 分流标记 $_pf_cn 处(配置习惯)"
    else
      report SKIP proxy/pf-rules "(PF 状态可读,但 NAT/filter anchor 规则查询失败)"
    fi
  else
    case "$_pf_info" in
      *'Permission denied'*|*'Operation not permitted'*) _pf_reason="当前用户无 /dev/pf 读取权限;需管理员运行才能核查活动规则" ;;
      *) _pf_reason="pfctl 不可用或内核 PF 查询失败" ;;
    esac
    report SKIP proxy/pf "($_pf_reason;未自动提权)"
  fi
  _afw=$(mac_application_firewall_state)
  case "$_afw" in
    *'State = 1'*|*'State = 2'*) report INFO proxy/application-firewall "macOS 应用防火墙已启用(与 PF/Network Extension 分开)" ;;
    *'State = 0'*) report INFO proxy/application-firewall "macOS 应用防火墙未启用(不代表无 PF/Network Extension)" ;;
    *) report SKIP proxy/application-firewall "(socketfilterfw 状态不可读)" ;;
  esac
  if _ne=$(systemextensionsctl list 2>/dev/null); then
    _nen=$(printf '%s\n' "$_ne" | awk '/com.apple.system_extension.network_extension/ {net=1;next} /^---/ {net=0} net && /\[activated enabled\]/ {n++} END {print n+0}')
    report INFO proxy/network-extension "已激活且启用的 Network Extension 系统扩展 $_nen 个(systemextensionsctl;不包含全部 app-extension VPN,不读取流量内容)"
  else
    report SKIP proxy/network-extension "(systemextensionsctl 不可读/系统版本不支持)"
  fi
}

mac_check_apps() {
  mac_apps_context
  _ca=$(printf '%s\n' "$MAC_APPS" | awk -F'|' '{print $2}' | mac_cn_labels | sort -u)
  _can=$(printf '%s\n' "$_ca" | grep -c . || true)
  if [ "$_can" -gt 0 ]; then
    report SUSPICIOUS mirror/cn-apps "标准 Applications 目录内命中国内软件 bundle ID $_can 个(installed 态,不等同于运行中): $(printf '%s' "$_ca" | head -n 8 | tr '\n' ' ')"
  elif printf '%s\n' "$MAC_APPS" | awk -F'|' 'NF>1 && $2!=""{ok=1} END{exit !ok}'; then
    report CLEAN mirror/cn-apps "可读 Applications bundle ID 未命中国内软件表(不包含自定义安装目录)"
  else
    report SKIP mirror/cn-apps "(Applications 目录无可读 bundle ID,可能无应用或权限受限)"
  fi
}

mac_check_devices() {
  if _bt=$(mac_bluetooth_summary); then
    _bn=$(printf '%s' "$_bt" | cut -d'|' -f1); _bc=$(printf '%s' "$_bt" | cut -d'|' -f2); _bz=$(printf '%s' "$_bt" | cut -d'|' -f3)
    case "$_bn:$_bc:$_bz" in *[!0-9:]*|'::') report SKIP fs/bluetooth "(IOBluetooth 返回无效统计)" ;;
      *) report INFO fs/bluetooth-state "蓝牙已配对 $_bn 个/连接中 $_bc 个(不输出名称、地址、序列号)"
         if [ "$_bz" -gt 0 ]; then report SUSPICIOUS fs/bluetooth "$_bz 个配对设备名含非 ASCII(文化习惯弱信号,不等同中文)"
         else report CLEAN fs/bluetooth "可读配对设备名称无非 ASCII 命中"; fi ;;
    esac
  else
    report SKIP fs/bluetooth "(IOBluetooth 配对元数据不可读;可能受蓝牙权限限制)"
  fi
  mac_wifi_context
  _wv=$(printf '%s\n' "$MAC_WIFI" | awk -F'|' '$5==1 {n++} END {print n+0}')
  _wz=$(printf '%s\n' "$MAC_WIFI" | awk -F'|' '$6==1 {n++} END {print n+0}')
  if [ "$_wz" -gt 0 ]; then
    report SUSPICIOUS fs/wifi-ssid "$_wz 个当前 Wi-Fi 名称含非 ASCII(仅本地比对;不输出 SSID/BSSID)"
  elif [ "$_wv" -gt 0 ]; then
    report CLEAN fs/wifi-ssid "可读的当前 Wi-Fi 名称无非 ASCII 命中(不扫描历史网络)"
  else
    report SKIP fs/wifi-ssid "(CoreWLAN 未提供当前 SSID:未关联或受 macOS 定位隐私限制;不据此判无 Wi-Fi)"
  fi
}

mac_check_radio() {
  mac_wifi_context
  _ap_summary=$(mac_airport_summary) || _ap_summary=""
  if [ -z "$MAC_WIFI$_ap_summary" ]; then
    report SKIP hw/radio "(CoreWLAN/system_profiler 无可读无线数据或超时)"
    return
  fi
  while IFS='|' read -r _wi _power _mode _country _visible _nonascii; do
    [ -n "$_wi" ] || continue
    report INFO hw/wifi "$_wi 电源=$_power 模式=$_mode(CoreWLAN;1=station,不输出 SSID/BSSID)"
  done <<EOF_WIFI
$MAC_WIFI
EOF_WIFI
  _countries=$(printf '%s\n' "$MAC_WIFI" | awk -F'|' '$4~/^[A-Z][A-Z]$/ {print $4}')
  _countries="$_countries
$(printf '%s\n' "$_ap_summary" | awk -F'|' '$2~/^[A-Z][A-Z]$/ {print $2}')"
  _countries=$(printf '%s\n' "$_countries" | grep -E '^[A-Z]{2}$' | sort -u)
  if [ -n "$_countries" ]; then
    for _country in $_countries; do
      case "$_country" in CN) report SUSPICIOUS hw/reg-domain "Wi-Fi 监管域 CN(CoreWLAN/system_profiler;弱证据,不等于实际所在地)" ;;
        *) report INFO hw/reg-domain "Wi-Fi 监管域 $_country(CoreWLAN/system_profiler;不作为物理定位实锤)" ;; esac
    done
  else
    report SKIP hw/reg-domain "(系统未提供国家码,可能受隐私限制;不调用已弃用 airport)"
  fi
  _associated=$(printf '%s\n' "$_ap_summary" | awk -F'|' '$3==1{n++} END{print n+0}')
  RADIO_ACCESS="macOS Wi-Fi:当前网络记录 $_associated 个;监管域 ${_countries:-未知}(不输出 SSID/BSSID,非物理定位)"
}

mac_check_remote_desktop() {
  mac_apps_context; mac_socket_context
  _rd_ps=$(ps -axo pid=,comm= 2>/dev/null)
  _rd_launch=$(launchctl list 2>/dev/null)
  _rd_any=0
  while IFS=';' read -r _rd_name _rd_app _rd_proc _rd_label; do
    _rd_inst=0; _rd_loaded=0; _rd_running=0; _rd_listen=0; _rd_conn=0
    printf '%s\n' "$MAC_APPS" | grep -qiE "$_rd_app" && _rd_inst=1
    printf '%s\n' "$_rd_launch" | awk '{print $3}' | grep -qiE "$_rd_label" && _rd_loaded=1
    _rd_pids=$(printf '%s\n' "$_rd_ps" | awk -v re="$_rd_proc" 'tolower($0) ~ re {print $1}')
    [ -n "$_rd_pids" ] && _rd_running=1
    _rd_sock=$(printf '%s\n' "$MAC_SOCKETS" | awk -F'|' -v ids="$_rd_pids" -v re="$_rd_proc" '
      BEGIN {split(ids,a,"\n");for(i in a) p[a[i]]=1}
      ($1 in p) || tolower($2) ~ re {print}')
    _rd_listen=$(printf '%s\n' "$_rd_sock" | awk -F'|' '$3=="LISTEN"{n++} END{print n+0}')
    _rd_conn=$(printf '%s\n' "$_rd_sock" | awk -F'|' '$3=="ESTABLISHED"{n++} END{print n+0}')
    if [ "$_rd_inst$_rd_loaded$_rd_running$_rd_listen$_rd_conn" != 00000 ]; then
      _rd_any=1
      report INFO gui/rd "$_rd_name: installed=$_rd_inst loaded=$_rd_loaded running=$_rd_running TCP-listening=$_rd_listen TCP-established=$_rd_conn(绑定可见进程;TCP 连接可能为心跳/中继,不直接认定有人远控)"
      [ "$_rd_conn" -gt 0 ] && OVERLAY_BREAKS="$OVERLAY_BREAKS $_rd_name(活动传输,交互控制未确认)"
    fi
  done <<'EOF_RD'
Apple Screen Sharing;com[.]apple[.](screensharing|RemoteDesktop);(^|[ /])(screensharingd|screensharingagent|ardagent)( |$);(^|[.])screensharing([.]|$)
RustDesk;rustdesk|flutter_hbb;(^|[ /])rustdesk( |$);rustdesk|flutter_hbb
AnyDesk;anydesk;(^|[ /])anydesk( |$);anydesk
TeamViewer;teamviewer;(^|[ /])teamviewer[^/]*( |$);teamviewer
ToDesk;(^|[.|])todesk([.|]|$);(^|[ /])todesk(_service|_daemon)?( |$);(^|[.])todesk([.]|$)
Sunlogin;sunlogin;(^|[ /])sunlogin[^/]*( |$);sunlogin
NoMachine;nomachine;(^|[ /])(nxserver|nxnode|nxplayer)( |$);nomachine
Chrome Remote Desktop;chromeremotedesktop;(^|[ /])chrome_remote_desktop[^/]*( |$);chromoting
Parsec;(^|[.|])parsec(gaming)?([.|]|$);(^|[ /])parsec( |$)|/parsec[.]app/contents/macos/parsecd( |$);(^|[.])parsec(gaming)?([.]|$)
EOF_RD
  if [ "$_rd_any" = 0 ]; then
    if [ -n "$_rd_ps" ] && [ "$MAC_SOCKETS_OK" = 1 ]; then
      report INFO gui/rd "标准应用目录/可见进程/socket 未命中远控产品表(含 Apple Screen Sharing);不覆盖隐藏或其他用户的会话"
    else
      report SKIP gui/rd "(应用/进程已检查,但进程或 socket 可见性不足以判断远控活动)"
    fi
  fi
}
