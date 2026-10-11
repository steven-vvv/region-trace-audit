# macOS read-only helpers. Subshells keep scratch variables out of check functions.
mac_console_user() (
  _cu=$(printf 'show State:/Users/ConsoleUser\n' | scutil 2>/dev/null |
    awk '$1=="Name" && $2==":" {print $3; exit}')
  case "$_cu" in ''|loginwindow|root|_mbsetupuser) return 1 ;; *) printf '%s\n' "$_cu" ;; esac
)

mac_boot_epoch() {
  sysctl -n kern.boottime 2>/dev/null |
    sed -n 's/.*{[[:space:]]*sec = \([0-9][0-9]*\),.*/\1/p'
}

mac_dns_servers() {
  scutil --dns 2>/dev/null |
    awk '$1 ~ /^nameserver\[[0-9]+\]$/ && $2==":" && !seen[$3]++ {print $3}'
}

mac_wifi_interfaces() {
  networksetup -listallhardwareports 2>/dev/null |
    awk '/^Hardware Port:/ {wifi=($0 ~ /Wi-Fi|AirPort/)} wifi && /^Device:/ {print $2}'
}

# Match bundle-id components, not substrings: com.todesktop is not ToDesk.
mac_cn_labels() {
  grep -iE '(^|\.)(tencent|qq|weixin|wechat|baidu|netease|alibaba|aliyun|dingtalk|sunlogin|todesk|iqiyi|youku|bilibili)(\.|$)'
}

# lsof -FpcfnT: retain only numeric TCP endpoint metadata, never arguments/content.
# Records: PID|command|state|local endpoint|peer endpoint. -f field boundaries matter.
mac_parse_sockets() {
  awk '
    function emit( a,n) {
      if (pid!="" && endpoint!="" && state!="") {
        n=split(endpoint,a,"->"); print pid "|" command "|" state "|" a[1] "|" (n>1?a[2]:"")
      }
      endpoint=""; state=""
    }
    /^p/ {emit(); pid=substr($0,2); command=""; next}
    /^c/ {command=substr($0,2); next}
    /^f/ {emit(); next}
    /^n/ {endpoint=substr($0,2); next}
    /^TST=/ {state=substr($0,5)}
    END {emit()}'
}

mac_socket_context() {
  [ "${MAC_SOCKETS_READY:-0}" = 1 ] && return
  MAC_SOCKETS_READY=1; MAC_SOCKETS=""; MAC_SOCKETS_OK=0
  # Empty lsof results also exit 1; do not equate them with a complete negative scan.
  if _ms_raw=$(lsof -nP -iTCP -FpcfnT 2>/dev/null); then MAC_SOCKETS_OK=1; fi
  if [ -n "$_ms_raw" ]; then
    MAC_SOCKETS=$(printf '%s\n' "$_ms_raw" | mac_parse_sockets)
  fi
  _ms_raw=""
}

mac_endpoint_ip() {
  printf '%s\n' "$1" | sed 's/:[^:]*$//; s/^\[//; s/\]$//'
}

# Apple frameworks expose only the selected attributes; no Bluetooth serials/keys.
mac_bluetooth_summary() {
  osascript -l JavaScript -e '
    ObjC.import("IOBluetooth");
    var devices=ObjC.unwrap($.IOBluetoothDevice.pairedDevices), n=0,c=0,z=0;
    if(!devices) throw new Error("paired-device query unavailable");
    devices.forEach(function(d){n++; if(d.isConnected)c++;
      var s=ObjC.unwrap(d.name); if(s && /[^\x20-\x7e]/.test(s))z++;});
    [n,c,z].join("|");' 2>/dev/null
}

mac_corewlan_summary() {
  osascript -l JavaScript -e '
    ObjC.import("CoreWLAN");
    var a=ObjC.unwrap($.CWWiFiClient.sharedWiFiClient.interfaces), out=[];
    if(!a) throw new Error("Wi-Fi interfaces unavailable");
    a.forEach(function(i){var n=ObjC.unwrap(i.interfaceName),c=ObjC.unwrap(i.countryCode),s=ObjC.unwrap(i.ssid);
      if(!/^[a-zA-Z0-9]+$/.test(n))return;
      out.push([n,i.powerOn?1:0,Number(i.interfaceMode),/^[A-Z]{2}$/.test(c||"")?c:"unknown",s?1:0,s&&/[^\x20-\x7e]/.test(s)?1:0].join("|"));});
    out.join("\n");' 2>/dev/null
}

# SPAirPortDataType only (not hardware/Bluetooth profiler, which include serials).
# Parse privately and emit only interface/country/association flags, never SSID/BSSID.
mac_airport_summary() {
  system_profiler -timeout 15 -detailLevel basic -json SPAirPortDataType 2>/dev/null |
    osascript -l JavaScript -e '
      ObjC.import("Foundation");
      var bytes=$.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
      var raw=$.NSString.alloc.initWithDataEncoding(bytes,$.NSUTF8StringEncoding);
      var d=JSON.parse(ObjC.unwrap(raw)), out=[];
      if(!Array.isArray(d.SPAirPortDataType))throw new Error("Wi-Fi report unavailable");
      d.SPAirPortDataType.forEach(function(root){(root.spairport_airport_interfaces||[]).forEach(function(i){
        var n=i._name,c=i.spairport_wireless_country_code,cur=i.spairport_current_network_information;
        if(!/^[a-zA-Z0-9]+$/.test(n||""))return;
        out.push([n,/^[A-Z]{2}$/.test(c||"")?c:"unknown",cur?1:0].join("|"));
      });}); out.join("\n");' 2>/dev/null
}

mac_wifi_context() {
  [ "${MAC_WIFI_READY:-0}" = 1 ] && return
  MAC_WIFI_READY=1; MAC_WIFI=$(mac_corewlan_summary) || MAC_WIFI=""
}

mac_app_inventory() (
  # Standard system/user app folders; no Spotlight indexing, app launch or network.
  for _ma_root in /Applications "$HOME/Applications"; do
    [ -d "$_ma_root" ] || continue
    find "$_ma_root" -maxdepth 3 -name '*.app' -type d -prune 2>/dev/null |
      while IFS= read -r _ma; do
        _bid=$(plutil -extract CFBundleIdentifier raw -o - "$_ma/Contents/Info.plist" 2>/dev/null) || _bid=""
        printf '%s|%s\n' "${_ma##*/}" "$_bid"
      done
  done
)

mac_apps_context() {
  [ "${MAC_APPS_READY:-0}" = 1 ] && return
  MAC_APPS_READY=1; MAC_APPS=$(mac_app_inventory)
}

mac_application_firewall_state() {
  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
}
