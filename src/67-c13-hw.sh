#────────────────────────────── C13 hw ──────────────────────────────
# 模块: 67-c13-hw.sh
# 定位:硬件/DMI/CPU 品牌与无线/蜂窝(--radio;桌面/物理机场景)
# 红线:绝不读取序列号/UUID/IMEI/IMSI/ICCID/WiFi 密码;SSID/BSSID 只本地比对、不输出

check_c13() {
  hdr "C13 hw · 硬件、DMI 与无线/蜂窝"

  if [ "$PLATFORM" = macos ]; then
    _model=$(sysctl -n hw.model 2>/dev/null)
    _cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
    if [ -n "$_model" ]; then report INFO hw/model "Mac 型号: $_model(不读取序列号/UUID)"
    else report SKIP hw/model "(hw.model 不可读)"; fi
    if [ -n "$_cpu" ]; then report INFO hw/cpu "CPU: $_cpu"
    else report SKIP hw/cpu "(CPU 品牌不可读)"; fi
    _wifi=$(mac_wifi_interfaces)
    if [ -n "$_wifi" ]; then
      report INFO hw/wireless "Wi-Fi 硬件接口: $(printf '%s' "$_wifi" | tr '\n' ' ')(不读取 SSID/BSSID,不代表已关联)"
    else
      report SKIP hw/wireless "(networksetup 无可见 Wi-Fi 硬件接口,不据此认定无无线硬件)"
    fi
    if [ "$RADIO" = 1 ]; then
      mac_check_radio
    else
      report SKIP hw/radio "(默认关闭;--radio 可读取 CoreWLAN/system_profiler 无线状态与监管域)"
    fi
    return
  fi

  # ── DMI 品牌(只读 vendor/product_name;不读 serial/UUID) ──
  if [ -r /sys/class/dmi/id/product_name ]; then
    _pv=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
    _pn=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    case "${_pv:-}${_pn:-}" in
      *[Ll]enovo*|*[Ll]EGION*|*HUAWEI*|*HONOR*|*Xiaomi*|*Redmi*|*POCO*|*OnePlus*|*OPPO*|*vivo*|*MEIZU*)
        report SUSPICIOUS hw/dmi "DMI 品牌: ${_pv:-?} ${_pn:-?}(国产品牌整机,弱信号;亦可能是海外购买的国产硬件)" ;;
      *KVM*|*QEMU*|*VMware*|*VirtualBox*|*Xen*|*"Microsoft Corporation"*|*OpenStack*|*"Alibaba Cloud"*|*"Tencent Cloud"*)
        report INFO hw/dmi "虚拟化平台: ${_pv:-?} ${_pn:-?}(云主机/VM —— 无线/蜂窝项不适用)" ;;
      *) report INFO hw/dmi "DMI: ${_pv:-?} ${_pn:-?}" ;;
    esac
  else
    report SKIP hw/dmi "(/sys/class/dmi 不可读 —— 容器常见)"
  fi

  # ── CPU 厂商(国产 CPU → 可疑弱信号) ──
  _cv=$(sed -n 's/^model name[[:space:]]*: *//p' /proc/cpuinfo 2>/dev/null | head -n 1)
  [ -z "$_cv" ] && _cv=$(sed -n 's/^vendor_id[[:space:]]*: *//p' /proc/cpuinfo 2>/dev/null | head -n 1)
  case "${_cv:-}" in
    *[Ll]oongson*|*龙芯*|*[Zz]haoxin*|*兆芯*|*[Pp]hytium*|*飞腾*|*[Hh]ygon*|*海光*|*Kunpeng*|*鲲鹏*)
      report SUSPICIOUS hw/cpu "CPU: $_cv(国产处理器 —— 国内采购环境特征,弱信号)" ;;
    "") report SKIP hw/cpu "(cpuinfo 不可读)" ;;
    *) report INFO hw/cpu "CPU: $_cv" ;;
  esac

  # ── 无线接口存在性(VPS 不该有;桌面/笔记本特征) ──
  _wif=0
  for _d in /sys/class/net/*/wireless; do
    [ -e "$_d" ] && _wif=1
  done
  if [ "$_wif" = 1 ]; then
    report INFO hw/wireless "存在物理无线接口(802.11)—— 桌面/笔记本特征(云主机不常见);监管域与关联网络需 --radio"
  else
    report CLEAN hw/wireless "无无线接口(有线/虚拟环境)"
  fi

  # ── --radio:监管域 / WiFi 关联 / WWAN MCC / GNSS ──
  if [ "$RADIO" != 1 ]; then
    report SKIP hw/radio "(默认关闭;--radio 可启用 iw 监管域/WiFi 关联状态/WWAN MCC/GNSS 存在性 —— 物理位置证据,仅桌面/物理机场景)"
    return
  fi

  if have iw; then
    _reg=$(iw reg get 2>/dev/null | sed -n 's/^country \([A-Z][A-Z]\):.*/\1/p' | head -n 1)
    if [ -n "${_reg:-}" ]; then
      case "$_reg" in
        CN) report SUSPICIOUS hw/reg-domain "WiFi 监管域 CN(内地;通常跟随最近关联 AP 所在国家 —— 物理在场弱证据)" ;;
        HK|MO) report INFO hw/reg-domain "WiFi 监管域 $_reg(港澳)" ;;
        *) report INFO hw/reg-domain "WiFi 监管域 $_reg" ;;
      esac
    else
      report SKIP hw/reg-domain "(iw reg 不可用或无权限)"
    fi
    # WiFi 关联状态(不输出 SSID/BSSID)
    for _i in $(ls /sys/class/net 2>/dev/null); do
      [ -e "/sys/class/net/$_i/wireless" ] || continue
      if iw dev "$_i" link 2>/dev/null | grep -q 'Connected'; then
        report INFO hw/wifi "$_i 已关联 WiFi(SSID/BSSID 不输出;BSSID 归属地查询属 --wifi-geo,未启用)"
      else
        report INFO hw/wifi "$_i 未关联"
      fi
    done
  else
    report SKIP hw/reg-domain "(无 iw;无线细节不可查)"
  fi

  # WWAN(蜂窝注册 MCC → local-access-net 物理证据)
  if have mmcli && mmcli --list-modems >/dev/null 2>&1; then
    _nmod=$(mmcli --list-modems 2>/dev/null | grep -oE 'Modem/[0-9]+' | grep -oE '[0-9]+' | head -n 3)
    for _m in $_nmod; do
      _mi=$(mmcli -m "$_m" 2>/dev/null)
      _mcc=$(printf '%s' "$_mi" | sed -n 's/^ *operator id: *//p' | head -n 1 | grep -oE '^4[0-9][0-9]')
      _op=$(printf '%s' "$_mi" | sed -n 's/^ *operator name: *//p' | head -n 1)
      case "${_mcc:-}" in
        460|461) report EXPOSED hw/wwan "蜂窝注册网络 MCC=${_mcc}(operator: ${_op:-未知})—— 中国大陆移动网络,物理在场实锤(local-access-net)" ;;
        *) [ -n "${_mcc:-}" ] && report INFO hw/wwan "蜂窝注册 MCC=$_mcc(operator: ${_op:-未知})" ;;
      esac
    done
  else
    report SKIP hw/wwan "(无 ModemManager 或无蜂窝模块)"
  fi

  # GNSS 守护存在性(不读坐标)
  if ps_filtered | grep -qE 'gpsd|geoclue'; then
    report INFO hw/gnss "GNSS 服务运行中(gpsd/GeoClue;坐标不读取;--wifi-geo 未启用,无外联)"
  else
    report SKIP hw/gnss "(无 gpsd/GeoClue)"
  fi
}
