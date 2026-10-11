#────────────────────────────── C19 gui ──────────────────────────────
# 模块: 65-c19-gui.sh
# 定位:图形会话、输入法与远程桌面四态;产品本身 INFO,不判可疑
# 红线:不截图、不读剪贴板/按键/窗口内容;客户端元数据交 C20

check_c19() {
  hdr "C19 gui · 图形会话、输入与远程桌面"

  if [ "$PLATFORM" = macos ]; then
    if mac_console_user >/dev/null; then
      report INFO gui/session "macOS console 图形用户已登录(Aqua;不以 DISPLAY/X11 判定)"
    else
      report SKIP gui/session "(scutil 无可见 console 用户;未登录或权限受限,不推断无桌面)"
    fi
    report INFO gui/ime "macOS 输入源由 macos 类读取 HIToolbox(单项 gui 请另运行 --section macos)"
    report INFO gui/fonts "macOS 内置 CJK 字体不作用户痕迹;用户字体由 macos 类检查"
    mac_check_remote_desktop
    return
  fi

  # ── 图形会话存在性 ──
  _gui=0; _guit=""
  [ -n "${DISPLAY:-}" ] && { _gui=1; _guit="$_guit X11(DISPLAY)"; }
  [ -n "${WAYLAND_DISPLAY:-}" ] && { _gui=1; _guit="$_guit Wayland"; }
  [ "${XDG_SESSION_TYPE:-}" = x11 ] || [ "${XDG_SESSION_TYPE:-}" = wayland ] && { _gui=1; _guit="$_guit $XDG_SESSION_TYPE(env)"; }
  [ -d /mnt/wslg ] && { _gui=1; _guit="$_guit WSLg"; }
  if have loginctl; then
    _lc=$(loginctl list-sessions --no-legend 2>/dev/null)
    if [ -n "$_lc" ]; then
      _gln=0
      while read -r _sid _uid _user _seat _tty _rest; do
        [ -z "${_sid:-}" ] && continue
        case "$_sid" in ''|*[!0-9]*) continue ;; esac
        _t=$(loginctl show-session "$_sid" -p Type --value 2>/dev/null)
        case "$_t" in x11|wayland) _gln=$((_gln+1)) ;; esac
      done <<EOF
$_lc
EOF
      [ "$_gln" -gt 0 ] && { _gui=1; _guit="$_guit 图形会话x$_gln(logind)"; }
    fi
  fi
  if [ "$_gui" = 1 ]; then
    report INFO gui/session "存在图形会话:${_guit# }"
    [ -n "${CURRENT_DESKTOP:-}" ] && report INFO gui/de "桌面环境: $CURRENT_DESKTOP"
    # 虚拟显示(Xvfb/vkms —— 无人值守桌面特征)
    if ps_filtered | grep -qE 'Xvfb|Xvnc|vkms'; then
      report INFO gui/virtual-display "检测到虚拟显示服务(Xvfb/Xvnc/vkms —— 无人值守桌面/远控载体常见)"
    fi
  else
    report SKIP gui/session "(无图形会话 —— headless/服务器场景,输入法与桌面项不适用)"
  fi

  # ── 键盘布局(XKB) ──
  if have localectl && localectl status >/dev/null 2>&1; then
    _lk=$(localectl status 2>/dev/null | sed -n 's/^ *X11 Layout: *//p')
    [ -z "$_lk" ] && _lk=$(localectl status 2>/dev/null | sed -n 's/^ *VC Keymap: *//p')
    case "${_lk:-}" in
      cn|zh*) report SUSPICIOUS gui/xkb "键盘布局 ${_lk}(文化习惯类信号)" ;;
      "") : ;;
      *) report INFO gui/xkb "键盘布局 $_lk" ;;
    esac
  fi

  # ── 输入法(仅图形/桌面上下文才判软信号;headless 下存在即 INFO) ──
  _ime=""
  ps_filtered | grep -q 'fcitx' && _ime="fcitx"
  ps_filtered | grep -q 'ibus-daemon' && _ime="${_ime:+$_ime }ibus"
  ps_filtered | grep -qi 'sogou' && _ime="${_ime:+$_ime }sogou"
  for _f in "$HOME/.config/fcitx/profile" "$HOME/.local/share/fcitx5/profile" "$HOME/.config/fcitx5/profile"; do
    if [ -r "$_f" ] && grep -qiE 'pinyin|shuangpin|wubi|cangjie|sogou' "$_f" 2>/dev/null; then
      if [ "$_gui" = 1 ]; then
        report SUSPICIOUS gui/ime "中文输入法配置($_f 含拼音/双拼/五笔引擎;文化习惯类信号)"
      else
        report INFO gui/ime "中文输入法配置存在($_f;当前无图形会话,降级为信息 —— 可能是构建残留或未启动桌面)"
      fi
    fi
  done
  [ -n "$_ime" ] && report INFO gui/ime-proc "输入法框架运行中: $_ime(引擎配置见上,若无命中则未发现中文引擎)"
  [ "$_gui" = 0 ] && [ -z "$_ime" ] && report SKIP gui/ime "(headless,无输入法)"

  # ── CJK 字体 ──
  if have fc-list; then
    _fc=$(fc-list :lang=zh 2>/dev/null | wc -l | tr -d ' ')
    if [ "${_fc:-0}" -gt 0 ]; then
      if [ "$_gui" = 1 ]; then
        report SUSPICIOUS gui/fonts "CJK 中文字体已安装($_fc 个;文化习惯类信号)"
      else
        report INFO gui/fonts "CJK 中文字体已安装($_fc 个;当前无图形会话,降级为信息 —— 可能是依赖带入或构建残留)"
      fi
    else
      report CLEAN gui/fonts "无 CJK 字体"
    fi
  else
    report SKIP gui/fonts "(无 fc-list)"
  fi

  # ── 远程桌面四态(installed/enabled/listening/connected) ──
  # 格式: 二进制|unit|端口列表|产品名
  _rd_list="xrdp|xrdp.service|3389|xrdp
vncserver|vncserver@.service|5900 5901 5902 5903|TigerVNC
x11vnc||5900|x11vnc
rustdesk|rustdesk.service|21115 21116 21117 21118 21119|RustDesk
anydesk|anydesk.service|7070|AnyDesk
teamviewer|teamviewerd.service|5938|TeamViewer
todesk|todesk.service|11111|ToDesk
sunloginclient|sunloginclient.service|53200|向日葵
nxserver|nxserver.service|4000|NoMachine
sunshine|sunshine.service|47984 47989 47990|Sunshine
gnome-remote-desktop|gnome-remote-desktop.service|3389 5900|GNOME Remote Desktop
uuremote|uuremote.service||UU远程(网易)
chrome-remote-desktop|chrome-remote-desktop.service||Chrome Remote Desktop
parsecd|parsec.service|8000 8001 8002|Parsec"
  _rd_any=0; RD_CONNECTED=""
  while IFS='|' read -r _bin _unit _ports _name; do
    [ -z "$_bin" ] && continue
    _inst=""
    have "$_bin" && _inst=bin
    [ -z "$_inst" ] && [ "$_name" = "UU远程(网易)" ] && { ls -d /opt/uu* "$HOME/.config/UURemote" "$HOME/.uuremote" >/dev/null 2>&1 && _inst=dir; ps_filtered | grep -qi 'uuremote' && _inst=proc; }
    [ -z "$_inst" ] && [ "$_name" = "Chrome Remote Desktop" ] && ls -d "$HOME/.config/chrome-remote-desktop" >/dev/null 2>&1 && _inst=dir
    if [ -n "$_unit" ] && [ "$_inst" = bin ]; then
      :
    elif [ -n "$_unit" ]; then
      for _ud in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [ -e "$_ud/$_unit" ] && _inst=unit
      done
    fi
    [ -z "$_inst" ] && continue
    _rd_any=1
    _st="installed"
    if have systemctl && [ -n "$_unit" ]; then
      systemctl is-enabled "$_unit" >/dev/null 2>&1 && _st="$_st+enabled"
    fi
    # listening/connected:检查 /proc/net/tcp{,6} 端口
    _lp=""; _cp=""
    for _p in $_ports; do
      _ph=$(printf '%04X' "$_p" 2>/dev/null)
      [ -z "$_ph" ] && continue
      for _tf in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$_tf" ] || continue
        if awk -v port=":$_ph " '$4=="0A" && $2 ~ port":" {found=1} END{exit !found}' "$_tf" 2>/dev/null; then :; fi
        if grep -q ":$_ph .*0A " "$_tf" 2>/dev/null; then _lp="$_lp $_p"; fi
        if grep -q ":$_ph .*01 " "$_tf" 2>/dev/null; then _cp="$_cp $_p"; fi
      done
    done
    [ -n "$_lp" ] && _st="$_st+listening($_lp )"
    [ -n "$_cp" ] && _st="$_st+connected($_cp )"
    _lvl=INFO
    case "$_st" in *connected*) _lvl=SUSPICIOUS; RD_CONNECTED="$RD_CONNECTED $_name" ;; esac
    report "$_lvl" "gui/rd" "$_name: $_st(远程桌面产品为环境上下文;connected=存在活动会话)"
  done <<EOF
$_rd_list
EOF
  [ "$_rd_any" = 0 ] && report CLEAN gui/rd "未发现常见远程桌面产品(xrdp/VNC/RustDesk/AnyDesk/TeamViewer/ToDesk/向日葵/NoMachine/Sunshine/GRD)"
}
