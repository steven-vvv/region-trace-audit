#────────────────────────────── C10 fs ──────────────────────────────
# 模块: 58-c10-fs.sh

check_c10() {
  hdr "C10 fs · 文件系统与人类痕迹(全可疑级)"

  # 家目录非 ASCII(启发式,主要捕捉中文)文件名
  if [ -n "$HOME" ] && [ -d "$HOME" ]; then
    _n=$(find "$HOME" -maxdepth 2 2>/dev/null | LC_ALL=C grep -c '[^ -~]' || true)
    _n=${_n:-0}
    if [ "$_n" -gt 0 ]; then
      report SUSPICIOUS fs/nonascii-names "家目录 2 层内 $_n 个非 ASCII 命名条目(启发式:可能为中文)"
    else
      report CLEAN fs/nonascii-names "家目录 2 层内无非 ASCII 命名"
    fi
  fi

  # gitconfig 身份与改写
  if [ -r "$HOME/.gitconfig" ]; then
    _mail=$(git config --global user.email 2>/dev/null || sed -n 's/.*email = //p' "$HOME/.gitconfig" | head -n 1)
    if [ -n "$_mail" ]; then
      case "$_mail" in
        *@qq.com|*@163.com|*@126.com|*@foxmail.com|*@sina.com|*@sohu.com|*@yeah.net|*@139.com|*@189.cn|*@aliyun.com)
          report SUSPICIOUS fs/git-email "git 全局邮箱 $(mask_mail "$_mail")(国内邮箱后缀)" ;;
        *) report CLEAN fs/git-email "git 全局邮箱 $(mask_mail "$_mail")" ;;
      esac
    fi
    if grep -qiE 'insteadof.*(ghproxy|fastgit|gh-proxy|gitee)' "$HOME/.gitconfig" 2>/dev/null; then
      report SUSPICIOUS fs/git-insteadof "git url.insteadOf 指向 ghproxy/fastgit/gitee(国内加速改写)"
    fi
  else
    report SKIP fs/gitconfig "(无 ~/.gitconfig)"
  fi

  # git 仓库 remote
  if have git && [ -d "$HOME" ]; then
    _gitee=0; _repos=0
    for _g in $(find "$HOME" -maxdepth 3 -name .git -type d 2>/dev/null | head -n 20); do
      _repos=$((_repos+1))
      if git -C "${_g%/.git}" remote -v 2>/dev/null | grep -q 'gitee\.com'; then
        _gitee=$((_gitee+1))
      fi
    done
    if [ "$_gitee" -gt 0 ]; then
      report SUSPICIOUS fs/git-gitee "扫描 $_repos 个仓库,$_gitee 个 remote 指向 gitee.com"
    elif [ "$_repos" -gt 0 ]; then
      report CLEAN fs/git-gitee "扫描 $_repos 个仓库,无 gitee remote"
    else
      report SKIP fs/git-gitee "(家目录 3 层内未发现 git 仓库)"
    fi
  else
    report SKIP fs/git-gitee "(git 不可用)"
  fi

  # known_hosts(行数/IP 计数;GeoIP 归属属 --deep-geo)
  _kh="$HOME/.ssh/known_hosts"
  if [ -r "$_kh" ]; then
    _kl=$(wc -l <"$_kh" | tr -d ' ')
    _ki=$(awk '{print $1}' "$_kh" 2>/dev/null | grep -cE '^[0-9a-fA-F.:]+$' || true)
    report INFO fs/known-hosts "$_kl 行,明文条目 ${_ki:-0}(GeoIP 归属查询属 --deep-geo)"
  else
    report SKIP fs/known-hosts "(无 ~/.ssh/known_hosts)"
  fi

  # ssh config
  if [ -r "$HOME/.ssh/config" ]; then
    _m=$(grep -iE 'HostName|ProxyJump' "$HOME/.ssh/config" 2>/dev/null | grep -E "$CN_DOMAIN_RE" | wc -l | tr -d ' ')
    if [ "${_m:-0}" -gt 0 ]; then
      report SUSPICIOUS fs/ssh-config "~/.ssh/config 有 $_m 处 HostName/ProxyJump 指向国内域名"
    else
      report CLEAN fs/ssh-config "~/.ssh/config 无国内域名目标"
    fi
  else
    report SKIP fs/ssh-config "(无 ~/.ssh/config)"
  fi

  # authorized_keys 注释
  if [ -r "$HOME/.ssh/authorized_keys" ]; then
    _c=$(awk 'NF>=3{print $NF}' "$HOME/.ssh/authorized_keys" 2>/dev/null | grep -cE "$CN_EMAIL_RE" || true)
    _zh=$(awk 'NF>=3{print $NF}' "$HOME/.ssh/authorized_keys" 2>/dev/null | LC_ALL=C grep -c '[^ -~]' || true)
    if [ "${_c:-0}" -gt 0 ] || [ "${_zh:-0}" -gt 0 ]; then
      report SUSPICIOUS fs/authorized-keys "authorized_keys 注释含国内邮箱(${_c:-0})或非 ASCII(${_zh:-0})"
    else
      report CLEAN fs/authorized-keys "authorized_keys 注释无特征"
    fi
  else
    report SKIP fs/authorized-keys "(无 authorized_keys)"
  fi

  # /etc/passwd:拼音用户名 / GECOS 中文名
  if [ -r /etc/passwd ]; then
    _u=$(printf '%s\n' "$CUR_USER")
    if is_pinyin_name "$_u"; then
      report SUSPICIOUS fs/passwd-username "用户名 $_u 疑似拼音姓名(启发式)"
    fi
    _gecos=$(grep "^${_u}:" /etc/passwd 2>/dev/null | cut -d: -f5)
    if printf '%s' "$_gecos" | LC_ALL=C grep -q '[^ -~]'; then
      report SUSPICIOUS fs/passwd-gecos "GECOS 字段含非 ASCII(可能为中文名)"
    fi
  fi

  # shell history:中文命令 / 国内域名(计数,不展示内容)
  _hh=0; _hd=0; _hf=0
  for _f in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"; do
    [ -r "$_f" ] || continue
    _hf=$((_hf+1))
    _x=$(LC_ALL=C grep -c '[^ -~]' "$_f" 2>/dev/null) || true; _x=${_x:-0}
    _hh=$((_hh+_x))
    _x=$(grep -cE "$CN_DOMAIN_RE" "$_f" 2>/dev/null) || true; _x=${_x:-0}
    _hd=$((_hd+_x))
  done
  if [ "$_hf" -gt 0 ]; then
    if [ "$_hh" -gt 0 ] || [ "$_hd" -gt 0 ]; then
      report SUSPICIOUS fs/history "history 含非 ASCII 行 ${_hh} / 国内域名行 $_hd(文化习惯类信号)"
    else
      report CLEAN fs/history "history 无中文/国内域名命中"
    fi
  else
    report SKIP fs/history "(无 history 文件或不可读)"
  fi

  # 蓝牙配对缓存 / WiFi 配置(通常需权限)
  if [ "$PLATFORM" = macos ]; then
    mac_check_devices
  else
  if [ -d /var/lib/bluetooth ] && [ -r /var/lib/bluetooth ]; then
    _bn=$(find /var/lib/bluetooth -mindepth 2 -maxdepth 2 -name info -exec grep -h '^Name=' {} \; 2>/dev/null | LC_ALL=C grep -c '[^ -~]' || true)
    if [ "${_bn:-0}" -gt 0 ]; then
      report SUSPICIOUS fs/bluetooth "蓝牙配对设备名含非 ASCII($_bn 个,可能为中文设备名)"
    else
      report CLEAN fs/bluetooth "蓝牙设备名无中文特征"
    fi
  else
    report SKIP fs/bluetooth "(不可读/无蓝牙缓存)"
  fi
  if [ -d /etc/NetworkManager/system-connections ] && [ -r /etc/NetworkManager/system-connections ] && ls -R /etc/NetworkManager/system-connections >/dev/null 2>&1; then
    _ws=$(grep -rh '^ssid=' /etc/NetworkManager/system-connections 2>/dev/null | LC_ALL=C grep -c '[^ -~]' || true)
    if [ "${_ws:-0}" -gt 0 ]; then
      report SUSPICIOUS fs/wifi-ssid "WiFi 配置含非 ASCII SSID($_ws 个)"
    else
      report CLEAN fs/wifi-ssid "WiFi SSID 无中文特征"
    fi
  else
    report SKIP fs/wifi-ssid "(无权限读 NM 配置)"
  fi

  fi

  # 国内软件数据目录
  _sd=""
  for _d in $CN_SOFT_DIRS; do
    [ -e "$HOME/$_d" ] && _sd="${_sd:+$_sd; }$_d"
  done
  if [ -n "$_sd" ]; then
    report SUSPICIOUS fs/cn-soft-dirs "国内软件数据目录存在: $_sd"
  else
    report CLEAN fs/cn-soft-dirs "无国内软件数据目录命中"
  fi

  # rc 文件:proxy 函数/国内域引用(SSH_* 伪造归 C12)
  for _r in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [ -r "$_r" ] || continue
    if grep -qE 'gitee|ghproxy|aliyun|taobao|bilibili' "$_r" 2>/dev/null; then
      report SUSPICIOUS fs/rc-domains "$(_r_basename "$_r") 含国内域名引用(文化习惯类信号)"
    fi
  done
}
