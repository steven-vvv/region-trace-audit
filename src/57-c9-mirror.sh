#────────────────────────────── C9 mirror ──────────────────────────────
# 模块: 57-c9-mirror.sh

check_c9() {
  hdr "C9 mirror · 软件源与开发工具镜像"

  # ── 发行版源 ──
  _src_hit=""
  for _f in /etc/apt/sources.list /etc/apt/sources.list.d /etc/yum.repos.d /etc/dnf/dnf.conf /etc/yum.conf \
            /etc/pacman.d/mirrorlist /etc/apk/repositories /etc/zypp/repos.d; do
    [ -e "$_f" ] || continue
    _m=$(grep -rhE "$CN_MIRROR_RE" "$_f" 2>/dev/null | head -n 3 | sed 's/#.*//' | grep -vE '^\s*$' | head -n 2)
    if [ -n "$_m" ]; then
      _src_hit="${_src_hit:+$_src_hit; }$_f: $(printf '%s' "$_m" | head -n 1 | awk '{print $1,$2}' | cut -c1-80)"
    fi
  done
  if [ -n "$_src_hit" ]; then
    report SUSPICIOUS mirror/distro "发行版源命中国内镜像: $_src_hit(访问加速习惯,文化习惯类信号)"
  else
    report CLEAN mirror/distro "发行版源未命中国内镜像域名表"
  fi

  # ── 语言生态包管理器配置 ──
  _dev_hit=""
  _pipf=""
  for _c in "$HOME/.pip/pip.conf" "$HOME/.config/pip/pip.conf" /etc/pip.conf; do
    [ -r "$_c" ] && _pipf="$_c"
  done
  [ -n "$_pipf" ] && grep -qE "$CN_MIRROR_RE|douban" "$_pipf" 2>/dev/null && _dev_hit="pip($_pipf)"
  [ -r "$HOME/.npmrc" ] && grep -qE "$CN_MIRROR_RE|npmmirror|cnpm" "$HOME/.npmrc" 2>/dev/null && _dev_hit="${_dev_hit:+$_dev_hit; }npm(~/.npmrc)"
  for _c in "$HOME/.cargo/config" "$HOME/.cargo/config.toml"; do
    [ -r "$_c" ] && grep -qE "$CN_MIRROR_RE|sjtug|rsproxy" "$_c" 2>/dev/null && _dev_hit="${_dev_hit:+$_dev_hit; }cargo($_c)"
  done
  if have go; then
    _gp=$(go env GOPROXY 2>/dev/null)
    case "$_gp" in *goproxy.cn*|*goproxy.io*|*aliyun*) _dev_hit="${_dev_hit:+$_dev_hit; }go GOPROXY=$_gp" ;; esac
  fi
  [ -r "$HOME/.m2/settings.xml" ] && grep -qE "$CN_MIRROR_RE|aliyun" "$HOME/.m2/settings.xml" 2>/dev/null && _dev_hit="${_dev_hit:+$_dev_hit; }maven(~/.m2)"
  for _c in "$HOME/.composer/config.json" "$HOME/.config/composer/config.json" "$HOME/.gemrc"; do
    [ -r "$_c" ] && grep -qE "$CN_MIRROR_RE|aliyun|tencent" "$_c" 2>/dev/null && _dev_hit="${_dev_hit:+$_dev_hit; }$_c"
  done
  [ -r "$HOME/.condarc" ] && grep -qE "$CN_MIRROR_RE|tuna|sjtu" "$HOME/.condarc" 2>/dev/null && _dev_hit="${_dev_hit:+$_dev_hit; }conda(~/.condarc)"
  if [ -n "$_dev_hit" ]; then
    report SUSPICIOUS mirror/dev-eco "开发工具镜像命中: $_dev_hit(文化习惯类信号)"
  else
    report CLEAN mirror/dev-eco "pip/npm/cargo/go/maven/composer/conda 未命中国内镜像"
  fi

  # ── 开发镜像 env 变量(当前 env + rc 文件) ──
  _env_hit=""
  for _v in $DEV_MIRROR_ENVS; do
    _val=$(eval "printf '%s' \"\${$_v:-}\"")
    case "$_val" in
      *aliyun*|*taobao*|*tencent*|*cnpmjs*|*goproxy.cn*|*ustc*|*tuna*|*sjtu*|*nju*|*bfsu*|*huaweicloud*|*tencentyun*)
        _env_hit="${_env_hit:+$_env_hit; }$_v" ;;
    esac
  done
  for _r in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [ -r "$_r" ] || continue
    _m=$(grep -E "^[[:space:]]*(export[[:space:]]+)?[A-Z_]+=.*$" "$_r" 2>/dev/null | grep -E "$CN_DEV_MIRROR_VAL_RE" | head -n 3 | cut -d= -f1 | tr '\n' ' ')
    [ -n "$_m" ] && _env_hit="${_env_hit:+$_env_hit; }rc($(_r_basename "$_r"): $_m)"
  done
  if [ -n "$_env_hit" ]; then
    report SUSPICIOUS mirror/dev-env "开发镜像 env 变量命中: $_env_hit(文化习惯类信号)"
  else
    report CLEAN mirror/dev-env "无开发镜像 env 变量命中"
  fi

  # ── docker/containerd 镜像源 ──
  _dk_any=0; _dk_hit=""
  for _f in /etc/docker/daemon.json "$HOME/.docker/daemon.json" /etc/containerd/config.toml; do
    [ -e "$_f" ] && _dk_any=1
    [ -r "$_f" ] && grep -qE "$CN_MIRROR_RE|registry\.cn-|ccr\.ccs\.tencentyun" "$_f" 2>/dev/null && _dk_hit="${_dk_hit:+$_dk_hit; }$_f"
  done
  if [ -n "$_dk_hit" ]; then
    report SUSPICIOUS mirror/docker "容器镜像 mirror 命中: $_dk_hit"
  elif [ "$_dk_any" = 1 ]; then
    report CLEAN mirror/docker "docker/containerd 配置存在,未命中国内镜像"
  else
    report SKIP mirror/docker "(无 docker/containerd 配置)"
  fi

  # ── 已装软件与字体(包级 installed 态;运行态见 C14) ──
  _pkg_list=""
  if have rpm; then _pkg_list=$(rpm -qa 2>/dev/null)
  elif have dpkg; then _pkg_list=$(dpkg -l 2>/dev/null | awk '/^ii/{print $2}')
  fi
  if [ "$PLATFORM" = macos ]; then
    mac_check_apps
  elif [ -n "$_pkg_list" ]; then
    _ime=$(printf '%s' "$_pkg_list" | grep -iE "$CN_SOFT_PKG_RE" | head -n 6 | tr '\n' ' ')
    if has_text "$_ime"; then
      report SUSPICIOUS mirror/cn-apps "已安装国内软件/输入法: $_ime"
    else
      report CLEAN mirror/cn-apps "包列表未命中国内软件表"
    fi
  else
    report SKIP mirror/cn-apps "(rpm/dpkg 不可用)"
  fi
  if [ -d /usr/share/fonts ]; then
    _fnt=$(ls /usr/share/fonts 2>/dev/null | grep -iE "$CJK_FONT_RE" | head -n 4 | tr '\n' ' ')
    if has_text "$_fnt"; then
      report SUSPICIOUS mirror/cjk-fonts "CJK 字体已安装: $_fnt(弱证据)"
    else
      report CLEAN mirror/cjk-fonts "未见 CJK 字体目录"
    fi
  fi
}
