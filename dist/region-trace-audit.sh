#!/bin/sh
#─────────────────────────────────────────────────────────────────────────────
# region-trace-audit — 陆港澳用户环境痕迹检测器
#
# 定位:独立的只读审计工具,检测本机是否存在暴露「使用者来自中国大陆/
# 香港/澳门」的痕迹,或伪装失败留下的矛盾痕迹。
# 判定五态:暴露 / 可疑 / 正常 / 信息 / 跳过(依赖缺失时注明原因)。
#
# v0.2 范围(本地 + active-probe 网络探测):
#   C1  sysinfo   系统与平台(含 u0 采集者边界)
#   C2  cloud     中资云与定制系统(信息级)
#   C16 boot      引导、初始化与持久化来源(上下文层,归因)
#   C17 kernelnet 内核、命名空间与网络数据面(上下文层)
#   C18 session   会话图与远程入口分类(活跃 SSH 对端;自身对端 GeoIP)
#   WS  wsl       WSL interop(Windows 侧区域/时区/代理/hosts,仅 WSL)
#   MAC macos     macOS 适配层(系统区域/系统代理/launchd/输入法/字体/Homebrew)
#   C3  egress    出口与 GeoIP(双源交叉,rDNS,双栈一致性;--deep-geo 连接图谱)
#   C4  path      链路与本地网络(traceroute CN 骨干、网关 OUI、MTU、CGNAT)
#   C5  proxy     代理、隧道、分流与覆盖网络(Tailscale/cloudflared/WARP 角色)
#   C6  dns       DNS 卫生(解析器归属、污染探测、hosts、加密 DNS)
#   C8  locale    地域配置(系统层,含出口时区交叉比对)
#   C9  mirror    软件源与开发工具镜像
#   C10 fs        文件系统与人类痕迹
#   C12 anti      隐藏与伪造痕迹(带上下文修正)
#   C19 gui       图形会话、输入法与远程桌面四态(桌面场景)
#   C15 browser   浏览器痕迹(搜索引擎/语言/国内域名计数;不读 URL 明文)
#   C13 hw        硬件/DMI/CPU 品牌;--radio 无线监管域/WWAN MCC(物理证据)
#   C11 time      时间行为统计 → 作息时区推断 + 时区一致性 + 内地假日/调休日历检验
#   C20 usegeo    实际使用地区融合视图(会话链/出口/链路断点/证据家族)
#   C14 services  进程、端口与服务
#
# 用法: region-trace-audit.sh [--brief] [--no-color] [--reveal] [--offline] [--deep-geo]
#                              [--section sysinfo|cloud|boot|kernelnet|session|egress|path|proxy|dns|wsl|locale|mirror|fs|anti|services]
# 退出码: 0=无异常  1=存在可疑  2=存在暴露
# 立场:一致性体检。不评判、不承诺任何规避效果。设计文档见仓库 PLAN.md。
#
# 源码结构:src/ 目录按序号分模块,build.sh 拼接为本单文件。
#─────────────────────────────────────────────────────────────────────────────
# shellcheck shell=sh   # 注:使用 local(dash/ash/bash/zsh 均支持,非严格 POSIX)

VERSION="0.6"

#────────────────────────────── 选项解析 ──────────────────────────────
# 模块: 10-options.sh

BRIEF=0; NOCOLOR=0; REVEAL=0; SECTION="all"; OFFLINE=0; DEEP_GEO=0; RADIO=0; JSON=0

usage() {
cat <<EOF
region-trace-audit v$VERSION — 陆港澳用户环境痕迹检测器(只读)

用法: region-trace-audit.sh [选项]
  --brief            只实时输出 可疑/暴露 行(汇总仍完整)
  --no-color         禁用颜色(亦遵循 NO_COLOR 环境变量/非终端自动禁用)
  --reveal           显示完整 IP/邮箱(默认脱敏:IP 前两段、邮箱用户名掩码)
  --offline          跳过一切外联(出口/路由/DNS 探测转为跳过,本地项照常)
  --deep-geo         对 known_hosts 与活跃连接对端做 GeoIP(向 ip-api 发送待查 IP;
                     默认关闭,开启前请知悉)
  --json             机器可读输出(单 JSON 对象,替代人读报告;退出码不变)
  --section <cat>    只运行指定类别: sysinfo macos cloud boot kernelnet session
                                  egress path proxy dns wsl locale mirror fs anti
                                  services gui browser hw time usegeo
  --radio            启用无线/蜂窝检查(iw 监管域/WiFi 关联/WWAN MCC/GNSS;物理在场证据)
  -h, --help         本帮助

v0.5 新增:macOS 适配层(系统区域/系统代理/launchd/输入法/用户字体/Homebrew)、
--json 机器可读输出(单 JSON 对象:meta/summary/items/usegeo_view,退出码不变)。
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --brief)    BRIEF=1 ;;
    --no-color) NOCOLOR=1 ;;
    --reveal)   REVEAL=1 ;;
    --offline)  OFFLINE=1 ;;
    --deep-geo) DEEP_GEO=1 ;;
    --radio)    RADIO=1 ;;
    --json)     JSON=1 ;;
    --section)  shift; SECTION="${1:-}"; [ -z "$SECTION" ] && SECTION="all" ;;
    -h|--help)  usage; exit 0 ;;
    *) printf '未知参数: %s(见 --help)\n' "$1" >&2; exit 64 ;;
  esac
  shift
done

#────────────────────────────── 框架:颜色 / 报告 / 脱敏 / 通用工具 ──────────────────────────────
# 模块: 20-framework.sh

if [ "$NOCOLOR" = 0 ] && [ -t 1 ] && [ -z "$NO_COLOR" ]; then
  C_EXP=$(printf '\033[1;31m'); C_SUS=$(printf '\033[33m')
  C_CLN=$(printf '\033[32m');   C_INF=$(printf '\033[36m')
  C_SKP=$(printf '\033[90m');   C_HDR=$(printf '\033[1m')
  C_RST=$(printf '\033[0m')
else
  C_EXP=""; C_SUS=""; C_CLN=""; C_INF=""; C_SKP=""; C_HDR=""; C_RST=""
fi

CNT_EXP=0; CNT_SUS=0; CNT_CLN=0; CNT_INF=0; CNT_SKP=0
LOG_EXP=""; LOG_SUS=""; JSON_LOG=""
TZ_MAIN=""; INSTALL_AGE_DAYS=0

# report <LEVEL> <cat/item> <desc>   —— desc 必须单行
report() {
  _rl="$1"; _rc="$2"; _rd="$3"
  case "$_rl" in
    EXPOSED)    CNT_EXP=$((CNT_EXP+1)); LOG_EXP="${LOG_EXP}${_rc}|${_rd}
"; _m='✗'; _c="$C_EXP"; _w='暴露' ;;
    SUSPICIOUS) CNT_SUS=$((CNT_SUS+1)); LOG_SUS="${LOG_SUS}${_rc}|${_rd}
"; _m='!'; _c="$C_SUS"; _w='可疑' ;;
    CLEAN)      CNT_CLN=$((CNT_CLN+1)); _m='✓'; _c="$C_CLN"; _w='正常' ;;
    INFO)       CNT_INF=$((CNT_INF+1)); _m='*'; _c="$C_INF"; _w='信息' ;;
    SKIP)       CNT_SKP=$((CNT_SKP+1)); _m='-'; _c="$C_SKP"; _w='跳过' ;;
    *) return 0 ;;
  esac
  if [ "${JSON:-0}" = 1 ]; then
    JSON_LOG="${JSON_LOG}${_rl}|${_rc}|$(json_escape "$_rd")
"
    return 0
  fi
  if [ "$BRIEF" = 0 ] || [ "$_rl" = "EXPOSED" ] || [ "$_rl" = "SUSPICIOUS" ]; then
    printf '%s[%s]%s %-20s %s %s→ %s%s%s\n' \
      "$_c" "$_m" "$C_RST" "[$_rc]" "$_rd" "$C_SKP" "$_c" "$_w" "$C_RST"
  fi
}

hdr() {  # 类别标题
  [ "${JSON:-0}" = 1 ] && return 0
  [ "$BRIEF" = 0 ] && printf '\n%s── %s ──%s\n' "$C_HDR" "$1" "$C_RST"
}

# JSON 字符串转义:反斜杠/引号/制表/回车转义,换行合并为 \n,
# 竖线转 \u007c —— 保证转义后不含字段分隔符与裸控制字符(防环境值注入破坏 JSON)
json_escape() {
  printf '%s\n' "$1" | LC_ALL=C awk '
    { if (NR>1) buf = buf "\\n"
      line = $0
      gsub(/\\/, "\\\\", line); gsub(/"/, "\\\"", line)
      gsub(/\t/, "\\t", line); gsub(/\r/, "\\r", line)
      gsub(/\|/, "\\u007c", line)
      buf = buf line }
    END { printf "%s", buf }' | LC_ALL=C tr -d '\001-\011\013\014\016-\037'
}

# JSON 输出(--json):items 全量 + 汇总 + usegeo 视图;单对象输出到 stdout
json_emit() {
  _esc='s/\\/\\\\/g; s/"/\\"/g'
  printf '{'
  printf '"meta":{'
  printf '"version":"%s","platform":"%s","generated":"%s"' "$VERSION" "$PLATFORM" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf ',"mode":{'
  printf '"offline":%s,"deep_geo":%s,"radio":%s,"reveal":%s' \
    "$([ "$OFFLINE" = 1 ] && printf true || printf false)" \
    "$([ "$DEEP_GEO" = 1 ] && printf true || printf false)" \
    "$([ "$RADIO" = 1 ] && printf true || printf false)" \
    "$([ "$REVEAL" = 1 ] && printf true || printf false)"
  printf '}}'
  printf ',"summary":{"exposed":%d,"suspicious":%d,"clean":%d,"info":%d,"skip":%d,"exit_code":%d}' \
    "$CNT_EXP" "$CNT_SUS" "$CNT_CLN" "$CNT_INF" "$CNT_SKP" "$EXIT_CODE"
  printf ',"items":['
  printf '%s' "$JSON_LOG" | awk -F'|' '
    NR>1 { printf "," }
    {
      item=$2; msg=$3
      cat = item; sub(/\/.*$/, "", cat)
      # msg 已在 report() 预转义(json_escape),不再二次转义
      printf "{\"level\":\"%s\",\"category\":\"%s\",\"item\":\"%s\",\"message\":\"%s\"}", $1, cat, item, msg
    }'
  printf ']'
  printf ',"usegeo_view":['
  printf '%s' "${USEGEO_VIEW:-}" | LC_ALL=C awk '
    NF>0 { if (n++) printf ","
      t=$0
      gsub(/\\/, "\\\\", t); gsub(/"/, "\\\"", t); gsub(/\|/, "\\u007c", t)
      printf "\"%s\"", t }'
  printf ']'
  printf '}\n'
}

mask_ip() {
  [ "$REVEAL" = 1 ] && { printf '%s' "$1"; return; }
  case "$1" in
    *:*) printf '%s' "$1" | awk -F: '{print $1":"$2"::(v6)"}' ;;
    *.*) printf '%s' "$1" | awk -F. '{print $1"."$2".x.x"}' ;;
    *)   printf '%s' "$1" ;;
  esac
}
mask_mail() {
  [ "$REVEAL" = 1 ] && { printf '%s' "$1"; return; }
  printf '%s' "$1" | awk -F@ '{ if (NF==2) printf "%c**@%s", substr($1,1,1), $2; else print "***" }'
}
_m_url() {
  [ "$REVEAL" = 1 ] && { printf '%s' "$1"; return; }
  printf '%s' "$1" | sed 's|\(https\?://[^/]*\).*|\1/…|'
}

have() { command -v "$1" >/dev/null 2>&1; }

has_text() { printf '%s' "$1" | grep -q '[^[:space:]]'; }

# GNU/BSD stat: validate numeric output (GNU stat -f prints filesystem metadata).
fs_mtime() (
  _mt=$(stat -c %Y "$1" 2>/dev/null) || _mt=""
  case "$_mt" in ''|*[!0-9]*) _mt=$(stat -f %m "$1" 2>/dev/null) || _mt="" ;; esac
  case "$_mt" in ''|*[!0-9]*) return 1 ;; *) printf '%s\n' "$_mt" ;; esac
)

# Consume newline-delimited paths without splitting spaces, quotes or backslashes.
# Filenames containing a newline remain outside this bounded sampling format.
file_mtimes() (
  while IFS= read -r _mf; do
    [ -f "$_mf" ] && fs_mtime "$_mf"
  done
  :
)

# 文件时间戳(birth 优先,回退 mtime;GNU/BSD 兼容;空=不可得)
fs_btime() {
  _t=""
  _t=$(stat -c %W "$1" 2>/dev/null) || _t=""
  case "$_t" in ""|0)
    _t=$(stat -f %B "$1" 2>/dev/null) || _t=""
  esac
  case "$_t" in ""|0)
    _t=$(stat -c %Y "$1" 2>/dev/null) || _t=""
    case "$_t" in ""|0) _t=$(stat -f %m "$1" 2>/dev/null) || _t="" ;; esac
  esac
  case "$_t" in ""|0|*[!0-9]*) printf '' ;; *) printf '%s' "$_t" ;;
  esac
}

_r_basename() { printf '%s' "$1" | sed 's|.*/||'; }

# 进程表(快照优先 —— 在 collector_context 采集并排除自身进程树;
# 实时采集会抓到本脚本自己的管道子进程(如 grep -q fcitx 的 argv),造成自匹配)
ps_filtered() {
  if [ -n "${PS_SNAP:-}" ]; then
    printf '%s\n' "$PS_SNAP"
  else
    { ps aux 2>/dev/null || ps -ef 2>/dev/null; } | awk -v pids="${MY_PIDS:- }" 'index(pids, " " $2 " ") == 0'
  fi
}

#────────────────────────────── 内置数据表与判定谓词 ──────────────────────────────
# 模块: 30-tables.sh
# 说明:全部为静态数据与纯函数,不产生副作用

# 时区分类:CN=陆港澳确定时区(含历史链接名) HKMO E8=非陆港澳东八 OTHER
tz_class() {
  case "$1" in
    Asia/Shanghai|Asia/Chongqing|Asia/Harbin|Asia/Chungking|Asia/PRC|PRC|\
    Asia/Urumqi|Asia/Kashgar) printf 'CN' ;;
    Asia/Hong_Kong|Asia/Hongkong|Hongkong|Asia/Macau|Asia/Macao|Macau|Macao) printf 'HKMO' ;;
    Asia/Singapore|Asia/Kuala_Lumpur|Asia/Kuching|Asia/Brunei|Asia/Makassar|\
    Asia/Manila|Asia/Taipei|Asia/Choibalsan|Asia/Ulaanbaatar|Asia/Irkutsk|\
    Australia/Perth) printf 'E8' ;;
    *) printf 'OTHER' ;;
  esac
}

# 时区 UTC 偏移(如 +0800;依赖 date 的 TZ 语义)
tz_offset() { TZ="$1" date +%z 2>/dev/null; }

cnname() { case "$1" in CN) printf '中国大陆';; HK) printf '香港';; MO) printf '澳门';; *) printf '%s' "$1";; esac; }

# 拼音姓名启发式:精确命中姓氏/名,或两段拼接均为表内词(保守,防误报)
PINYIN_SURNAME='wang li zhang liu chen yang huang zhao wu zhou xu sun ma zhu hu guo he gao lin luo zheng liang xie song tang deng feng han cao zeng peng xiao tian dong pan yuan yu ye du su wei cheng lu ding ren shen yao jiang cui zhong tan'
PINYIN_GIVEN='wei ming hong tao jun jing lei fang qiang yong hua yu tian xin yun fei yue hang chen xi zhe hao nan shuai bo chao peng yu jia qi lin yang cheng long xin jian guo qing xue ying juan min li na ting yan qin yue zhen rui ze kai lang jie'

is_pinyin_name() {
  _h=$(printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d '._-')
  case " $PINYIN_SURNAME " in *" $_h "*) return 0 ;; esac
  case " $PINYIN_GIVEN " in *" $_h "*) return 0 ;; esac
  if [ "${#_h}" -ge 4 ] && [ "${#_h}" -le 12 ]; then
    _i=2
    while [ "$_i" -lt "$(( ${#_h} - 1 ))" ]; do
      _a=$(printf '%s' "$_h" | cut -c1-"$_i"); _b=$(printf '%s' "$_h" | cut -c"$(($_i+1))"-)
      case " $PINYIN_SURNAME $PINYIN_GIVEN " in *" $_a "*) case " $PINYIN_GIVEN " in *" $_b "*) return 0 ;; esac ;; esac
      _i=$((_i+1))
    done
  fi
  return 1
}

# Windows 时区名分类(陆港澳共用 China Standard Time;E8=东八非陆港澳)
win_tz_class() {
  case "$1" in
    "China Standard Time") printf 'CN' ;;
    "Taipei Standard Time"|"Singapore Standard Time"|"Kuala Lumpur Standard Time"|\
    "W. Australia Standard Time"|"Irkutsk Standard Time"|"Ulaanbaatar Standard Time") printf 'E8' ;;
    *) printf 'OTHER' ;;
  esac
}

# 时区名 → 十进制小时偏移(Asia/Shanghai → 8.0;失败 → 空串)
tz_off_hours() {
  _o=$(tz_offset "$1" 2>/dev/null)
  case "$_o" in
    [+-][0-9][0-9][0-9][0-9]) ;;
    *) printf '' ; return ;;
  esac
  _s=${_o%????}; _hm=${_o#?}; _h=${_hm%??}; _m=${_hm#??}
  case "$_h" in 0?) _h=${_h#0} ;; esac
  case "$_m" in 0?) _m=${_m#0} ;; esac
  _v=$((_h * 60 + _m)); [ "$_s" = "-" ] && _v=$((- _v))
  awk "BEGIN{printf \"%.1f\", $_v/60}"
}

# ── 内地法定假日与调休补班日(国务院办公厅通知;2024–2026;2027 待公布) ──
# 调休补班日 = 内地特有的「周末上班日」;港澳及海外无此实践 → 遵循该日历是内地工作节奏的强特征
CN_HOLIDAYS="20240101 20240210 20240211 20240212 20240213 20240214 20240215 20240216 20240217 20240404 20240405 20240406 20240501 20240502 20240503 20240504 20240505 20240610 20240915 20240916 20240917 20241001 20241002 20241003 20241004 20241005 20241006 20241007 20250101 20250128 20250129 20250130 20250131 20250201 20250202 20250203 20250204 20250404 20250405 20250406 20250501 20250502 20250503 20250504 20250505 20250531 20250601 20250602 20251001 20251002 20251003 20251004 20251005 20251006 20251007 20251008 20260101 20260102 20260103 20260215 20260216 20260217 20260218 20260219 20260220 20260221 20260222 20260223 20260404 20260405 20260406 20260501 20260502 20260503 20260504 20260505 20260619 20260620 20260621 20260925 20260926 20260927 20261001 20261002 20261003 20261004 20261005 20261006 20261007"
CN_MAKEUP="20240204 20240218 20240407 20240428 20240511 20240914 20240929 20241012 20250126 20250208 20250427 20250928 20251011 20260104 20260214 20260228 20260509 20260920 20261010"

# ── 正则表 ──
CN_MIRROR_RE='mirrors\.aliyun\.com|mirrors\.tuna\.|mirrors\.ustc\.edu|mirrors\.163\.com|mirror\.sjtu\.edu|mirrors\.huaweicloud\.com|repo\.huaweicloud\.com|mirrors\.tencent\.com|mirrors\.cloud\.tencent\.com|mirrors\.bfsu\.edu|mirror\.nju\.edu|mirrors\.zju\.edu|mirrors\.cqu\.edu'
CLOUD_INT_MIRROR_RE='mirrors\.cloud\.aliyuncs\.com|mirrors\.tencentyun\.com|mirrors\.myhuaweicloud\.com|mirror\.tencentyun'
CN_EMAIL_RE='@(qq|163|126|foxmail|sina|sohu|yeah|139|189|aliyun)\.(com|cn|net)|@189\.cn'
CN_DOMAIN_RE='baidu\.com|taobao|tmall|aliyun|jd\.com|bilibili|qq\.com|163\.com|weibo|zhihu|douyin|csdn\.net|gitee\.com|cnblogs|51cto|aliyuncs|tencentcloud|huaweicloud|ghproxy|fastgit|gh-proxy|lanzn|moeyy'
CN_DEV_MIRROR_VAL_RE='taobao|aliyun|tencent|npmmirror|cnpmjs|goproxy\.cn|goproxy\.io|ustc|tuna|sjtu|nju|bfsu|huaweicloud|tencentyun|github\.cnpmjs|mirrors\.cloud'
CJK_FONT_RE='wqy|wenquanyi|noto.*cjk|cjk|source-han|opposans|misans|harmonyossans|alibaba.*puhui'
CN_NTP_RE='aliyun|tencent|cn\.pool\.ntp|ntp\.org\.cn|time\.edu|ntp\.aliyun'

# ── 进程 / 端口 / 云特征 ──
CLOUD_AGENT_PROC_RE='AliYunDun|aliyun-service|aegis|AliyunDunUpdate|barad|YDService|YDLive|yunjing|qcloud|telescope|VolcanoAgent|argus'
CLOUD_AGENT_DIRS='/usr/local/aegis /usr/local/qcloud /usr/local/telescope /usr/local/cloudmonitor /usr/local/sa /usr/local/ubt'
CN_CLOUD_DMI_RE='Alibaba|Tencent|HUAWEI CLOUD|Volcano|CTYUN|UCloud|Kingsoft|Baidu'
PROXY_PORT_LIST='7890 7891 7892 7897 10808 10809 8388 8118 3128 9090 7895 20170 20171'
PROXY_PROC_RE='clash|mihomo|v2ray|xray|ss-local|ssr-|hysteria|trojan|sing-box|naive|brook|snell'
CN_APP_PROC_RE='WeChat|weixin|linuxqq|dingtalk|wps|baidunetdisk|xunlei|netease-cloud|youku'
CN_SOFT_PKG_RE='^(fcitx|ibus-rime|rime|fcitx5|sogou|wechat|weixin|electronic-wechat|qq|linuxqq|dingtalk|wps|baidunetdisk|xunlei|baidupcs|netease-cloud-music|youku)'
CN_SOFT_DIRS='.xwechat_files .config/qq .config/QQ .config/dingtalk .config/baidunetdisk BaiduNetdiskDownload xunlei-download .config/netease-cloud-music .config/NetEase'
DEV_MIRROR_ENVS='ELECTRON_MIRROR ELECTRON_CUSTOM_DIR NVM_NODEJS_ORG_MIRROR NODEJS_ORG_MIRROR SASS_BINARY_SITE SASS_BINARY_PATH PHANTOMJS_CDNURL CHROMEDRIVER_CDNURL PUPPETEER_DOWNLOAD_HOST PUPPETEER_DOWNLOAD_BASE_URL SENTRYCLI_CDNURL PYTHON_INDEX_URL PIP_INDEX_URL GOPROXY HOMEBREW_BOTTLE_DOMAIN HOMEBREW_API_DOMAIN NPM_CONFIG_REGISTRY YARN_REGISTRY MAVEN_MIRROR'

# ── 网络类数据表(v0.2) ──
# 国内公共 DNS
CN_PUBLIC_DNS=" 114.114.114.114 114.114.115.115 223.5.5.5 223.6.6.6 119.29.29.29 119.28.28.28 180.76.76.76 1.2.4.8 210.2.4.8 182.254.116.116 182.254.118.118 123.125.81.6 140.207.198.6 "
# 已知 DNS 注入假 IP(公开文献记录的稳定集合,小而保守)
FAKE_IPS=" 8.7.198.45 46.82.174.68 59.24.3.173 78.16.49.15 93.46.8.89 159.106.121.75 203.98.7.65 243.185.187.39 37.61.54.158 4.36.66.178 "
# 国内网络设备厂商 OUI 前缀(华为/荣耀/TP-Link/小米/H3C 等常见段;启发式,弱证据)
GW_OUI_CN_LIST="00:18:82 34:6B:D3 48:46:FB 58:60:5F 88:28:B3 34:87:23 18:DE:D7 50:C7:BF 14:CC:20 5C:E9:31 AC:84:C6 30:B5:C2 54:C8:0F 64:09:80 64:64:4A 28:6C:07 0C:1D:AF 78:11:DC 3C:8C:98 D4:3A:E9"

#────────────────────────────── 网络探测设施(active-probe)──────────────────────────────
# 模块: 40-netlib.sh

HTTP_TOOL=""
http_detect() {
  have curl && { HTTP_TOOL="curl"; return 0; }
  have wget && { HTTP_TOOL="wget"; return 0; }
  HTTP_TOOL=""
}

http_get() { # $1=url
  case "$HTTP_TOOL" in
    curl) curl -s --max-time 8 "$1" 2>/dev/null ;;
    wget) wget -q -T 8 -O - "$1" 2>/dev/null ;;
  esac
}
http_get6() { # 强制 IPv6
  case "$HTTP_TOOL" in
    curl) curl -s -6 --max-time 8 "$1" 2>/dev/null ;;
    wget) wget -q -6 -T 8 -O - "$1" 2>/dev/null ;;
  esac
}
http_post() { # $1=url $2=JSON body
  case "$HTTP_TOOL" in
    curl) curl -s --max-time 10 -H 'Content-Type: application/json' -d "$2" "$1" 2>/dev/null ;;
    wget) wget -q -T 10 -O - --header='Content-Type: application/json' --post-data="$2" "$1" 2>/dev/null ;;
  esac
}

# 从单条 JSON 对象提取 "key":"value"(浅层,值中无嵌套转义)
jf() { # $1=key $2=json
  printf '%s' "$2" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

ip_is_private() {
  case "$1" in
    ::|::1|[fF][cCdD]*:*|[fF][eE][89aAbB]*:*|[fF][fF]*:*) return 0 ;;
    10.*|192.168.*|127.*|169.254.*|0.0.0.0|255.255.255.255|22[4-9].*|23[0-9].*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.7[0-9].*|100.8[0-9].*|100.9[0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    *) return 1 ;;
  esac
}

hex2ip() { # /proc/net/tcp 小端 hex(8 位)→ 点分十进制
  printf '%s' "$1" | awk 'function d(x){v=0;for(i=1;i<=length(x);i++){v=v*16+index("0123456789abcdef",tolower(substr(x,i,1)))-1}return v}{printf "%d.%d.%d.%d", d(substr($0,7,2)), d(substr($0,5,2)), d(substr($0,3,2)), d(substr($0,1,2))}'
}

# ip-api 单 IP 查询 → "CC|country|as|reverse"(失败输出 ERR)
geoip1() {
  # 主源 HTTPS(ipwho.is,支持 IPv4/IPv6,抗传输篡改);失败回退 ip-api(HTTP,仅 IPv4)
  _b=$(http_get "https://ipwho.is/$1")
  case "$(jf success "$_b")" in true|1)
    _asn=$(printf '%s' "$_b" | sed -n 's/.*"asn":[ ]*\([0-9][0-9]*\).*/AS\1/p' | head -n 1)
    printf '%s|%s|%s|' "$(jf country_code "$_b")" "$(jf country "$_b")" "${_asn:-}"
    return ;;
  esac
  _b=$(http_get "http://ip-api.com/json/$1?fields=status,countryCode,country,as,reverse")
  if [ "$(jf status "$_b")" != "success" ]; then printf 'ERR'; return; fi
  printf '%s|%s|%s|%s' "$(jf countryCode "$_b")" "$(jf country "$_b")" "$(jf as "$_b")" "$(jf reverse "$_b")"
}

# 域名解析(经系统解析路径,取首个 A 记录)
dns_lookup() {
  if have dig; then dig +short +time=3 +tries=1 A "$1" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+' | head -n 1; return; fi
  if have getent; then
    _a=$(getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1{print $1}')
    if [ -n "$_a" ]; then printf '%s' "$_a"; return; fi
  fi
  if have nslookup; then
    nslookup "$1" 2>/dev/null | awk '/^Address/ && $2 !~ /#/{print $2}' | tail -n 1
  fi
}

#────────────────────────────── 平台与采集者上下文 ──────────────────────────────
# 模块: 41-context.sh

PLATFORM=""; PLATFORM_NOTE=""
IN_SSH_CHAIN=0; IN_MUX=0; PARENT_CHAIN=""; MY_PIDS=" "
CUR_USER=""; CUR_UID=""
ROUTE_IFACE=""; ROUTE_SRC=""; ROUTE_GW=""; NET_ANNOT=""
EGRESS_CC=""; EGRESS_TZ=""; EGRESS_CC6=""
# ── 结构化证据注册表(供 C20 usegeo 消费;各 check 写入) ──
TZ_NAME=""; TZ_CLASS=""; LOCALE_ZH=0            # C8
SESS_N=0; SESS_LOCAL_N=0; SESS_REMOTES=""       # C18
SESS_ENTRIES=""; SELF_PEER=""; SELF_PEER_CC=""  # C18
DG_IPCC=""                                      # C3 deep-geo(ip=CC 注册表)
NETNS_ISOLATED=0                                # C17
OVERLAY_BREAKS=""                               # C5(链路断点)
TZ_INFER_OFF=""; TZ_INFER_CONF=""; TZ_INFER_N=0; TZ_INFER_E8=no  # C11
RD_CONNECTED=""                                 # C19(远控活动会话)
RADIO_ACCESS=""; RADIO_ACCESS_CC=""             # C13 --radio
USEGEO_VIEW=""                                  # C20(汇总区视图)
PS_SNAP=""                                      # 进程快照(ps_filtered 数据源)

detect_platform() {
  PLATFORM="linux"; PLATFORM_NOTE=""
  case "$(uname -s)" in
    Darwin) PLATFORM="macos"; PLATFORM_NOTE="macOS(原生只读采集;不适用项显式跳过)" ;;
    MINGW*|MSYS*) PLATFORM="msys"; PLATFORM_NOTE="MSYS/Git Bash(/proc 不全,尽力降级)" ;;
    Linux)
      if grep -qi microsoft /proc/version 2>/dev/null; then
        PLATFORM="wsl"; PLATFORM_NOTE="WSL(Windows interop 检测 v0.3)"
      elif [ -f /.dockerenv ]; then
        PLATFORM="container-docker"; PLATFORM_NOTE="Docker 容器(wtmp/DMI/lspci 等项将 SKIP)"
      elif [ -f /run/.containerenv ]; then
        PLATFORM="container-podman"; PLATFORM_NOTE="Podman 容器"
      elif grep -q kubepods /proc/1/cgroup 2>/dev/null; then
        PLATFORM="container-k8s"; PLATFORM_NOTE="K8s pod(cluster DNS/SA 见 services 类)"
      elif cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -q '^container=lxc'; then
        PLATFORM="container-lxc"; PLATFORM_NOTE="LXC(近 VM 处理)"
      else
        _v=""
        if have systemd-detect-virt; then
          _v=$(systemd-detect-virt --vm 2>/dev/null)
        fi
        case "$_v" in ""|none)
          if have dmesg && dmesg 2>/dev/null | head -n 200 | grep -qiE 'hypervisor|kvm|vmware|xen|virtual box|virtualbox'; then
            _v="dmesg-hint"
          elif [ -r /sys/class/dmi/id/sys_vendor ]; then
            case "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)" in
              QEMU*|VMware*|Xen*|Microsoft\ Corporation|Amazon*|OpenStack*|innotek*) _v="dmi-hint" ;;
            esac
          fi ;;
        esac
        case "$_v" in
          ""|none) PLATFORM_NOTE="物理机/未识别虚拟化" ;;
          *)       PLATFORM_NOTE="虚拟机($_v)" ;;
        esac
      fi ;;
    *) PLATFORM_NOTE="未知内核 $(uname -s),尽力降级" ;;
  esac
}

# u0:采集者边界 —— 脚本自身的运行上下文(所有结果继承此 scope)
collector_context() {
  CUR_USER=$(id -un 2>/dev/null || printf '?')
  CUR_UID=$(id -u 2>/dev/null || printf '?')
  _p=$$; _i=0; MY_PIDS=" $$ "
  while [ "$_i" -lt 6 ]; do
    _pp=$(ps -o ppid= -p "$_p" 2>/dev/null | tr -d ' ')
    if [ -z "$_pp" ] || [ "$_pp" = "0" ] || [ "$_pp" = "1" ]; then break; fi
    MY_PIDS="$MY_PIDS $_pp "
    _pn=$(ps -o comm= -p "$_pp" 2>/dev/null | awk 'NR==1{print $1}' 2>/dev/null)
    [ -z "$_pn" ] && break
    PARENT_CHAIN="${PARENT_CHAIN:+$PARENT_CHAIN → }$_pn"
    case "${_pn##*/}" in
      sshd|sshd-session) IN_SSH_CHAIN=1 ;;
      tmux*|screen*) IN_MUX=1 ;;
    esac
    _p=$_pp; _i=$((_i+1))
  done
  # 进程快照(排除自身进程树;供 ps_filtered 使用,防管道子进程自匹配)
  PS_SNAP=$({ ps aux 2>/dev/null || ps -ef 2>/dev/null; } | awk -v pids="$MY_PIDS" 'index(pids, " " $2 " ") == 0')
}

# 网络上下文(出口注记用;本地操作,不外联)
net_context() {
  if [ "$PLATFORM" = macos ] && have route; then
    _rt=$(route -n get 1.1.1.1 2>/dev/null)
    ROUTE_IFACE=$(printf '%s' "$_rt" | awk '$1=="interface:" {print $2}')
    ROUTE_GW=$(printf '%s' "$_rt" | awk '$1=="gateway:" {print $2}')
    if [ -n "$ROUTE_IFACE" ] && have ifconfig; then
      ROUTE_SRC=$(ifconfig "$ROUTE_IFACE" 2>/dev/null | awk '$1=="inet" {print $2; exit}')
    fi
  elif have ip; then
    _rt=$(ip route get 1.1.1.1 2>/dev/null | head -n 1)
    ROUTE_IFACE=$(printf '%s' "$_rt" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
    ROUTE_SRC=$(printf '%s' "$_rt" | sed -n 's/.* src \([0-9a-fA-F.:]*\).*/\1/p')
    ROUTE_GW=$(printf '%s' "$_rt" | sed -n 's/.* via \([0-9a-fA-F.:]*\).*/\1/p')
  elif [ -r /proc/net/route ]; then
    # 回退:默认路由(Destination=00000000)的网关小端 hex + 接口名
    _line=$(awk '$2=="00000000"{print $1, $3; exit}' /proc/net/route 2>/dev/null)
    if [ -n "$_line" ]; then
      ROUTE_IFACE=$(printf '%s' "$_line" | awk '{print $1}')
      ROUTE_GW=$(hex2ip "$(printf '%s' "$_line" | awk '{print $2}')")
    fi
    have hostname && ROUTE_SRC=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  case "$ROUTE_IFACE" in
    tun*|utun*|tap*|wg*|ppp*|tailscale*) NET_ANNOT="经隧道接口 $ROUTE_IFACE" ;;
  esac
  if [ -n "${http_proxy:-}${https_proxy:-}${HTTP_PROXY:-}${HTTPS_PROXY:-}${all_proxy:-}" ]; then
    NET_ANNOT="${NET_ANNOT:+$NET_ANNOT;}经环境代理"
  fi
  case "$PLATFORM" in
    container-*) NET_ANNOT="${NET_ANNOT:+$NET_ANNOT;}容器内观测(NAT 后出口)" ;;
  esac
}

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

#────────────────────────────── C1 sysinfo ──────────────────────────────
# 模块: 50-c1-sysinfo.sh

check_c1() {
  hdr "C1 sysinfo · 系统与平台"

  # 发行版与内核
  _pretty="unknown"
  [ -r /etc/os-release ] && _pretty=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"' | head -n 1)
  if [ "$PLATFORM" = macos ]; then
    _pretty="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
  fi
  report INFO sysinfo/os "$_pretty · $(uname -sr) · $(uname -m)"

  # 平台判定
  report INFO sysinfo/platform "平台: $PLATFORM${PLATFORM_NOTE:+ · $PLATFORM_NOTE}"

  # 采集者边界(u0)
  _tty=$(tty 2>/dev/null) || _tty=""
  case "$_tty" in ""|*"not a tty"*) _tty="无tty" ;; *) _tty="${_tty#/dev/}" ;; esac
  _chain_flags=""
  [ "$IN_SSH_CHAIN" = 1 ] && _chain_flags="$_chain_flags [sshd]"
  [ "$IN_MUX" = 1 ] && _chain_flags="$_chain_flags [mux]"
  report INFO sysinfo/collector "采集者: uid=$CUR_UID($CUR_USER) · tty=$_tty · 父链: ${PARENT_CHAIN:-?}$_chain_flags"

  # uptime
  if [ "$PLATFORM" = macos ]; then
    _bt=$(mac_boot_epoch)
    case "$_bt" in
      ''|*[!0-9]*) report SKIP sysinfo/uptime "(kern.boottime 不可读)" ;;
      *) _up=$(($(date +%s) - _bt))
         report INFO sysinfo/uptime "运行时长: $((_up/86400)) 天 $(((_up%86400)/3600)) 小时(kern.boottime)" ;;
    esac
  elif [ -r /proc/uptime ]; then
    _up=$(cut -d. -f1 /proc/uptime)
    report INFO sysinfo/uptime "运行时长: $((_up/86400)) 天 $(((_up%86400)/3600)) 小时"
  else
    report SKIP sysinfo/uptime "(/proc/uptime 不可读)"
  fi

  # 系统安装时间(machine-id 时间估算,与 C12 新装判定共用)
  if [ "$PLATFORM" = macos ]; then
    _setup=$(fs_btime /var/db/.AppleSetupDone)
    if [ -n "$_setup" ]; then
      _setup_days=$((($(date +%s) - _setup) / 86400))
      report INFO sysinfo/setup-age "设置助手完成标记约 $_setup_days 天前(.AppleSetupDone 创建/修改时间;迁移或重置会改变,不等于初次安装日期)"
    else
      report SKIP sysinfo/install-age "(.AppleSetupDone 元数据不可读;不猜测安装日期)"
    fi
  else
    _it=$(fs_btime /etc/machine-id)
    [ -z "$_it" ] && _it=$(fs_btime /lost+found 2>/dev/null)
    if [ -n "$_it" ] && [ "$_it" != 0 ]; then
      _now=$(date +%s)
      INSTALL_AGE_DAYS=$(( (_now - _it) / 86400 ))
      [ "$INSTALL_AGE_DAYS" -lt 0 ] && INSTALL_AGE_DAYS=0
      report INFO sysinfo/install-age "系统约安装于 $INSTALL_AGE_DAYS 天前(machine-id 时间估算)"
    else
      report SKIP sysinfo/install-age "(无法取 machine-id/lost+found 时间)"
    fi

  fi

  # 连接方式
  if [ -n "$SSH_CONNECTION" ] || [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
    _src=$(printf '%s' "${SSH_CONNECTION:-$SSH_CLIENT}" | awk '{print $1}')
    report INFO sysinfo/session "连接方式: SSH(来源 $(mask_ip "${_src:-?}"), pts=${SSH_TTY#*/dev/})"
  elif [ "$IN_SSH_CHAIN" = 1 ]; then
    report INFO sysinfo/session "连接方式: SSH(父链含 sshd,但 env 无 SSH_* 变量 —— 见 anti 类)"
  elif have who; then
    _wai=$(who am i 2>/dev/null | awk '{print $NF}')
    case "$_wai" in
      "("*")") report INFO sysinfo/session "连接方式: 远程会话(who: $(mask_ip "$(printf '%s' "$_wai" | tr -d '()')"),来源工具未知)" ;;
      *) report INFO sysinfo/session "连接方式: 本机/非交互($([ "$IN_MUX" = 1 ] && printf '经 tmux/screen;')无 SSH 环境)" ;;
    esac
  else
    report INFO sysinfo/session "连接方式: 本机/非交互(who 不可用)"
  fi

  # TCP 拥塞控制
  if [ "$PLATFORM" = macos ]; then
    _nr=$(sysctl -n net.inet.tcp.use_newreno 2>/dev/null)
    case "$_nr" in
      0|1) report INFO sysinfo/tcp-cc "Darwin TCP use_newreno=$_nr(内核配置;不等于逐连接实际算法)" ;;
      *) report SKIP sysinfo/tcp-cc "(Darwin TCP 拥塞控制 sysctl 不可读/版本不支持)" ;;
    esac
  elif [ -r /proc/sys/net/ipv4/tcp_congestion_control ]; then
    _cc=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null)
    case "$_cc" in
      bbr) report INFO sysinfo/tcp-cc "拥塞控制 bbr(国内用户常用配置,海外亦常见,仅作提示)" ;;
      *)   report INFO sysinfo/tcp-cc "拥塞控制 ${_cc:-default}" ;;
    esac
  else
    report SKIP sysinfo/tcp-cc "(Linux /proc/sys 检测不适用或不可读)"
  fi

  # 登录用户列表
  if have who && who 2>/dev/null | grep -q .; then
    _n=$(who 2>/dev/null | grep -c . )
    _rem=$(who 2>/dev/null | grep -cE '\([0-9a-fA-F.:]+\)')
    report INFO sysinfo/logins "在线会话 $_n 个(其中远程来源 $_rem 个,值已脱敏)"
  else
    report SKIP sysinfo/logins "(who 不可用/无会话记录)"
  fi
}

#────────────────────────────── C2 cloud ──────────────────────────────
# 模块: 51-c2-cloud.sh

check_c2() {
  hdr "C2 cloud · 中资云与定制系统(信息级)"

  _hits=""
  _vendor=""; _product=""

  # DMI/SMBIOS
  if [ -r /sys/class/dmi/id/sys_vendor ]; then
    _vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
    _product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    if printf '%s' "$_vendor $_product" | grep -qE "$CN_CLOUD_DMI_RE"; then
      _hits="DMI[$_vendor/$_product]"
    elif printf '%s' "$_vendor" | grep -qiE '^HUAWEI$'; then
      _hits="DMI[$_vendor](华为硬件或华为云,需 product 区分)"
    fi
    [ -n "$_vendor" ] && report INFO cloud/dmi "DMI: $_vendor / ${_product:-?}"
  else
    report SKIP cloud/dmi "(Linux DMI 接口不适用或不可读;macOS 硬件见 hw 类)"
  fi

  # 云 agent 进程
  _ps=$(ps_filtered)
  if [ -n "$_ps" ]; then
    _ag=$(printf '%s' "$_ps" | grep -vE 'grep|region-trace' | grep -icE "$CLOUD_AGENT_PROC_RE" || true)
    if [ "${_ag:-0}" -gt 0 ]; then
      _hits="${_hits:+$_hits; }云agent进程 x$_ag(运行中)"
    fi
  else
    report SKIP cloud/agent-proc "(ps 不可用)"
  fi

  # 云 agent 目录
  for _d in $CLOUD_AGENT_DIRS; do
    [ -d "$_d" ] && _hits="${_hits:+$_hits; }目录 $_d"
  done

  # 云内网镜像源(C9 深查,此处判定归属)
  for _f in /etc/apt/sources.list /etc/yum.repos.d /etc/dnf/dnf.conf /etc/pacman.d/mirrorlist /etc/apk/repositories; do
    if [ -e "$_f" ]; then
      if grep -rE "$CLOUD_INT_MIRROR_RE" "$_f" >/dev/null 2>&1; then
        _hits="${_hits:+$_hits; }内网镜像源($_f)"
        break
      fi
    fi
  done

  # 定制痕迹
  for _f in /etc/motd /etc/issue; do
    if [ -r "$_f" ] && grep -qiE 'alibaba|tencent|huawei|volcano|aliyun' "$_f" 2>/dev/null; then
      _hits="${_hits:+$_hits; }$_f 含厂商定制字样"
    fi
  done

  # 预装包
  _pkgs=""
  if have rpm; then _pkgs=$(rpm -qa 2>/dev/null | grep -iE '^(aliyun|tencent|qcloud|huawei|volcano)' | head -n 8)
  elif have dpkg; then _pkgs=$(dpkg -l 2>/dev/null | awk '{print $2}' | grep -iE '^(aliyun|tencent|qcloud|huawei|volcano)' | head -n 8)
  fi
  [ -n "$_pkgs" ] && _hits="${_hits:+$_hits; }预装包: $(printf '%s' "$_pkgs" | tr '\n' ' ' | cut -c1-120)"

  if [ -n "$_hits" ]; then
    report INFO cloud/summary "检出中资云特征: $_hits(节点国内/海外待 egress 类判定;监控 agent 意味着数据回传中资厂商)"
  else
    report CLEAN cloud/summary "未检出中资云/定制系统特征(普通 IDC 不作检测点)"
  fi
}

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

#────────────────────────────── C4 path ──────────────────────────────
# 模块: 53-c4-path.sh

check_c4() {
  hdr "C4 path · 链路、路由与本地网络"

  # ── 网关 MAC OUI(启发式,弱证据;VPS 虚拟网关自然不命中) ──
  _mac=""; _arp_available=0
  if [ "$PLATFORM" = macos ] && [ -n "$ROUTE_GW" ]; then
    if _arp=$(arp -n "$ROUTE_GW" 2>/dev/null); then
      _arp_available=1
      _mac=$(printf '%s\n' "$_arp" | awk '{for(i=1;i<NF;i++) if($i=="at" && $(i+1) ~ /^[0-9a-fA-F:]+$/) print $(i+1)}' |
        awk -F: 'NF==6 {for(i=1;i<=6;i++){if(length($i)==1)$i="0"$i}; print toupper($1":"$2":"$3":"$4":"$5":"$6)}')
    fi
  elif [ -n "$ROUTE_GW" ] && [ -r /proc/net/arp ]; then
    _arp_available=1
    _mac=$(awk -v g="$ROUTE_GW" '$1==g{print toupper($4); exit}' /proc/net/arp 2>/dev/null)
  fi
  if [ "$_arp_available" = 1 ]; then
    if [ -n "$_mac" ]; then
      _oui=$(printf '%s' "$_mac" | cut -d: -f1-3)
      case " $GW_OUI_CN_LIST " in
        *" $_oui "*)
          report SUSPICIOUS path/gw-oui "默认网关 MAC OUI=$_oui 命中国内网络设备厂商表(启发式,弱证据)" ;;
        *)
          report INFO path/gw-oui "网关 $(mask_ip "$ROUTE_GW") 的 ARP 项 OUI=$_oui(未命中国内设备表)" ;;
      esac
    else
      report SKIP path/gw-oui "(ARP 表无网关条目)"
    fi
  else
    report SKIP path/gw-oui "(无默认网关/ARP 缓存不可读;macOS 使用 arp -n,隧道接口可能无 ARP)"
  fi

  # ── MTU ──
  _mtu=""
  if [ "$PLATFORM" = macos ] && [ -n "$ROUTE_IFACE" ]; then
    _mtu=$(ifconfig "$ROUTE_IFACE" 2>/dev/null | awk 'NR==1{for(i=1;i<NF;i++)if($i=="mtu")print $(i+1)}')
  elif [ -n "$ROUTE_IFACE" ] && [ -r "/sys/class/net/$ROUTE_IFACE/mtu" ]; then
    _mtu=$(cat "/sys/class/net/$ROUTE_IFACE/mtu" 2>/dev/null)
  fi
  if [ -n "$_mtu" ]; then
    case "$_mtu" in
      1492|1488|1480) report SUSPICIOUS path/mtu "出口接口 $ROUTE_IFACE MTU=$_mtu(PPPoE 线路特征)" ;;
      *) report INFO path/mtu "出口接口 $ROUTE_IFACE MTU=$_mtu" ;;
    esac
  fi

  # ── CGNAT ──
  case "$ROUTE_SRC" in
    100.6[4-9].*|100.7[0-9].*|100.8[0-9].*|100.9[0-9].*|100.1[01][0-9].*|100.12[0-7].*)
      report SUSPICIOUS path/cgnat "本机源地址 $ROUTE_SRC 位于 CGNAT 段 100.64.0.0/10(运营商级 NAT,国内移动网络常见)" ;;
  esac

  # ── traceroute CN 骨干检测(active-probe) ──
  if [ "$OFFLINE" = 1 ]; then
    report SKIP path/trace "(--offline:跳过外联探测)"
    return
  fi
  # stdbuf -oL:强制行缓冲 —— tracepath 管道下为块缓冲,被看门狗强杀会丢失已输出内容
  _pre=""
  have stdbuf && _pre="stdbuf -oL"
  _tr=""
  if have traceroute; then _tr="traceroute -n -q 1 -w 1 -m 18"
  elif have tracepath; then _tr="tracepath -n -m 15"
  elif have busybox && busybox traceroute 2>&1 | head -n 1 | grep -qi usage; then _tr="busybox traceroute -n -q 1 -w 1 -m 18"
  fi
  if [ -z "$_tr" ]; then
    report SKIP path/trace "(缺 traceroute/tracepath)"
    return
  fi
  # 注:GNU timeout 与 tracepath 信号处理不兼容(实测空输出),
  # 改用「后台运行 + 看门狗强杀」限时;CN 骨干通常出现在近端 hop,部分结果即可判定
  _run_bounded() { # $1=限时秒 其余=命令
    _secs=$1; shift
    "$@" 2>/dev/null &
    _tp=$!
    ( sleep "$_secs" && kill -9 "$_tp" 2>/dev/null ) &
    _wd=$!
    wait "$_tp" 2>/dev/null
    kill -9 "$_wd" 2>/dev/null
    wait "$_wd" 2>/dev/null
  }
  _hops=""
  for _a in 1.1.1.1 8.8.8.8; do
    _hops="$_hops $(_run_bounded 12 $_pre $_tr "$_a" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v "^$_a$")"
  done
  _pub=""; _seen=""
  for _h in $_hops; do
    case " $_seen " in *" $_h "*) continue ;; esac
    _seen="$_seen $_h"
    ip_is_private "$_h" && continue
    _pub="$_pub $_h"
  done
  _npub=$(printf '%s' "$_pub" | wc -w | tr -d ' ')
  if [ "${_npub:-0}" -lt 2 ]; then
    report SKIP path/trace "(沿途公网 hop 不足($_npub 个),无法判定)"
    return
  fi
  _body="["; _f1=1
  for _i in $_pub; do [ "$_f1" = 1 ] && _f1=0 || _body="$_body,"; _body="$_body\"$_i\""; done
  _body="$_body]"
  _r=$(http_post "http://ip-api.com/batch?fields=status,query,countryCode,as" "$_body")
  if [ -z "$_r" ]; then
    report SKIP path/trace "(批量 GeoIP 查询失败)"
    return
  fi
  _sum=$(printf '%s' "$_r" | awk '{
    gsub(/\},[ ]*\{/, "\n"); n=split($0, recs, /\n/)
    cn=0; cnips=""; hk=0; other=0
    for(i=1;i<=n;i++){
      r=recs[i]
      if (r !~ /"status":"success"/) continue
      cc=""; if (match(r, /"countryCode":"[A-Z][A-Z]"/)) cc=substr(r, RSTART+16, 2)
      as=""; if (match(r, /"as":"[^"]*"/)) as=substr(r, RSTART+6, RLENGTH-7)
      ip=""; if (match(r, /"query":"[^"]*"/)) ip=substr(r, RSTART+9, RLENGTH-10)
      if (cc=="CN" || as ~ /^AS(4134|4808|4837|9808|9929|58453|23724|4538)([^0-9]|$)/ || ip ~ /^202\.97\./ || ip ~ /^219\.158\./) {
        cn++
        if (cn<=3) cnips=cnips" "ip
      } else if (cc=="HK" || cc=="MO") hk++
      else other++
    }
    printf "%d %d %d %s\n", cn, hk, other, cnips
  }')
  set -- $_sum
  _cn=$1; _hk=$2; _oth=$3; _cni=$(shift 3; printf '%s' "$*" | sed 's/^ //')
  case "$_cn" in ''|*[!0-9]*) _cn=0 ;; esac
  if [ "$_cn" -gt 0 ]; then
    report EXPOSED path/trace-cn "路由经过中国骨干网:$(printf '%s' "$_cni" | tr ' ' ',') 等 $_cn 个 hop(AS4134 电信/4808·4837 联通/9808 移动/CMI/CERNET/202.97·219.158 段)—— 物理链路经过中国大陆"
  else
    report CLEAN path/trace-cn "沿途 $_oth 个公网 hop,无 CN 骨干网痕迹"
  fi
  _hk_n=0
  case "${_hk:-0}" in ''|*[!0-9]*) ;; *) _hk_n=$_hk ;; esac
  [ "$_hk_n" -gt 0 ] && report INFO path/trace-hk "路径经香港中转($_hk_n 个 hop,亚太路由常见)"
}

#────────────────────────────── C5 proxy ──────────────────────────────
# 模块: 54-c5-proxy.sh

check_c5() {
  hdr "C5 proxy · 代理、隧道、分流与覆盖网络"

  _ps=$(ps_filtered)

  # ── env 代理变量(掩码凭据) ──
  _pe=0
  for _v in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
    eval "_val=\${$_v:-}"
    if [ -n "$_val" ]; then
      report INFO proxy/env "$_v=$(printf '%s' "$_val" | sed 's|\(//[^@/]*\)@|//<凭据已掩码>@|')"
      _pe=1
    fi
  done
  [ "$_pe" = 0 ] && report CLEAN proxy/env "无代理环境变量"

  # ── 接口分类 ──
  _vpn=""; _cni=""
  if [ "$PLATFORM" = macos ]; then _ifnames=$(ifconfig -l 2>/dev/null)
  else _ifnames=$(ls /sys/class/net 2>/dev/null); fi
  for _i in $_ifnames; do
    case "$_i" in
      lo|eth*|ens*|enp*|eno*|enx*|wlan*|wlp*|wwan*|wwp*|bond*|br0|usb*) : ;;
      utun*|tun*|tap*|wg*|tailscale*|zt*|nordlynx*|ppp*|CloudflareWARP*|warp*) _vpn="$_vpn $_i" ;;
      docker*|veth*|br-*|cni*|cali*|flannel*|weave*|kube*|virbr*|dummy*|podman*) _cni="$_cni $_i" ;;
    esac
  done
  [ -n "$_vpn" ] && report INFO proxy/vpn-iface "VPN/隧道接口:$_vpn"
  [ -n "$_cni" ] && report INFO proxy/cni-iface "容器/桥接接口:$_cni"
  for _i in $_vpn; do
    case "$_i" in ppp*) report SUSPICIOUS proxy/pppoe "PPPoE 会话接口 $_i(拨号线路特征)" ;; esac
  done
  case "$ROUTE_IFACE" in
    utun*|tun*|tap*|wg*|ppp*|tailscale*)
      report INFO proxy/default-route "默认路由经隧道接口 $ROUTE_IFACE(出口探测经此接口)" ;;
    *) report INFO proxy/default-route "默认路由接口: ${ROUTE_IFACE:-未知}" ;;
  esac

  # ── 代理栈进程 ──
  _pproc=$(printf '%s' "$_ps" | grep -oE "$PROXY_PROC_RE" | sort -u | tr '\n' ' ')
  [ -n "$_pproc" ] && report INFO proxy/stack-proc "代理栈进程(active): $_pproc"

  # ── clash/mihomo 订阅节点命名 ──
  for _d in "$HOME/.config/clash" "$HOME/.config/mihomo" "$HOME/.config/clash-verge" /etc/clash /etc/mihomo; do
    [ -d "$_d" ] || continue
    _n=$(grep -rhoE '沪|京|深|穗|蓉|港|IPLC|IEPL|家宽|专线|回国' "$_d" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${_n:-0}" -gt 0 ]; then
      report SUSPICIOUS proxy/clash-nodes "$_d 配置含国内订阅节点命名特征 x$_n(沪/港/IPLC/家宽等)"
    fi
  done

  # ── 透明代理/分流规则(需 root;无权限时跳过) ──
  if [ "$PLATFORM" = macos ]; then
    mac_check_firewall
  elif have iptables && iptables -t nat -L -n >/dev/null 2>&1; then
    if iptables -t nat -L -n 2>/dev/null | grep -qE 'REDIRECT|TPROXY'; then
      report SUSPICIOUS proxy/transparent "iptables NAT 表含 REDIRECT/TPROXY(透明代理/分流)"
    fi
    if iptables -L -n 2>/dev/null | grep -qiE 'chnroute|china'; then
      report SUSPICIOUS proxy/chnroute "iptables 含 CN 直连分流规则集(chnroute)"
    fi
  else
    report SKIP proxy/iptables "(缺权限或未安装 iptables,透明代理规则无法核查)"
  fi
  if have nft && nft list ruleset >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -qE 'redirect|tproxy'; then
      report SUSPICIOUS proxy/transparent "nftables 含 redirect/tproxy(透明代理/分流)"
    fi
  fi

  # ── DNS 分流配置 ──
  for _f in /etc/dnsmasq.conf /etc/dnsmasq.d /etc/smartdns/smartdns.conf; do
    [ -e "$_f" ] || continue
    if grep -rqE '114\.114\.114\.114|223\.5\.5\.5|119\.29\.29\.29' "$_f" 2>/dev/null; then
      report SUSPICIOUS proxy/dns-split "$_f 国内域名指向国内公共 DNS(分流配置)"
    fi
  done

  # ── Tailscale(local-daemon 只读) ──
  if ls /sys/class/net 2>/dev/null | grep -qx 'tailscale0' || printf '%s' "$_ps" | grep -q 'tailscaled'; then
    report INFO proxy/tailscale "Tailscale 运行中(Mesh 内虚拟地址不做地理归属)"
    OVERLAY_BREAKS="$OVERLAY_BREAKS Tailscale-mesh"
    case "$ROUTE_IFACE" in tailscale*) report INFO proxy/tailscale "默认路由经 tailscale0 —— 正在使用 exit node" ;; esac
    if have tailscale; then
      _tsst=$(tailscale status 2>/dev/null)
      if printf '%s' "$_tsst" | grep -q 'exit node'; then
        report INFO proxy/tailscale "status 含 exit node 条目(提供或使用 exit node)"
      fi
      _tpn=$(printf '%s' "$_tsst" | grep -cE '^[a-z0-9_.-]+@[a-z0-9_.-]+:' || true)
      if [ "${_tpn:-0}" -gt 0 ]; then
        _tdir=$(printf '%s' "$_tsst" | grep -c 'direct' || true)
        report INFO proxy/tailscale "mesh peers $_tpn 个(其中 direct 连接 ${_tdir:-0} 个,余经 DERP 中继;地址不输出)—— 中继后对端位置不可直接观察"
      fi
    fi
  fi

  # ── cloudflared / WARP ──
  if printf '%s' "$_ps" | grep -q 'cloudflared'; then
    _n=0
    for _f in /etc/cloudflared/config.yml "$HOME/.cloudflared/config.yml"; do
      if [ -r "$_f" ]; then _x=$(grep -c 'hostname:' "$_f" 2>/dev/null) || true; _x=${_x:-0}; _n=$((_n+_x)); fi
    done
    report INFO proxy/cloudflared "cloudflared 出站 Tunnel 运行中(ingress $_n 条;凭据不读取;不改变默认出口,不作 VPN 证据)"
    OVERLAY_BREAKS="$OVERLAY_BREAKS Cloudflare-Tunnel(入站)"
  fi
  if printf '%s' "$_ps" | grep -q 'warp-svc' || [ -d /var/lib/CloudflareWARP ]; then
    case "$ROUTE_IFACE" in
      CloudflareWARP*|warp*) report INFO proxy/warp "Cloudflare WARP 运行中,默认路由经 WARP 接口(出口探测实际走 WARP)" ;;
      *) report INFO proxy/warp "Cloudflare WARP 客户端存在(默认路由未经过 WARP;可能仅 DNS 接管/备用;enrollment 数据不读取)" ;;
    esac
  fi

  # ── 通用 mesh / 反向隧道 / proxychains ──
  _mesh=$(printf '%s' "$_ps" | grep -oE 'zerotier-one|nebula|netbird|strongswan|openvpn' | sort -u | tr '\n' ' ')
  [ -n "$_mesh" ] && report INFO proxy/mesh "mesh/VPN daemon(active): $_mesh"
  _rt=$(printf '%s' "$_ps" | grep -oE 'autossh|frpc|frps|ngrok' | sort -u | tr '\n' ' ')
  [ -n "$_rt" ] && report INFO proxy/reverse-tunnel "反向隧道进程(active): $_rt(入站来源被隧道遮蔽,操作者链路不可直接观察)"
  for _f in /etc/proxychains.conf "$HOME/.proxychains/proxychains.conf"; do
    [ -r "$_f" ] && report INFO proxy/proxychains "proxychains 配置存在($_f)"
  done
}

#────────────────────────────── C6 dns ──────────────────────────────
# 模块: 55-c6-dns.sh

check_c6() {
  hdr "C6 dns · DNS 卫生"

  # ── 生效解析器 ──
  _res=$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')
  _stub=1
  for _r in $_res; do case "$_r" in 127.0.0.53|127.0.0.54|127.0.0.55) ;; *) _stub=0 ;; esac; done
  _resrc="resolv.conf"
  if [ "$_stub" = 1 ] && [ -r /run/systemd/resolve/resolv.conf ]; then
    _res=$(awk '/^nameserver/{print $2}' /run/systemd/resolve/resolv.conf 2>/dev/null | tr '\n' ' ')
    _resrc="systemd-resolved 上游"
  elif [ "$_stub" = 1 ] && have resolvectl; then
    _res=$(resolvectl status 2>/dev/null | grep -oE 'Current DNS Server: [0-9a-fA-F.:]+' | awk '{print $4}' | tr '\n' ' ')
    _resrc="systemd-resolved(resolvectl)"
  fi
  if [ "$PLATFORM" = macos ]; then
    _res=$(mac_dns_servers | tr '\n' ' ')
    _resrc="scutil --dns;含 scoped/supplemental 解析器,实际选择取决于域名/接口"
  fi
  if ! has_text "$_res"; then
    report SKIP dns/resolvers "(无法确定生效解析器)"
  else
    _masked=""; _lb=0; _nr=0
    for _r in $_res; do
      _masked="$_masked $(mask_ip "$_r")"; _nr=$((_nr+1))
      case "$_r" in 127.*) _lb=$((_lb+1)) ;; esac
    done
    _extra=""
    if [ "$_lb" -gt 0 ] && [ "$_lb" -eq "$_nr" ]; then
      _extra=" —— 本地回环转发器(上游不可见)"
      if grep -qi 'generated by cloudflare-warp' /etc/resolv.conf 2>/dev/null; then
        _extra=" —— 本地回环转发器;resolv.conf 由 cloudflare-warp 生成(WARP DNS 接管)"
      fi
    fi
    [ -n "$KUBERNETES_SERVICE_HOST" ] && case "$_res" in *10.*|*169.254.*) _extra=" —— K8s cluster DNS(平台注记)";; esac
    report INFO dns/resolvers "生效解析器($_resrc):${_masked}${_extra}"
    _hit=""
    for _r in $_res; do case "$CN_PUBLIC_DNS" in *" $_r "*) _hit="$_hit $_r";; esac; done
    if [ -n "$_hit" ]; then
      report SUSPICIOUS dns/cn-public "解析器命中国内公共 DNS:${_hit}(使用习惯)"
    fi
    # 解析器 GeoIP(外联最小集;回环转发器无上游可查)
    _pubres=""
    for _r in $_res; do ip_is_private "$_r" || _pubres="$_pubres $_r"; done
    if ! has_text "$_pubres"; then
      report INFO dns/resolver-geo "解析器为私网/回环/链路本地地址,上游归属不可见(转发器行为见 proxy 类)"
    elif [ "$OFFLINE" != 1 ] && [ -n "$HTTP_TOOL" ]; then
      _cnr=""
      for _r in $_pubres; do
        _gr=$(geoip1 "$_r")
        case "${_gr%%|*}" in CN|HK|MO) _cnr="$_cnr $_r" ;; esac
      done
      if [ -n "$_cnr" ]; then
        report SUSPICIOUS dns/resolver-geo "解析器 GeoIP 位于陆港澳:${_cnr}"
      else
        report CLEAN dns/resolver-geo "解析器 GeoIP 无陆港澳归属"
      fi
    else
      report SKIP dns/resolver-geo "(--offline 或缺 HTTP 工具)"
    fi
  fi

  # ── DNS 污染探测(≥2 域名命中已知假 IP 才判阳性) ──
  if [ "$OFFLINE" = 1 ]; then
    report SKIP dns/pollution "(--offline:跳过外联 DNS 查询)"
  elif have dig || have getent || have nslookup; then
    [ "$PLATFORM" = macos ] && report INFO dns/probe-scope "dig/nslookup 探测不覆盖 macOS 按域名/接口选择的全部解析路径;不等同于所有应用的 DNS 行为"
    _fake=0; _nx=0; _ips=""
    for _d in facebook.com twitter.com x.com youtube.com; do
      _ip=$(dns_lookup "$_d")
      if [ -z "$_ip" ]; then _nx=$((_nx+1)); continue; fi
      case "$FAKE_IPS" in *" $_ip "*) _fake=$((_fake+1)) ;; esac
      _ips="$_ips $_ip"
    done
    _dup=$(printf '%s' "$_ips" | tr ' ' '\n' | grep -v '^$' | sort | uniq -d | head -n 1)
    if [ "$_fake" -ge 2 ]; then
      report EXPOSED dns/pollution "已知污染域名解析返回已知假 IP(x$_fake)—— 解析链路经过注入路径"
    elif [ -n "$_dup" ]; then
      # 同 IP 启发式:先排除已知过滤/拦截 IP(黑洞地址、Cloudflare Gateway、Umbrella 等)
      case "$_dup" in
        0.0.0.0|127.*|::1)
          report INFO dns/pollution "被测域名解析到统一拦截 IP($_dup,广告过滤/本地阻断风格),非注入" ;;
        146.112.*)
          report INFO dns/pollution "被测域名解析到统一过滤 IP($(mask_ip "$_dup"),Cisco Umbrella 拦截页),非注入" ;;
        *)
          _dupcls="EXPOSED"; _dupnote="注入特征"
          if [ "$OFFLINE" != 1 ] && [ -n "$HTTP_TOOL" ]; then
            _gd=$(geoip1 "$_dup")
            case "$_gd" in *AS13335*|*LOUDFLARE*)
              _dupcls="INFO"; _dupnote="统一过滤 IP(Cloudflare Gateway/Zero Trust 拦截),非注入" ;;
            esac
          fi
          if [ "$_dupcls" = "EXPOSED" ]; then
            report EXPOSED dns/pollution "多个被污染域名解析到同一 IP($(mask_ip "$_dup"))—— $_dupnote"
          else
            report INFO dns/pollution "被测域名解析到 $(mask_ip "$_dup") —— $_dupnote"
          fi ;;
      esac
    elif [ "$_fake" = 1 ]; then
      report SUSPICIOUS dns/pollution "单一假 IP 命中(待复核,可能为误报)"
    elif [ "$_nx" -ge 3 ]; then
      report INFO dns/pollution "被测域名均无法解析($_nx/4)—— 更可能是阻断或过滤,而非注入"
    else
      report CLEAN dns/pollution "4 个已知污染域名解析无注入特征"
    fi
  else
    report SKIP dns/pollution "(缺 dig/getent/nslookup)"
  fi

  # ── /etc/hosts 硬解析 ──
  if [ -r /etc/hosts ]; then
    _n=$(grep -vE '^\s*#|localhost|ip6-' /etc/hosts 2>/dev/null | grep -cE "$CN_DOMAIN_RE" || true)
    _n=${_n:-0}
    if [ "$_n" -gt 0 ]; then
      report SUSPICIOUS dns/hosts "/etc/hosts 含 $_n 条国内域名硬解析"
    else
      report CLEAN dns/hosts "/etc/hosts 无国内域名硬解析"
    fi
  fi

  # ── 加密 DNS 与 FallbackDNS ──
  if [ -r /etc/systemd/resolved.conf ]; then
    grep -qE '^\s*DNSOverTLS=yes' /etc/systemd/resolved.conf 2>/dev/null && \
      report INFO dns/dot "systemd-resolved DNSOverTLS 已启用"
    _fb=$(sed -n 's/^FallbackDNS=//p' /etc/systemd/resolved.conf 2>/dev/null | head -n 1)
    case "$_fb" in
      *114.114.114.114*|*223.5.5.5*|*119.29.29.29*) report SUSPICIOUS dns/fallback "resolved FallbackDNS 含国内 DNS" ;;
    esac
  fi
  for _f in /etc/stubby/stubby.conf /etc/dnscrypt-proxy/dnscrypt-proxy.toml; do
    [ -e "$_f" ] && report INFO dns/encrypted "加密 DNS 配置存在($_f)"
  done
}

#────────────────────────────── C8 locale ──────────────────────────────
# 模块: 56-c8-locale.sh

check_c8() {
  hdr "C8 locale · 地域配置(系统层)"

  # ── locale ──
  _loc="${LC_ALL:-${LANG:-}}"
  [ -z "$_loc" ] && [ -r /etc/locale.conf ] && _loc=$(sed -n 's/^LANG=//p' /etc/locale.conf | head -n 1 | tr -d '"')
  _sysloc=""
  [ -r /etc/locale.conf ] && _sysloc=$(sed -n 's/^LANG=//p' /etc/locale.conf | head -n 1 | tr -d '"')
  case "${_loc:-unknown}" in
    zh_CN*|zh_HK*|zh_MO*) LOCALE_ZH=1
 report SUSPICIOUS locale/lang "locale=$_loc(zh_CN/HK/MO,文化习惯类信号)" ;;
    zh_TW*|zh_SG*)        report INFO locale/lang "locale=$_loc(TW/SG,不属陆港澳三地)" ;;
    *)                    report CLEAN locale/lang "locale=${_loc:-未设置}" ;;
  esac
  case "${_sysloc:-}" in
    zh_CN*|zh_HK*|zh_MO*) report SUSPICIOUS locale/sys-lang "/etc/locale.conf=$_sysloc(系统级,部署者痕迹)" ;;
  esac

  # ── 时区(三源) ──
  _tz=""
  if [ -L /etc/localtime ] || [ -e /etc/localtime ]; then
    _link=$(readlink /etc/localtime 2>/dev/null)
    if [ -n "$_link" ]; then
      _tz=$(printf '%s' "$_link" | sed 's|.*zoneinfo/||')
    fi
  fi
  [ -z "$_tz" ] && [ -r /etc/timezone ] && _tz=$(head -n 1 /etc/timezone)
  if [ -z "$_tz" ] && have timedatectl; then
    _tz=$(timedatectl show -p Timezone --value 2>/dev/null) || _tz=""
    [ -z "$_tz" ] && _tz=$(timedatectl 2>/dev/null | sed -n 's/.*Time zone: \([A-Za-z/_]*\).*/\1/p' | head -n 1)
  fi
  if [ -z "$_tz" ]; then
    _zz=$(date +%Z 2>/dev/null)
    case "$_zz" in
      CST) report INFO locale/tz "date +%Z=CST(歧义:中国标准时间/美国中部,无法定论)" ;;
      *)   report SKIP locale/tz "(时区不可探测)" ;;
    esac
  fi
  if [ -n "$_tz" ]; then
    TZ_MAIN=$_tz; TZ_NAME=$_tz
    _cls=$(tz_class "$_tz"); TZ_CLASS=$_cls
    case "$_cls" in
      CN)   report EXPOSED locale/tz "系统时区 $_tz(陆港澳确定时区,长期在其他时区的用户不会保留)" ;;
      HKMO) report EXPOSED locale/tz "系统时区 $_tz(港澳确定时区)" ;;
      E8)
        if [ -n "$EGRESS_TZ" ] && [ "$(tz_offset "$EGRESS_TZ")" = "+0800" ]; then
          report CLEAN locale/tz "系统时区 $_tz 与出口时区($EGRESS_TZ)同属东八,自洽"
        elif [ -n "$EGRESS_CC" ]; then
          report EXPOSED locale/tz "系统时区 $_tz(东八)与出口地区 $(cnname "$EGRESS_CC")(${EGRESS_TZ:-未知时区})不匹配 —— 时区与地区矛盾(东八区特判)"
        else
          report INFO locale/tz "系统时区 $_tz(东八、非陆港澳;出口数据缺失,无法比对)"
        fi ;;
      *)
        if [ -n "$EGRESS_TZ" ] && [ "$(tz_offset "$EGRESS_TZ")" != "$(tz_offset "$_tz")" ]; then
          report SUSPICIOUS locale/tz "系统时区 $_tz(UTC$(tz_offset "$_tz"))与出口地理时区 $EGRESS_TZ(UTC$(tz_offset "$EGRESS_TZ"))不一致(中转节点常见,仅作参考)"
        elif [ -n "$EGRESS_TZ" ]; then
          report CLEAN locale/tz "系统时区 $_tz 与出口时区 $EGRESS_TZ 一致"
        else
          report INFO locale/tz "系统时区 $_tz(出口数据缺失,无法比对)"
        fi ;;
    esac
    # TZ env:值本身命中陆港澳 → 暴露;与系统不一致 → 可疑
    if [ -n "$TZ" ]; then
      _tzc=$(tz_class "$TZ")
      case "$_tzc" in
        CN)   report EXPOSED locale/tz-env "TZ=$TZ(陆港澳确定时区)" ;;
        HKMO) report EXPOSED locale/tz-env "TZ=$TZ(港澳确定时区)" ;;
      esac
      if [ "$TZ" != "$_tz" ]; then
        report SUSPICIOUS locale/tz-env "TZ=$TZ 与系统时区 $_tz 不一致(伪造/混乱痕迹)"
      fi
    fi
  fi

  # ── localedef / man / 键盘 / hostname / RTC ──
  if have locale; then
    _lc=$(locale -a 2>/dev/null | grep -iE '^zh_(CN|HK|MO)' | head -n 4 | tr '\n' ' ')
    if has_text "$_lc"; then
      if [ "$PLATFORM" = macos ]; then
        report INFO locale/localedef "系统提供中文 locale: $_lc(macOS 内置可用列表,不代表用户启用;偏好见 macos 类)"
      else
        report SUSPICIOUS locale/localedef "已生成中文 locale: $_lc(文化习惯类信号)"
      fi
    else
      report CLEAN locale/localedef "未生成 zh_CN/HK/MO locale"
    fi
  else
    report SKIP locale/localedef "(locale 命令不可用)"
  fi

  if [ -d /usr/share/man/zh ] || ls -d /usr/share/man/zh* >/dev/null 2>&1; then
    report SUSPICIOUS locale/man-zh "存在中文 man 手册页(文化习惯类信号)"
  fi

  if [ -r /etc/default/keyboard ]; then
    _kb=$(sed -n 's/^XKBLAYOUT=//p' /etc/default/keyboard | tr -d '"')
    case "$_kb" in *cn*) report SUSPICIOUS locale/keyboard "XKB 键盘布局含 cn($_kb)" ;;
                     *) report INFO locale/keyboard "XKB 布局: ${_kb:-default}" ;;
    esac
  fi

  _hn=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || printf '?')
  case "$_hn" in
    *.cn|*.com.cn) report SUSPICIOUS locale/hostname "hostname=$_hn(.cn 后缀)" ;;
    *) case "$_hn" in
         *[Cc]hina*|*-cn-*|cn-*|*-cn) report SUSPICIOUS locale/hostname "hostname=$_hn(含 CN 字样)" ;;
         *) if is_pinyin_name "$_hn"; then
              report SUSPICIOUS locale/hostname "hostname=$_hn(疑似拼音姓名,启发式)"
            else
              report CLEAN locale/hostname "hostname=$_hn"
            fi ;;
       esac ;;
  esac

  if have timedatectl; then
    if timedatectl 2>/dev/null | grep -q 'RTC in local TZ: yes'; then
      report INFO locale/rtc "RTC 使用本地时间(常见于双系统安装)"
    fi
  fi
}

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

#────────────────────────────── C12 anti ──────────────────────────────
# 模块: 59-c12-anti.sh

check_c12() {
  hdr "C12 anti · 隐藏与伪造痕迹(带上下文修正)"

  # ── 登录日志权限矩阵 ──
  if [ "$PLATFORM" = macos ]; then
    report SKIP anti/linux-logs "(macOS 不使用此 Linux wtmp/btmp/lastlog/utmp 权限基线;登录记录见 session 类)"
  else
    for _f in /var/log/wtmp /var/log/btmp /var/log/lastlog /run/utmp; do
      if [ ! -e "$_f" ]; then
        report SKIP anti/"$(printf '%s' "$_f" | tr / _ | tr -d '.')" "(不存在:容器/最小系统常见)"
        continue
      fi
      case "$_f" in
        /var/log/btmp)
          # btmp 各发行版默认即不可读(RHEL 600 / Debian 660 root:utmp)
          [ -r "$_f" ] && report INFO anti/btmp "btmp 可读(少数发行版默认)" \
                         || report INFO anti/btmp "btmp 不可读(RHEL/Debian 系默认,正常)"
          continue ;;
      esac
      if [ -r "$_f" ]; then
        report INFO anti/"$(printf '%s' "$_f" | tr / _ | tr -d '.')" "$_f 当前用户可读(默认权限)"
      else
        # 上下文修正:容器 SKIP;新装 INFO;正常老化系统不可读 = 刻意 → 可疑
        case "$PLATFORM" in
          container-*) report SKIP anti/"$(printf '%s' "$_f" | tr / _ | tr -d '.')" "$_f 不可读(容器环境)" ;;
          *)
            if [ "${INSTALL_AGE_DAYS:-0}" -gt 0 ] && [ "$INSTALL_AGE_DAYS" -lt 30 ]; then
              report INFO anti/"$(printf '%s' "$_f" | tr / _ | tr -d '.')" "$_f 不可读(系统安装 $INSTALL_AGE_DAYS 天,新装可能为部署基线)"
            else
              report SUSPICIOUS anti/"$(printf '%s' "$_f" | tr / _ | tr -d '.')" "$_f 对当前用户不可读(正常系统应为可读 —— 疑似刻意隐藏)"
            fi ;;
        esac
      fi
    done

  fi

  # wtmp 空但 uptime 长
  if [ -r /var/log/wtmp ] && [ ! -s /var/log/wtmp ]; then
    _up=$(cut -d. -f1 /proc/uptime 2>/dev/null || printf 0)
    if [ "${_up:-0}" -gt 2592000 ]; then
      report SUSPICIOUS anti/wtmp-empty "wtmp 为空但系统运行 $((_up/86400)) 天(日志被清)"
    fi
  fi

  # SSH_* 剥离判定(需 sshd 上下文;tmux/su/service 上下文为正常差异)
  if [ "$IN_SSH_CHAIN" = 1 ] && [ -z "$SSH_CONNECTION" ] && [ -z "$SSH_CLIENT" ] && [ -z "$SSH_TTY" ]; then
    report SUSPICIOUS anti/ssh-env-stripped "shell 由 sshd 派生但 env 无 SSH_* 变量(疑似 env 剥离)"
  elif [ "$IN_MUX" = 1 ] && [ -z "$SSH_CONNECTION" ] && [ -z "$SSH_CLIENT" ]; then
    report INFO anti/ssh-env "tmux/screen 环境下无 SSH_* 变量(正常差异:server 继承环境)"
  elif [ "$IN_SSH_CHAIN" = 0 ] && [ -z "$SSH_CONNECTION" ]; then
    report INFO anti/ssh-env "本地/service 上下文,无 SSH_* 属正常"
  fi

  # rc 文件 SSH_* 赋值 / 伪造函数
  _rc_any=0; _rc_hit=0
  for _r in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
    [ -r "$_r" ] || continue
    _rc_any=1
    if grep -qE '(^|[;}&])[[:space:]]*(export[[:space:]]+)?SSH_(CLIENT|CONNECTION)=' "$_r" 2>/dev/null; then
      report SUSPICIOUS anti/rc-ssh-fake "$(_r_basename "$_r") 含 SSH_CLIENT/SSH_CONNECTION 赋值(伪造痕迹)"; _rc_hit=1
    fi
    if grep -qE 'env[[:space:]]+-u[[:space:]]+.*SSH' "$_r" 2>/dev/null; then
      report SUSPICIOUS anti/rc-env-u "$(_r_basename "$_r") 含 env -u SSH_* 别名/函数(剥离痕迹)"
    fi
  done
  [ "${_rc_any:-0}" = 0 ] && report SKIP anti/rc-ssh-fake "(无 rc 文件)"
  [ "${_rc_any:-0}" = 1 ] && [ "${_rc_hit:-0}" = 0 ] && report CLEAN anti/rc-ssh-fake "rc 文件无 SSH_* 赋值/伪造/env -u 痕迹"

  # systemd unit InaccessiblePaths(用户级与系统级可读部分)
  _ia=""
  for _d in "$HOME/.config/systemd/user" /etc/systemd/system; do
    [ -d "$_d" ] && [ -r "$_d" ] || continue
    if grep -rl 'InaccessiblePaths' "$_d" 2>/dev/null | grep -qE '.' &&
       grep -rh 'InaccessiblePaths' "$_d" 2>/dev/null | grep -qE 'wtmp|utmp|lastlog|/proc/net'; then
      _ia="${_ia:+$_ia; }$_d"
    fi
  done
  if [ "$PLATFORM" = macos ]; then
    report SKIP anti/unit-inaccessible "(macOS 不使用 systemd InaccessiblePaths)"
  elif [ -n "$_ia" ]; then
    report SUSPICIOUS anti/unit-inaccessible "systemd unit 含 InaccessiblePaths(wtmp/utmp/proc-net):$_ia"
  else
    report CLEAN anti/unit-inaccessible "可读范围内无 InaccessiblePaths(wtmp/utmp/proc-net)命中"
  fi

  # 沙箱 wrapper(~/.local/bin 文本脚本含 landlock/bwrap 关键词)
  if [ -d "$HOME/.local/bin" ]; then
    _w=$(grep -rl -iE 'landlock|LANDLOCK|bwrap' "$HOME/.local/bin" 2>/dev/null | head -n 3 | tr '\n' ' ')
    if has_text "$_w"; then
      report SUSPICIOUS anti/sandbox-wrapper "~/.local/bin 存在沙箱 wrapper: $_w(Landlock/bwrap)"
    fi
  fi

  # history 截断痕迹
  if [ -f "$HOME/.bash_history" ] && [ ! -s "$HOME/.bash_history" ]; then
    report SUSPICIOUS anti/history-truncated ".bash_history 存在但为 0 字节(清空痕迹;HISTSIZE=${HISTSIZE:-未设})"
  fi

  # claude shell-snapshot 中 SSH_CLIENT 与当前 env 不一致
  _snap_dir="$HOME/.claude/shell-snapshots"
  if [ -d "$_snap_dir" ]; then
    _cur=$(printf '%s' "${SSH_CONNECTION:-$SSH_CLIENT}" | awk '{print $1}')
    _snapval=$(grep -rhoE 'SSH_CLIENT="[^"]*"' "$_snap_dir" 2>/dev/null | head -n 1 | sed 's/.*="//;s/ .*//')
    if [ -n "$_snapval" ] && [ -n "$_cur" ] && [ "$_snapval" != "$_cur" ]; then
      report SUSPICIOUS anti/snapshot-mismatch "shell 快照记录 SSH 来源 $(mask_ip "$_snapval") 与当前 $(mask_ip "$_cur") 不一致(与当前值矛盾,或为历史残留)"
    elif [ -n "$_snapval" ] && [ -z "$_cur" ]; then
      report INFO anti/snapshot-mismatch "shell 快照记录 SSH 来源 $(mask_ip "$_snapval")(当前会话无 SSH_*,仅记录)"
    fi
  else
    report SKIP anti/snapshot "(无 ~/.claude/shell-snapshots)"
  fi

  # NTP 指向国内
  _ntp_hit=""; _ntp_any=0
  for _f in /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony/sources /etc/ntp.conf /etc/systemd/timesyncd.conf; do
    [ -r "$_f" ] || continue
    _ntp_any=1
    grep -qiE "(server|pool)[[:space:]].*$CN_NTP_RE" "$_f" 2>/dev/null && _ntp_hit="$_f"
  done
  if [ -n "$_ntp_hit" ]; then
    report SUSPICIOUS anti/ntp-cn "NTP 配置指向国内服务器($_ntp_hit,使用习惯)"
  elif [ "$_ntp_any" = 1 ]; then
    report CLEAN anti/ntp-cn "NTP 配置未命中国内服务器"
  else
    report SKIP anti/ntp-cn "(无可读 NTP 配置)"
  fi

  # 运行中进程 TZ/LANG 与系统不一致(抽查;命中陆港澳值则可疑,否则 INFO 注记)
  _ptz=""
  if [ -d /proc ] && [ -n "$CUR_UID" ] && [ "$CUR_UID" != "?" ]; then
    for _pid in $(ps -o pid= -u "$CUR_UID" 2>/dev/null | head -n 60); do
      [ -d "/proc/$_pid" ] || continue
      _tzv=$(cat "/proc/$_pid/environ" 2>/dev/null | tr '\0' '\n' | sed -n 's/^TZ=//p' | head -n 1)
      [ -z "$_tzv" ] && continue
      if [ -n "${TZ_MAIN:-}" ] && [ "$_tzv" != "$TZ_MAIN" ]; then
        _ptz="$_pid:$_tzv"; break
      fi
    done
  fi
  if [ "$PLATFORM" = macos ]; then
    report SKIP anti/proc-tz "(macOS 无 /proc/PID/environ;不读取完整进程环境以避免凭据采集)"
  elif [ -n "$_ptz" ]; then
    _ptzval=${_ptz#*:}
    _pc=$(tz_class "$_ptzval")
    case "$_pc" in
      CN|HKMO) report SUSPICIOUS anti/proc-tz "进程 TZ=$_ptzval 与系统 ${TZ_MAIN:-?} 不一致且为陆港澳时区" ;;
      *) report INFO anti/proc-tz "进程 TZ=$_ptzval 与系统 ${TZ_MAIN:-?} 不一致(service manager 注入差异常见)" ;;
    esac
  else
    report CLEAN anti/proc-tz "抽查自有进程 TZ,与系统一致或未设置"
  fi

  # ANTHROPIC_BASE_URL 非官方
  for _src in "env:$(printf '%s' "${ANTHROPIC_BASE_URL:-}")" "settings:$HOME/.claude/settings.json"; do
    _v=${_src#*:}; _w=${_src%%:*}
    [ -z "$_v" ] && continue
    case "$_w" in
      env) case "$_v" in
             api.anthropic.com|"") : ;;
             *) if printf '%s' "$_v" | grep -qE "$CN_DOMAIN_RE"; then
                  report SUSPICIOUS anti/anthropic-baseurl "ANTHROPIC_BASE_URL=$(_m_url "$_v")(国内中转特征)"
                else
                  report INFO anti/anthropic-baseurl "ANTHROPIC_BASE_URL 非官方域 $(_m_url "$_v")"
                fi ;;
           esac ;;
      settings) if grep -q 'ANTHROPIC_BASE_URL' "$_v" 2>/dev/null; then
                  _sv=$(sed -n 's/.*ANTHROPIC_BASE_URL[^"]*"[^"]*"\([^"]*\)".*/\1/p' "$_v" 2>/dev/null | head -n 1)
                  case "$_sv" in
                    api.anthropic.com|"") : ;;
                    *) report INFO anti/anthropic-baseurl "settings.json ANTHROPIC_BASE_URL=$(_m_url "${_sv:-?}")(非官方;注意 2.1.91+ 该场景触发时区上报)" ;;
                  esac
                fi ;;
    esac
  done

  # 采集完整性旁证
  if have mount; then
    if mount 2>/dev/null | grep ' /proc ' | grep -q hidepid; then
      report INFO anti/hidepid "/proc 以 hidepid 挂载(其他用户进程不可见 —— 观察范围受限,非隐藏痕迹)"
    fi
  fi
  if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "1" ]; then
    report INFO anti/selinux "SELinux enforcing(部分路径不可读属策略,非隐藏痕迹)"
  fi
}

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

#────────────────────────────── C16 boot ──────────────────────────────
# 模块: 61-c16-boot.sh
# 定位:上下文层 —— 引导与初始化来源,为其他类别的命中提供「谁设置的」归因

check_c16() {
  hdr "C16 boot · 引导、初始化与持久化来源"

  if [ "$PLATFORM" = macos ]; then
    _pid1=$(ps -p 1 -o comm= 2>/dev/null)
    if [ -n "$_pid1" ]; then
      report INFO boot/pid1 "PID 1 = ${_pid1##*/}(macOS 服务管理器)"
    else
      report SKIP boot/pid1 "(PID 1 信息不可读)"
    fi
    report SKIP boot/linux-init "(macOS 不适用 Linux cmdline/cloud-init/systemd/initramfs 检测;launchd 见 macos 类)"
    return
  fi

  case "$PLATFORM" in
    container-*)
      report SKIP boot/all "(容器环境,引导链与固件不可见)"
      return ;;
  esac

  # ── 引导模式 ──
  if [ -d /sys/firmware/efi ]; then
    report INFO boot/mode "UEFI 引导"
  elif [ -d /sys/firmware ]; then
    report INFO boot/mode "BIOS/Legacy 引导"
  else
    report SKIP boot/mode "(/sys/firmware 不可见 —— WSL/受限环境常见)"
  fi

  # ── PID 1 ──
  _pid1=$(cat /proc/1/comm 2>/dev/null | tr -d '[:space:]')
  if [ "$_pid1" = "systemd" ]; then
    report INFO boot/pid1 "PID 1 = systemd"
  else
    report INFO boot/pid1 "PID 1 = ${_pid1:-未知}(非 systemd —— 部分服务类检测将 SKIP)"
  fi

  # ── kernel cmdline:注入检测(只提取 TZ/LANG/ip= 类参数) ──
  _cm=$(cat /proc/cmdline 2>/dev/null)
  if [ -n "$_cm" ]; then
    _tzinj=$(printf '%s' "$_cm" | sed -n 's/.*systemd\.setenv=TZ=\([^ ]*\).*/\1/p' | head -n 1)
    if [ -n "$_tzinj" ]; then
      case "$(tz_class "$_tzinj")" in
        CN|HKMO) report EXPOSED boot/cmdline-tz "cmdline 注入 TZ=$_tzinj(陆港澳确定时区)" ;;
        E8)      report INFO boot/cmdline-tz "cmdline 注入 TZ=$_tzinj(东八非陆港澳;与出口比对见 locale 类)" ;;
        *)       report INFO boot/cmdline-tz "cmdline 注入 TZ=$_tzinj" ;;
      esac
    fi
    _langinj=$(printf '%s' "$_cm" | sed -n 's/.*systemd\.setenv=LANG=\([^ ]*\).*/\1/p' | head -n 1)
    case "${_langinj:-}" in
      zh_CN*|zh_HK*|zh_MO*) report SUSPICIOUS boot/cmdline-lang "cmdline 注入 LANG=$_langinj(文化习惯类信号)" ;;
    esac
    case "$_cm" in
      *" ip="*|*ip=dhcp*|*ip=dhcp6*) report INFO boot/cmdline-net "cmdline 含 ip= 网络参数(网络启动/PXE/云镜像)" ;;
    esac
    report INFO boot/cmdline "cmdline $(printf '%s' "$_cm" | wc -w | tr -d ' ') 个参数(已做分类提取,不记录完整内容)"
  else
    report SKIP boot/cmdline "(不可读)"
  fi

  # ── default target / 显示管理器 ──
  if have systemctl && systemctl get-default >/dev/null 2>&1; then
    report INFO boot/target "默认 target: $(systemctl get-default 2>/dev/null)"
  else
    report SKIP boot/target "(systemd 不可用)"
  fi
  if [ -L /etc/systemd/system/display-manager.service ]; then
    report INFO boot/dm "显示管理器: $(readlink /etc/systemd/system/display-manager.service 2>/dev/null | sed 's|.*/||')"
  else
    report INFO boot/dm "无显示管理器(headless)"
  fi

  # ── 初始化来源归因(cloud-init / Ignition) ──
  _ci=""
  [ -d /etc/cloud ] && _ci="/etc/cloud"
  [ -d /var/lib/cloud ] && _ci="${_ci:+$_ci }/var/lib/cloud"
  if [ -n "$_ci" ]; then
    report INFO boot/cloud-init "cloud-init 存在(配置可能来自镜像/云元数据,origin=cloud-init)"
    for _f in /etc/cloud/cloud.cfg /var/lib/cloud/instance/cloud-config.txt; do
      [ -r "$_f" ] || continue
      _cctz=$(sed -n 's/^[[:space:]]*timezone:[[:space:]]*//p' "$_f" 2>/dev/null | head -n 1)
      [ -n "$_cctz" ] && report INFO boot/cloud-init-tz "cloud-init 注入 timezone=$_cctz(origin=cloud-init;当前生效值判定见 locale 类)"
      _cclc=$(sed -n 's/^[[:space:]]*locale:[[:space:]]*//p' "$_f" 2>/dev/null | head -n 1)
      [ -n "$_cclc" ] && report INFO boot/cloud-init-locale "cloud-init 注入 locale=$_cclc(origin=cloud-init)"
    done
  fi
  if [ -d /var/lib/ignition ] || [ -d /usr/lib/ignition ]; then
    report INFO boot/ignition "Ignition 配置存在(不可变系统/容器节点,origin=image)"
  fi

  # ── rc.local(legacy 启动脚本) ──
  if [ -r /etc/rc.local ]; then
    if grep -qE 'SSH_CLIENT|SSH_CONNECTION' /etc/rc.local 2>/dev/null; then
      report SUSPICIOUS boot/rc-local "rc.local 含 SSH_* 引用(伪造/剥离痕迹)"
    else
      report INFO boot/rc-local "rc.local 存在($(wc -l </etc/rc.local 2>/dev/null | tr -d ' ') 行)"
    fi
  fi

  # ── 持久化启动面概览 ──
  if have systemctl && systemctl list-unit-files >/dev/null 2>&1; then
    _en=$(systemctl list-unit-files --type=service 2>/dev/null | awk '$2=="enabled"{n++} END{print n+0}')
    _tm=$(systemctl list-unit-files --type=timer 2>/dev/null | awk '$2=="enabled"{n++} END{print n+0}')
    report INFO boot/enabled "enabled 服务 $_en 个 / timer $_tm 个(服务级地域命中见 services 类)"
  fi
  if [ -d "$HOME/.config/autostart" ]; then
    _au=$(ls "$HOME/.config/autostart" 2>/dev/null | head -n 6 | tr '\n' ' ')
    has_text "$_au" && report INFO boot/autostart "XDG autostart: $_au(用户级持久化)"
  fi

  # ── initramfs ──
  if ls /boot/init* >/dev/null 2>&1; then
    report INFO boot/initramfs "initramfs 存在($(ls /boot/init* 2>/dev/null | wc -l | tr -d ' ') 个;内容参数不解析)"
  else
    report SKIP boot/initramfs "(/boot 不可读或无 initramfs)"
  fi
}

#────────────────────────────── C17 kernelnet ──────────────────────────────
# 模块: 62-c17-kernelnet.sh
# 定位:上下文层 —— 内核、命名空间与网络数据面;解释 C3/C4/C5 的观测范围

check_c17() {
  hdr "C17 kernelnet · 内核、命名空间与网络数据面"

  if [ "$PLATFORM" = macos ]; then
    report INFO kernel/scope "macOS 当前主机网络视图;Linux netns/cgroup/LSM/seccomp 不适用,不据此推断未受沙箱限制"
    _ifs=$(ifconfig -l 2>/dev/null)
    if [ -n "$_ifs" ]; then
      report INFO kernel/ifaces "可见网络接口: $_ifs(utun 为隧道,不单凭接口名推断物理位置)"
    else
      report SKIP kernel/ifaces "(ifconfig 不可用/无权限)"
    fi
    if [ -n "$ROUTE_IFACE" ]; then
      report INFO kernel/routes "到探测目标的路由接口 $ROUTE_IFACE;网关 $(mask_ip "${ROUTE_GW:-未知}")"
    else
      report SKIP kernel/routes "(route 查询不可用/无路由)"
    fi
    _forward=$(sysctl -n net.inet.ip.forwarding 2>/dev/null)
    case "$_forward" in
      0|1) report INFO kernel/ip-forward "IPv4 转发=$_forward(仅拓扑角色)" ;;
      *) report SKIP kernel/ip-forward "(sysctl 不可读)" ;;
    esac
    report INFO kernel/firewall "PF 活动规则/应用防火墙/Network Extension 状态由 proxy 类采集(单项运行请用 --section proxy)"
    return
  fi

  # ── LSM ──
  _lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)
  if [ -n "$_lsm" ]; then
    report INFO kernel/lsm "LSM: $_lsm"
  elif [ -d /sys/fs/selinux ]; then
    report INFO kernel/lsm "SELinux(lsm 列表不可读,sysfs 已挂载)"
  elif [ -d /sys/kernel/security/apparmor ]; then
    report INFO kernel/lsm "AppArmor"
  else
    report SKIP kernel/lsm "(/sys/kernel/security 不可读)"
  fi

  # ── cgroup 版本 ──
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    report INFO kernel/cgroup "cgroup v2(controllers: $(head -c 100 /sys/fs/cgroup/cgroup.controllers 2>/dev/null)…)"
  elif [ -d /sys/fs/cgroup/systemd ] || [ -d /sys/fs/cgroup/blkio ]; then
    report INFO kernel/cgroup "cgroup v1"
  else
    report SKIP kernel/cgroup "(不可判定)"
  fi

  # ── seccomp(沙箱/容器旁证) ──
  _sc=$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status 2>/dev/null)
  case "${_sc:-}" in
    2) report INFO kernel/seccomp "Seccomp 过滤模式(容器/沙箱常见 —— 部分系统调用受限)" ;;
    *) report INFO kernel/seccomp "Seccomp=${_sc:-未知}(未过滤)" ;;
  esac

  # ── 网络命名空间对比(观测范围声明) ──
  _sns=$(ls -Li /proc/self/ns/net 2>/dev/null | awk '{print $1}')
  _p1ns=$(ls -Li /proc/1/ns/net 2>/dev/null | awk '{print $1}')
  if [ -n "$_sns" ] && [ -n "$_p1ns" ]; then
    if [ "$_sns" = "$_p1ns" ]; then
      report INFO kernel/netns "与 PID 1 同网络命名空间(本报告网络观测 = 宿主 netns)"
    else
      report INFO kernel/netns "与 PID 1 不同网络命名空间(隔离环境 —— 出口/路由/连接观测仅代表当前 netns)"
      NETNS_ISOLATED=1
    fi
  else
    report SKIP kernel/netns "(namespace 句柄不可读 —— /proc/1/ns 需 root,非特权运行常见)"
  fi

  # ── 接口物理性 ──
  _phys=""; _virt=""
  for _d in /sys/class/net/*; do
    [ -e "$_d" ] || continue
    _n=${_d##*/}
    [ "$_n" = "lo" ] && continue
    if [ -e "$_d/device" ]; then _phys="$_phys $_n"; else _virt="$_virt $_n"; fi
  done
  report INFO kernel/ifaces "接口分类:${_phys:+物理:$_phys}${_virt:+ 虚拟:$_virt}"

  # ── 路由全貌 ──
  if [ -r /proc/net/route ]; then
    _rl=$(wc -l < /proc/net/route | tr -d ' ')
    report INFO kernel/routes "main 表 $((_rl-1)) 条路由(多路由表/policy routing 需 iproute2)"
  fi
  if [ -r /proc/net/if_inet6 ]; then
    _r6=$(wc -l < /proc/net/if_inet6 | tr -d ' ')
    [ "$_r6" -gt 0 ] && report INFO kernel/route6 "IPv6 接口前缀 $_r6 条(if_inet6;完整 v6 路由/多表/VRF 归属需 iproute2+root)"
  fi
  # 数据面分层存在性声明(nftables/iptables;规则明细需 root,此处仅声明可见层)
  if [ -r /proc/net/ip_tables_names ] && [ -n "$(cat /proc/net/ip_tables_names 2>/dev/null)" ]; then
    report INFO kernel/iptables "iptables 表: $(cat /proc/net/ip_tables_names 2>/dev/null | tr '\n' ' ')(规则明细需 root)"
  fi
  if have nft && nft list tables >/dev/null 2>&1; then
    report INFO kernel/nftables "nftables 表 $(nft list tables 2>/dev/null | wc -l | tr -d ' ') 个(透明代理可在 nft 层;规则明细需 root)"
  fi
  if have ip; then
    _rules=$(ip rule list 2>/dev/null | grep -cvE '^(0|32766|32767):')
    if [ "${_rules:-0}" -gt 0 ]; then
      report INFO kernel/policy-routing "存在 $_rules 条非默认策略路由(代理栈/多 WAN/VRF 常见;数据面归属见 path/proxy 类)"
    fi
  fi

  # ── IP 转发(router/subnet-router 角色) ──
  if [ -r /proc/sys/net/ipv4/ip_forward ]; then
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
      report INFO kernel/ip-forward "IPv4 转发已启用(router/subnet-router/容器宿主角色;非地域信号)"
    fi
  fi
}

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

#────────────────────────────── WSL interop ──────────────────────────────
# 模块: 64-wsl-interop.sh
# 定位:仅 WSL 平台 —— 经 interop 只读查询 Windows 侧地域痕迹(区域/时区/代理/语言/hosts)

check_wsl() {
  hdr "WSL interop · Windows 侧地域痕迹"

  if [ "$PLATFORM" != "wsl" ]; then
    report SKIP wsl/all "(非 WSL 环境)"
    return
  fi

  # ── interop 可用性 + 区域/时区(单次 powershell 调用) ──
  _psout=""
  if have powershell.exe; then
    if have timeout; then
      _psout=$(timeout 12 powershell.exe -NoProfile -Command \
        "(Get-Culture).Name; ([System.TimeZoneInfo]::Local).Id; (Get-WinSystemLocale).Name" 2>/dev/null) || _psout=""
    else
      _psout=$(powershell.exe -NoProfile -Command \
        "(Get-Culture).Name; ([System.TimeZoneInfo]::Local).Id; (Get-WinSystemLocale).Name" 2>/dev/null) || _psout=""
    fi
  fi
  if [ -n "$_psout" ]; then
    _cul=$(printf '%s\n' "$_psout" | sed -n '1p' | tr -d '\r')
    _wtz=$(printf '%s\n' "$_psout" | sed -n '2p' | tr -d '\r')
    _sloc=$(printf '%s\n' "$_psout" | sed -n '3p' | tr -d '\r')
    case "${_cul}${_sloc}" in
      *zh-CN*|*zh-HK*|*zh-MO*) report SUSPICIOUS wsl/culture "Windows 区域 $_cul / 系统区域 $_sloc(简中/港澳,文化习惯类信号)" ;;
      *zh-TW*|*zh-SG*)        report INFO wsl/culture "Windows 区域 $_cul / 系统区域 $_sloc(TW/SG,不属陆港澳三地)" ;;
      *)                      report INFO wsl/culture "Windows 区域 $_cul / 系统区域 ${_sloc:-?}" ;;
    esac
    case "$(win_tz_class "$_wtz")" in
      CN) report EXPOSED wsl/tz "Windows 时区 $_wtz(陆港澳确定时区 —— 陆/港/澳共用该时区名)" ;;
      E8) report INFO wsl/tz "Windows 时区 $_wtz(东八非陆港澳;与出口比对见 locale 类)" ;;
      *)  report INFO wsl/tz "Windows 时区 $_wtz" ;;
    esac
  else
    report SKIP wsl/powershell "(interop 不可用或已禁用 —— Windows 侧无法核查)"
  fi

  # ── 注册表:系统代理与系统语言 ──
  _reg=""
  if have reg.exe; then
    if have timeout; then
      _reg=$(timeout 8 reg.exe query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 2>/dev/null) || _reg=""
    else
      _reg=$(reg.exe query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 2>/dev/null) || _reg=""
    fi
  fi
  if [ -n "$_reg" ]; then
    _pe=$(printf '%s' "$_reg" | sed -n 's/.*ProxyEnable.*REG_DWORD[[:space:]]*//p' | tr -d '\r ')
    _pv=$(printf '%s' "$_reg" | sed -n 's/.*ProxyServer.*REG_SZ[[:space:]]*//p' | tr -d '\r')
    if [ "${_pe:-0x0}" != "0x0" ] && [ -n "$_pv" ]; then
      case "$_pv" in
        127.0.0.1:*|localhost:*) report SUSPICIOUS wsl/win-proxy "Windows 系统代理已启用 → $_pv(本机代理端口,常见于国内代理客户端)" ;;
        *) report INFO wsl/win-proxy "Windows 系统代理已启用 → $(mask_ip "${_pv%%:*}"):${_pv#*:}" ;;
      esac
    else
      report CLEAN wsl/win-proxy "Windows 系统代理未启用"
    fi
  else
    report SKIP wsl/reg "(reg.exe interop 不可用)"
  fi
  _nls=""
  if have reg.exe; then
    if have timeout; then
      _nls=$(timeout 8 reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language' /v Default 2>/dev/null) || _nls=""
    else
      _nls=$(reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language' /v Default 2>/dev/null) || _nls=""
    fi
  fi
  if [ -n "$_nls" ]; then
    _lv=$(printf '%s' "$_nls" | sed -n 's/.*REG_SZ[[:space:]]*//p' | tr -d '\r ')
    case "${_lv:-}" in
      0804) report SUSPICIOUS wsl/win-lang "Windows 系统语言 = 0804(简体中文)" ;;
      0c04|0404) report INFO wsl/win-lang "Windows 系统语言 = $_lv(繁体中文,港台)" ;;
      *) report INFO wsl/win-lang "Windows 系统语言 = ${_lv:-未知}" ;;
    esac
  fi

  # ── Windows hosts 文件 ──
  _wh='/mnt/c/Windows/System32/drivers/etc/hosts'
  if [ -r "$_wh" ]; then
    _n=$(grep -vE '^\s*#|localhost' "$_wh" 2>/dev/null | grep -cE "$CN_DOMAIN_RE" || true)
    _n=${_n:-0}
    if [ "$_n" -gt 0 ]; then
      report SUSPICIOUS wsl/win-hosts "Windows hosts 含 $_n 条国内域名硬解析"
    else
      report CLEAN wsl/win-hosts "Windows hosts 无国内域名硬解析"
    fi
  else
    report SKIP wsl/win-hosts "(Windows hosts 不可读)"
  fi
}

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

#────────────────────────────── C15 browser ──────────────────────────────
# 模块: 66-c15-browser.sh
# 定位:浏览器痕迹 —— 已装浏览器/profile、默认搜索引擎、界面语言、历史国内域名计数
# 红线:只计数,不读取/不输出 URL 明文、查询词、书签标题、扩展内容、凭据

check_c15() {
  hdr "C15 browser · 浏览器痕迹(仅计数)"

  # ── 已装浏览器与 profile(目录存在即可判定) ──
  _nfound=0
  _br_check() { # $1=名称 $2=profile 目录 $3=附加二进制
    _p=""
    [ -d "$2" ] && _p="$2"
    [ -z "$_p" ] && [ -n "$3" ] && have "$3" && _p="bin-only"
    if [ -n "$_p" ]; then
      _nfound=$((_nfound+1))
      if [ "$_p" = "bin-only" ]; then
        report INFO "browser/$1" "已安装($3;无用户 profile —— 未使用或他人环境)"
      else
        _profile=0
        for _candidate in "$2"/Default "$2"/Profile* "$2"/profiles.ini; do
          [ -e "$_candidate" ] && _profile=1
        done
        if [ "$_profile" = 1 ]; then
          report INFO "browser/$1" "存在用户 profile($2)"
        else
          report INFO "browser/$1" "目录存在但未发现可见 profile($2;可能为空或权限受限)"
        fi
      fi
    fi
  }
  if [ "$PLATFORM" = macos ]; then
    # macOS 路径(应用二进制在 /Applications,profile 在 ~/Library)
    _br_check firefox "$HOME/Library/Application Support/Firefox" firefox
    _br_check chrome "$HOME/Library/Application Support/Google/Chrome" "Google Chrome"
    _br_check chromium "$HOME/Library/Application Support/Chromium" chromium
    _br_check brave "$HOME/Library/Application Support/BraveSoftware/Brave-Browser" "Brave Browser"
    _br_check edge "$HOME/Library/Application Support/Microsoft Edge" "Microsoft Edge"
    _br_check vivaldi "$HOME/Library/Application Support/Vivaldi" vivaldi
  else
    _br_check firefox "$HOME/.mozilla/firefox" firefox
    _br_check chrome "$HOME/.config/google-chrome" google-chrome
    _br_check chromium "$HOME/.config/chromium" chromium
    _br_check brave "$HOME/.config/BraveSoftware/Brave-Browser" brave-browser
    _br_check edge "$HOME/.config/microsoft-edge" microsoft-edge
    _br_check vivaldi "$HOME/.config/vivaldi" vivaldi
    _br_check opera "$HOME/.config/opera" opera
  fi

  if [ "$_nfound" -eq 0 ]; then
    report SKIP browser/all "(无浏览器及 profile —— 服务器/无桌面场景常见)"
    return
  fi

  # 运行中状态
  if ps_filtered | grep -qE '(firefox|chrome|chromium|brave|msedge|vivaldi|opera)( |$)'; then
    report INFO browser/running "浏览器进程运行中(历史文件可能被锁,只读不受影响)"
  fi

  # ── Firefox:prefs.js(文本,逐 profile) ──
  _ffdir="$HOME/.mozilla/firefox"
  [ -d "$HOME/Library/Application Support/Firefox" ] && _ffdir="$HOME/Library/Application Support/Firefox"
  if [ -d "$_ffdir" ] && [ -r "$_ffdir/profiles.ini" ]; then
    _nprof=0; _zh=0; _cneng=0
    _prof_list=$(sed -n 's/^Path=//p' "$_ffdir/profiles.ini" 2>/dev/null)
    while IFS= read -r _pr; do
      [ -z "${_pr:-}" ] && continue
      case "$_pr" in \~/*) continue ;; esac
      case "$_pr" in /*) _pf=$_pr ;; *) _pf="$_ffdir/$_pr" ;; esac
      [ -d "$_pf" ] || continue
      _nprof=$((_nprof+1))
      if [ -r "$_pf/prefs.js" ]; then
        _pj=$(cat "$_pf/prefs.js" 2>/dev/null)
        _eng=$(printf '%s' "$_pj" | sed -n 's/.*browser\.search\.\(default\|selected\)Engine", "\([^"]*\)".*/\2/p' | head -n 1)
        case "${_eng:-}" in
          *百度*|*Baidu*|*baidu*|*sogou*|*搜狗*|*360*|*so\.com*)
            report SUSPICIOUS browser/search "Firefox 默认搜索引擎: $_eng(国内引擎,文化习惯类信号)"; _cneng=$((_cneng+1)) ;;
        esac
        _loc=$(printf '%s' "$_pj" | sed -n 's/.*intl\.locale\.\(requested\)", "\([^"]*\)".*/\2/p' | head -n 1)
        [ -z "$_loc" ] && _loc=$(printf '%s' "$_pj" | sed -n 's/.*general\.useragent\.locale", "\([^"]*\)".*/\1/p' | head -n 1)
        case "${_loc:-}" in
          zh-CN*|zh-HK*|zh-MO*) report SUSPICIOUS browser/lang "Firefox 界面语言: $_loc(文化习惯类信号)"; _zh=$((_zh+1)) ;;
        esac
      fi
    done <<EOF
$_prof_list
EOF
    report INFO browser/firefox "Firefox profile $_nprof 个(搜索引擎命中 $_cneng/界面语言命中 $_zh)"
  fi

  # ── Chromium 系(Chrome/Chromium/Brave/Edge/Vivaldi):Preferences JSON ──
  if [ "$PLATFORM" = macos ]; then
    _cp_scan="Google/Chrome
Chromium
BraveSoftware/Brave-Browser
Microsoft Edge
Vivaldi"
    _cp_root="$HOME/Library/Application Support"
  else
    _cp_scan="google-chrome
chromium
BraveSoftware/Brave-Browser
microsoft-edge
vivaldi
opera"
    _cp_root="$HOME/.config"
  fi
  while IFS= read -r _cp; do
    _bdir="$_cp_root/$_cp"
    [ -d "$_bdir" ] || continue
    _bname=$(printf '%s' "$_cp" | sed 's|.*/||')
    _nprof=0
    for _prof in "$_bdir"/Default "$_bdir"/Profile*; do
      [ -d "$_prof" ] || continue
      _nprof=$((_nprof+1))
      [ -r "$_prof/Preferences" ] || continue
      _pj=$(head -c 2000000 "$_prof/Preferences" 2>/dev/null)
      # 默认搜索引擎(Preferences 内 default_search_provider_data.short_name)
      _eng=$(printf '%s' "$_pj" | sed -n 's/.*"default_search_provider_data"[^S]*"short_name":"\([^"]*\)".*/\1/p' | head -c 40)
      case "${_eng:-}" in
        *百度*|*[Bb]aidu*|*[Ss]ogou*|*搜狗*|*360*|*so\.com*)
          report SUSPICIOUS "browser/$_bname-search" "$_bname 默认搜索引擎: $_eng(国内引擎,文化习惯类信号)" ;;
      esac
      # 界面语言 / accept-languages
      _al=$(printf '%s' "$_pj" | sed -n 's/.*"intl\.accept_languages":"\([^"]*\)".*/\1/p' | head -c 40)
      _ap=$(printf '%s' "$_pj" | sed -n 's/.*"application_locale":"\([^"]*\)".*/\1/p' | head -c 40)
      case "${_al:-}${_ap:-}" in
        *zh-CN*|*zh-HK*|*zh-MO*) report SUSPICIOUS "browser/$_bname-lang" "$_bname 界面/接受语言: ${_ap:-${_al:-?}}(文化习惯类信号)" ;;
      esac
    done
    [ "$_nprof" -gt 0 ] && report INFO "browser/$_bname" "$_bname profile $_nprof 个(已检查搜索引擎与语言设置)"
  done <<EOF
$_cp_scan
EOF

  # ── 历史/书签国内域名计数(只计数;上限 30MB/文件,防大文件耗时) ──
  _hcount=0
  _h_scan() { # $1=文件 $2=浏览器名
    [ -f "$1" ] || return 0
    if [ ! -r "$1" ]; then
      report SKIP "browser/$2-history" "(历史文件不可读;macOS 权限/TCC 限制可能导致跳过)"
      return
    fi
    _c=$(head -c 30000000 "$1" 2>/dev/null | LC_ALL=C grep -aoE 'https?://[a-zA-Z0-9.-]+' \
         | sed 's|https\?://||' | grep -cE "$CN_DOMAIN_RE" || true)
    _c=${_c:-0}
    if [ "$_c" -gt 0 ]; then
      _lvl=INFO; [ "$_c" -ge 10 ] && _lvl=SUSPICIOUS
      report "$_lvl" "browser/$2-history" "$2 历史文件前 30MB 匹配国内域名 $_c 次(原始字节近似计数,非访问次数;不输出 URL/查询词;≥10 判可疑)"
      _hcount=$((_hcount+1))
    else
      report CLEAN "browser/$2-history" "$2 历史文件前 30MB 未匹配国内域名(不代表全部历史无记录)"
    fi
  }
  if [ -d "$_ffdir" ]; then
    while IFS= read -r _pr; do
      case "$_pr" in \~/*) continue ;; esac
      case "$_pr" in /*) _pf=$_pr ;; *) _pf="$_ffdir/$_pr" ;; esac
      _h_scan "$_pf/places.sqlite" firefox
    done <<EOF
$(sed -n 's/^Path=//p' "$_ffdir/profiles.ini" 2>/dev/null)
EOF
  fi
  while IFS= read -r _cp; do
    for _prof in "$_cp_root/$_cp"/Default "$_cp_root/$_cp"/Profile*; do
      _h_scan "$_prof/History" "${_cp##*/}"
    done
  done <<EOF
$_cp_scan
EOF
}

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

#────────────────────────────── C11 time ──────────────────────────────
# 模块: 68-c11-time.sh
# 定位:时间行为统计 → 作息时区推断(防 AI 后台污染:只取用户主动动作,簇化降噪)
# 红线:只采集小时分桶,不采集/不输出任何内容、命令文本、主机名

check_c11() {
  hdr "C11 time · 时间行为统计与作息时区推断"

  # 当前系统 UTC 偏移分钟数(本地时间源换算用;历史条目按当前时区回溯 —— 已知局限)
  _z=$(date +%z 2>/dev/null)
  OFFMIN=0
  case "$_z" in
    [+-][0-9][0-9][0-9][0-9])
      _sgn=${_z%????}; _hm=${_z#?}
      _hh=${_hm%??}; _mm=${_hm#??}
      case "$_hh" in 0?) _hh=${_hh#0} ;; esac
      case "$_mm" in 0?) _mm=${_mm#0} ;; esac
      OFFMIN=$((_hh*60+_mm))
      [ "$_sgn" = "-" ] && OFFMIN=$((-OFFMIN)) ;;
  esac

  _ev=""          # 全部事件 epoch(UTC)
  _src_n=""       # 各源计数说明

  # ── t1 登录时刻(wtmp,last -F;本地时间) ──
  _n1=0
  # 注:macOS last 无 -F(完整日期)选项,跳过 t1(zsh history/AI 会话已覆盖)
  if have last && last -F -n 400 >/dev/null 2>&1 && last -F -n 400 2>/dev/null | grep -q '^[a-zA-Z0-9]'; then
    _e1=$(last -F -n 400 2>/dev/null | awk -v off=$OFFMIN '
      function mke(y,mo,d,h,mi,s, era,yoe,doy,doe,days) {
        if (mo<=2){y--}; era=int((y>=0?y:y-399)/400); yoe=y-era*400
        doy=int((153*(mo+(mo>2?-3:9))+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy
        days=era*146097+doe-719468
        return days*86400+h*3600+mi*60+s-off*60
      }
      BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",MN," ")
            for(i=1;i<=12;i++)M[MN[i]]=i}
      /^(reboot|shutdown|wtmp|btmp)/ {next}
      {
        for(f=3;f<=6;f++) if ($f ~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/) break
        if (f>6) next
        # $f=WD $(f+1)=Mon $(f+2)=Day $(f+3)=HH:MM:SS $(f+4)=Year
        if ($(f+3) !~ /^[0-9]{1,2}:[0-9][0-9]:[0-9][0-9]$/) next
        if ($(f+4) !~ /^[0-9][0-9][0-9][0-9]$/) next
        if (M[$(f+1)]=="") next
        split($(f+3),T,":")
        print mke($(f+4)+0, M[$(f+1)], $(f+2)+0, T[1]+0, T[2]+0, T[3]+0)
      }')
    _n1=$(printf '%s\n' "$_e1" | grep -c '^[0-9]' || true)
    [ "${_n1:-0}" -gt 0 ] && _ev="$_ev
$_e1"
  fi
  if [ "${_n1:-0}" -gt 0 ]; then _src_n="$_src_n 登录=$_n1"; else _src_n="$_src_n 登录=0"; fi

  # ── t2 shell history 时间戳(bash #epoch / zsh :epoch:;)(天然人工) ──
  _n2=0
  _h2="$HOME/.bash_history"
  if [ -r "$_h2" ]; then
    _n2=$(grep -c '^#[0-9]\{9,\}$' "$_h2" 2>/dev/null || true)
    if [ "${_n2:-0}" -gt 0 ]; then
      _ev="$_ev
$(grep '^#[0-9]\{9,\}$' "$_h2" | tr -d '#')"
    fi
  fi
  _h2z="$HOME/.zsh_history"
  if [ -r "$_h2z" ]; then
    _nz=$(sed -n 's/^: \([0-9]\{9,\}\):.*/\1/p' "$_h2z" 2>/dev/null | grep -c . || true)
    if [ "${_nz:-0}" -gt 0 ]; then
      _n2=$((_n2+_nz))
      _ev="$_ev
$(sed -n 's/^: \([0-9]\{9,\}\):.*/\1/p' "$_h2z")"
    fi
  fi
  _src_n="$_src_n history=$_n2"

  # ── t3 AI 会话用户输入时刻(claude/pi/codex;UTC ISO 时间戳;滤 tool_result/元数据) ──
  _n3=0
  for _base in "$HOME/.claude/projects" "$HOME/.pi/agent/sessions" "$HOME/.codex/sessions"; do
    [ -d "$_base" ] || continue
    _files=$(find "$_base" -name '*.jsonl' -mtime -120 2>/dev/null | head -n 150)
    [ -z "$_files" ] && continue
    _e3=$(while IFS= read -r _af; do
      LC_ALL=C awk '
      function mke(y,mo,d,h,mi,s, era,yoe,doy,doe,days) {
        if (mo<=2){y--}; era=int((y>=0?y:y-399)/400); yoe=y-era*400
        doy=int((153*(mo+(mo>2?-3:9))+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy
        days=era*146097+doe-719468
        return days*86400+h*3600+mi*60+s
      }
      {
        if ($0 !~ /"role"[[:space:]]*:[[:space:]]*"user"/ && $0 !~ /"type"[[:space:]]*:[[:space:]]*"user"/) next
        if ($0 ~ /"tool_result"/ || $0 ~ /"function_call_output"/ || \
            $0 ~ /"toolUseResult"/ || $0 ~ /"isMeta"[[:space:]]*:[[:space:]]*true/ || $0 ~ /"isSidechain"[[:space:]]*:[[:space:]]*true/) next
        if (!match($0, /"timestamp"[[:space:]]*:[[:space:]]*"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) next
        ts=substr($0, RSTART, RLENGTH)
        sub(/^[^:]+:[[:space:]]*"/, "", ts)
        split(ts, a, /[-T:]/)
        print mke(a[1]+0, a[2]+0, a[3]+0, a[4]+0, a[5]+0, a[6]+0)
      }' "$_af" 2>/dev/null
    done <<EOF
$_files
EOF
    )
    _c=$(printf '%s\n' "$_e3" | grep -c '^[0-9]' || true)
    if [ "${_c:-0}" -gt 0 ]; then _n3=$((_n3+_c)); _ev="$_ev
$_e3"; fi
  done
  _src_n="$_src_n AI用户输入=$_n3"

  # ── t5 交互文件 mtime(Downloads/Documents/Desktop/常用 dotfile;120 天内) ──
  _n5=0
  _e5=""
  for _d in "$HOME/Downloads" "$HOME/Documents" "$HOME/Desktop"; do
    [ -d "$_d" ] || continue
    _e5="$_e5
$(find "$_d" -maxdepth 2 -type f -mtime -120 2>/dev/null | head -n 200 | file_mtimes)"
  done
  for _f in "$HOME/.bashrc" "$HOME/.gitconfig" "$HOME/.ssh/config" "$HOME/.config/tmux/tmux.conf"; do
    [ -f "$_f" ] && [ -n "$(find "$_f" -mtime -120 2>/dev/null)" ] && _e5="$_e5
$(fs_mtime "$_f")"
  done
  _n5=$(printf '%s\n' "$_e5" | grep -c '^[0-9]' || true)
  [ "${_n5:-0}" -gt 0 ] && _ev="$_ev
$_e5"
  _src_n="$_src_n 文件mtime=$_n5"

  # ── t7 git commit 时刻+作者时区偏移(最多 6 个仓库,500 条/仓) ──
  _n7=0; _tz7=""
  if have git; then
    _mymail=$(git config --global user.email 2>/dev/null)
    _repos=$(find "$HOME" -maxdepth 3 -name .git -type d 2>/dev/null | head -n 6)
    while IFS= read -r _r; do
      [ -n "$_r" ] || continue
      _d=${_r%/.git}
      if [ -n "$_mymail" ]; then
        _gl=$(git -C "$_d" log --all --author="$_mymail" --pretty='%at %ai' -n 500 2>/dev/null)
      else
        _gl=$(git -C "$_d" log --all --pretty='%at %ai' -n 500 2>/dev/null)
      fi
      [ -z "$_gl" ] && continue
      _tz7="$_tz7
$(printf '%s\n' "$_gl" | grep -oE '[+-][0-9]{4}$' | sort | uniq -c)"
      _e7=$(printf '%s\n' "$_gl" | awk '$1 ~ /^[0-9]+$/ {print $1}')
      _c=$(printf '%s\n' "$_e7" | grep -c '^[0-9]' || true)
      [ "${_c:-0}" -gt 0 ] && { _n7=$((_n7+_c)); _ev="$_ev
$_e7"; }
    done <<EOF
$_repos
EOF
  fi
  _src_n="$_src_n git提交=$_n7"

  # ── t9 包安装时刻(dnf/apt/pacman;本地时间) ──
  _n9=0; _e9=""
  if have dnf; then
    _e9=$(dnf history list --reverse 2>/dev/null | awk -v off=$OFFMIN -F'|' '
      function mke(y,mo,d,h,mi,s,om, era,yoe,doy,doe,days) {
        if (mo<=2){y--}; era=int((y>=0?y:y-399)/400); yoe=y-era*400
        doy=int((153*(mo+(mo>2?-3:9))+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy
        days=era*146097+doe-719468
        return days*86400+h*3600+mi*60+s-om*60
      }
      $1 ~ /^[ ]*[0-9]+[ ]*$/ && $4 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
        gsub(/^ +| +$/,"",$4); split($4, p, /[ :-]/)
        print mke(p[1]+0,p[2]+0,p[3]+0,p[4]+0,p[5]+0,0, off)
      }')
  elif [ -r /var/log/apt/history.log ]; then
    _e9=$(sed -n 's/^Start-Date: \([0-9-]\{10\}\)  \([0-9:]\{8\}\).*/\1 \2/p' /var/log/apt/history.log | awk -v off=$OFFMIN '
      function mke(y,mo,d,h,mi,s,om, era,yoe,doy,doe,days) {
        if (mo<=2){y--}; era=int((y>=0?y:y-399)/400); yoe=y-era*400
        doy=int((153*(mo+(mo>2?-3:9))+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy
        days=era*146097+doe-719468
        return days*86400+h*3600+mi*60+s-om*60
      }{ split($1,a,"-"); split($2,b,":"); print mke(a[1]+0,a[2]+0,a[3]+0,b[1]+0,b[2]+0,b[3]+0, off) }')
  fi
  _n9=$(printf '%s\n' "$_e9" | grep -c '^[0-9]' || true)
  [ "${_n9:-0}" -gt 0 ] && _ev="$_ev
$_e9"
  _src_n="$_src_n 装包=$_n9"

  # ── t10 桌面交互旁证(输入法词库/浏览器历史文件 mtime,存在才计) ──
  _n10=0; _e10=""
  for _f in "$HOME/.config/fcitx/profile" "$HOME/.local/share/fcitx5" "$HOME/.config/ibus"; do
    if [ -e "$_f" ]; then
      _e10="$_e10
$(find "$_f" -type f -mtime -120 2>/dev/null | head -n 30 | file_mtimes)"
    fi
  done
  for _f in "$HOME/.config/google-chrome/Default/History" "$HOME/.mozilla/firefox"/*/"places.sqlite" \
    "$HOME/Library/Application Support/Google/Chrome"/*/History \
    "$HOME/Library/Application Support/Microsoft Edge"/*/History \
    "$HOME/Library/Application Support/Firefox/Profiles"/*/places.sqlite; do
    [ -f "$_f" ] && _e10="$_e10
$(fs_mtime "$_f")"
  done
  _n10=$(printf '%s\n' "$_e10" | grep -c '^[0-9]' || true)
  [ "${_n10:-0}" -gt 0 ] && _ev="$_ev
$_e10"
  _src_n="$_src_n 桌面旁证=$_n10"

  # ── t6 重启时刻(仅 INFO,不入扫描) ──
  if have last && last -F reboot -n 10 2>/dev/null | grep -q 'reboot'; then
    _rb=$(last -F reboot -n 10 2>/dev/null | grep -c 'reboot' || true)
    report INFO time/reboots "近 $_rb 次重启(wtmp;云主机重启多由控制台/宿主发起,不作作息依据)"
  fi

  # ── t4 聚合:排序去重 → 5 分钟簇化取簇首(人簇发,AI 平铺;降权爆发) ──
  _n_raw=$(printf '%s\n' "$_ev" | grep -c '^[0-9]' || true)
  if [ "${_n_raw:-0}" -lt 30 ]; then
    report SKIP time/infer "(有效事件 ${_n_raw:-0} 个 <30,样本不足,不推断;${_src_n# })"
    return
  fi
  _cl=$(printf '%s\n' "$_ev" | grep '^[0-9]' | sort -n | uniq | awk '
    { if ($1 - prev > 300 || NR==1) { print $1; prev = $1 } }')
  _ncl=$(printf '%s\n' "$_cl" | grep -c '^[0-9]' || true)

  # ── UTC 直方图 + offset 扫描(-12…+14,步长 0.5h;得分 = P(08–24 本地) − P(01–07 本地)) ──
  _res=$(printf '%s\n' "$_cl" | awk '
    { h[int($1/3600)%24]++; wd[int(($1/86400+4))%7]++ }
    END {
      n=0; for(i=0;i<24;i++) n+=h[i]
      best_s=-2
      for (oi=-24; oi<=28; oi++) {
        off=oi*0.5; act=0; slp=0
        for (i=0;i<24;i++) {
          lh=i+off; while (lh<0) lh+=24; lh=lh%24
          if (lh>=8 && lh<24) act+=h[i]
          else if (lh>=1 && lh<7) slp+=h[i]
        }
        S[oi]=(act-slp)/n
        if (S[oi]>best_s) best_s=S[oi]
      }
      offs=""; first=1; sec_s=-2
      for (oi=-24; oi<=28; oi++) {
        if (S[oi] >= best_s-0.005) {
          if (first) { offs=sprintf("%.1f", oi*0.5); first=0 }
          else offs=offs "," sprintf("%.1f", oi*0.5)
        } else if (S[oi] > sec_s) sec_s=S[oi]
      }
      we=0; for(i=0;i<7;i++) if (i==0||i==6) we+=wd[i]
      printf "%s %.3f %.3f %.3f\n", offs, best_s, sec_s, (n?we/n:0)
      m=0; for(i=0;i<24;i++) if (h[i]>m) m=h[i]
      for(i=0;i<24;i++) printf "%02d %d\n", i, (m? int(h[i]*30/m+0.5) : 0)
    }')
  _offs=$(printf '%s\n' "$_res" | sed -n '1p' | awk '{print $1}')
  _bo=${_offs%%,*}
  _bs=$(printf '%s\n' "$_res" | sed -n '1p' | awk '{print $2}')
  _b2=$(printf '%s\n' "$_res" | sed -n '1p' | awk '{print $3}')
  _we=$(printf '%s\n' "$_res" | sed -n '1p' | awk '{print $4}')

  case "$_bs" in
    0.*|1.*) : ;;
    *) _bs=0 ;;
  esac
  if awk "BEGIN{exit !($_bs >= 0.55)}"; then _conf=高
  elif awk "BEGIN{exit !($_bs >= 0.35)}"; then _conf=中
  else _conf=低; fi

  # ASCII 直方图(UTC 小时分布;--brief/--json 时省略,判定行仍输出)
  if [ "$BRIEF" != 1 ] && [ "${JSON:-0}" != 1 ]; then
    printf '%s   UTC 小时分布(30 格满幅,簇首 %d 个/原始 %d 个;%s)%s\n' "$C_DIM" "$_ncl" "$_n_raw" "$(printf '%s' "$_src_n" | sed 's/^ //')" "$C_RST"
    printf '%s\n' "$_res" | tail -n 24 | awk -v c="$C_DIM" -v r="$C_RST" \
      '{printf "%s   %s %s%s\n", c, $1, substr("------------------------------", 1, $2), r}'
  fi

  # ── 判定 1:作息推断 vs 系统时区设置(一致性检验) ──
  TZ_INFER_OFF=$_offs; TZ_INFER_CONF=$_conf; TZ_INFER_N=$_ncl
  _olo=99; _ohi=-99
  for _o in $(printf '%s' "$_offs" | tr ',' ' '); do
    awk "BEGIN{exit !($_o < $_olo)}" && _olo=$_o
    awk "BEGIN{exit !($_o > $_ohi)}" && _ohi=$_o
  done
  # 东八关联度三档:contains(区间含 8.0,强)/ near(东亚工作节奏段 5–8.5,上缘≥7;
  # +7 时区如曼谷/雅加达/河内/珀斯亦可解释,仅作中等关联)/ none(无关联)
  _e8rel=none
  awk "BEGIN{exit !($_olo <= 8.0 && 8.0 <= $_ohi)}" && _e8rel=contains
  [ "$_e8rel" = none ] && awk "BEGIN{exit !($_ohi >= 7.0 && $_ohi <= 8.5 && $_olo >= 5.0)}" && _e8rel=near
  TZ_INFER_E8=no; [ "$_e8rel" != none ] && TZ_INFER_E8=yes
  case "$_e8rel" in
    contains) _e8desc="作息区间含 UTC+8" ;;
    near)     _e8desc="东/东南亚工作节奏段(UTC+${_olo}–${_ohi};+7 时区如曼谷/雅加达/珀斯亦可解释)" ;;
    *)        _e8desc="" ;;
  esac
  _we_pct=$(awk -v fraction="$_we" 'BEGIN {printf "%.0f%%", fraction*100}')
  report INFO time/infer "作息推断 UTC+${_offs}(置信${_conf};最佳得分 $_bs,次优 $_b2;周末占比 $_we_pct)${_e8desc:+ · $_e8desc}"

  _tz_hit=""; case "${TZ_CLASS:-}" in CN|HKMO) _tz_hit=hit ;; esac
  if [ -z "${TZ_NAME:-}" ]; then
    report SKIP time/tz-consist "(系统时区不可探测,无法与作息比对)"
  elif [ "$_conf" = "低" ]; then
    report INFO time/tz-consist "作息推断置信低(直方图平坦/混合用户/自动化占比高),关联性弱,不作一致性判定(系统时区 $TZ_NAME)"
  else
    _so=$(tz_off_hours "$TZ_NAME")
    if [ -n "$_so" ] && awk "BEGIN{exit !($_so >= $_olo && $_so <= $_ohi)}"; then
      report CLEAN time/tz-consist "作息区间 UTC+${_olo}–${_ohi} 覆盖系统时区偏移(UTC+${_so})—— 时区设置与实际使用节奏一致(佐证)"
    elif [ -n "$_so" ]; then
      if awk "BEGIN{exit !($_so < $_olo)}"; then _d=$(awk "BEGIN{printf \"%.1f\", $_olo-$_so}"); else _d=$(awk "BEGIN{printf \"%.1f\", $_so-$_ohi}"); fi
      if awk "BEGIN{exit !($_d >= 1.0)}"; then
        if [ "$_e8rel" != none ]; then
          report SUSPICIOUS time/tz-consist "作息推断 UTC+${_offs}(置信${_conf},${_e8desc})与系统时区 $TZ_NAME(UTC+${_so})偏差 ${_d}h —— 时区设置与实际使用节奏不一致(作息软证据,长居东八者特征)"
        elif [ "$_tz_hit" = hit ]; then
          report SUSPICIOUS time/tz-consist "系统时区为陆港澳($TZ_NAME,UTC+${_so})而作息推断 UTC+${_offs}(偏差 ${_d}h)—— 时区声明与使用节奏矛盾(伪装痕迹或样本污染)"
        else
          report SUSPICIOUS time/tz-consist "作息推断 UTC+${_offs}(置信${_conf})与系统时区 $TZ_NAME(UTC+${_so})偏差 ${_d}h —— 时区设置与实际使用节奏不一致"
        fi
      else
        report INFO time/tz-consist "作息区间 UTC+${_olo}–${_ohi} 与系统时区(UTC+${_so})偏差 ${_d}h(轻微;夜猫型作息会前移推断值)"
      fi
    else
      report SKIP time/tz-consist "(系统时区偏移不可解析: $TZ_NAME)"
    fi
  fi

  # ── 判定 2:内地法定假日/调休补班日历检验(调休为内地特有;港澳及海外无此实践) ──
  _off8=$(printf '%s' "$_offs" | tr ',' '\n' | awk '{d=($1>8?$1-8:8-$1); if(NR==1||d<bd){bd=d;bo=$1}} END{print bo}')
  _cal=$(printf '%s\n' "$_cl" | awk -v off="$_off8" -v hol="$CN_HOLIDAYS" -v mk="$CN_MAKEUP" '
    function dfc(y,mo,d, era,yoe,doy,doe) {
      if (mo<=2){y--}; era=int((y>=0?y:y-399)/400); yoe=y-era*400
      doy=int((153*(mo+(mo>2?-3:9))+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy
      return era*146097+doe-719468
    }
    function cfd(z, era,doe,yoe,y,doy,mp,dd) {
      z+=719468; era=int((z>=0?z:z-146096)/146097); doe=z-era*146097
      yoe=int((doe-int(doe/1460)+int(doe/36524)-int(doe/146096))/365)
      y=yoe+era*400; doy=doe-(365*yoe+int(yoe/4)-int(yoe/100))
      mp=int((5*doy+2)/153); dd=doy-int((153*mp+2)/5)+1
      mp+=3; if (mp>12){mp-=12;y++}
      return sprintf("%04d%02d%02d", y, mp, dd)
    }
    BEGIN {
      nh=split(hol,H," "); for(i=1;i<=nh;i++) HOL[H[i]]=1
      nm=split(mk,M," "); for(i=1;i<=nm;i++) MK[M[i]]=1
    }
    {
      lt=$1+off*3600; days=int(lt/86400); dt=cfd(days); dow=(days+4)%7
      if (MK[dt]) { mkev++; if(!(dt in MKD)){MKD[dt]=1; mkd++} }
      else if (HOL[dt] && dow!=0 && dow!=6) { hev++; if(!(dt in HD)){HD[dt]=1; hd++} }
      else if (dow==0||dow==6) { wev++ }
      else { wdev++ }
      if (mn==""||$1<mn) mn=$1; if ($1>mx) mx=$1
    }
    END {
      if (mn!="") {
        dmin=cfd(int((mn+off*3600)/86400)); dmax=cfd(int((mx+off*3600)/86400))
        for (d in MK) if (d>=dmin && d<=dmax) mkcov++
        for (d in HOL) if (d>=dmin && d<=dmax) {
          dow2=(dfc(substr(d,1,4)+0, substr(d,5,2)+0, substr(d,7,2)+0)+4)%7
          if (dow2!=0 && dow2!=6) holcov++
        }
      }
      printf "%d %d %d %d %d %d %d %d\n", mkev+0, mkd+0, hev+0, hd+0, wdev+0, wev+0, mkcov+0, holcov+0
    }')
  set -- $_cal
  _mkev=$1; _mkd=$2; _hev=$3; _hd=$4; _wdev=$5; _wev=$6; _mkcov=$7; _holcov=$8
  if [ "${_mkcov:-0}" -eq 0 ] || [ "${_holcov:-0}" -lt 3 ]; then
    report SKIP time/cn-calendar "(数据窗口未覆盖足够调休/法定假日(补班日覆盖 ${_mkcov:-0} 个/假日工作日 ${_holcov:-0} 天;日历表覆盖 2024–2026),无法检验内地日历)"
  elif [ "${_mkev:-0}" -ge 1 ] && [ "${_hev:-0}" -eq 0 ]; then
    _cald="调休补班日活跃(${_mkd} 天/窗口内 ${_mkcov} 个)且法定假日(工作日 ${_holcov} 天)零活动 —— 作息遵循内地工作日历"
    if [ "$_tz_hit" = hit ]; then
      report INFO time/cn-calendar "$_cald(与系统时区一致,佐证)"
    elif [ "$_mkd" -ge 2 ]; then
      report SUSPICIOUS time/cn-calendar "$_cald(强烈作息软证据:调休为内地特有,而机器环境非东八)"
    else
      report INFO time/cn-calendar "$_cald(单日样本,证据偏弱;调休为内地特有实践)"
    fi
  elif [ "${_hev:-0}" -ge 3 ] && [ "${_mkev:-0}" -eq 0 ]; then
    if [ "$_tz_hit" = hit ]; then
      report INFO time/cn-calendar "法定假日(工作日)活跃 ${_hd} 天而调休补班日零活动 —— 不符合内地休假节奏(系统时区为陆港澳,声明与日历行为矛盾;亦可能值守/自由职业)"
    else
      report INFO time/cn-calendar "法定假日(工作日)活跃 ${_hd} 天 —— 假期仍工作,海外/自由职业节奏正常,不构成内地佐证"
    fi
  else
    report INFO time/cn-calendar "日历统计:补班日活跃 ${_mkev} 次/假日工作日 ${_hev} 次/工作日 ${_wdev} 次/周末 ${_wev} 次(混合模式,无明确指向)"
  fi

  # ── t7 附加:git 作者时区偏移直方图(计数为提交数,非仓库数) ──
  _tot7=0; _n8c=0
  if printf '%s\n' "$_tz7" | grep -q '[0-9]'; then
    _tot7=$(printf '%s\n' "$_tz7" | awk '{s+=$1} END{print s+0}')
    _n8c=$(printf '%s\n' "$_tz7" | grep ' +0800' | awk '{s+=$1} END{print s+0}')
    if [ "${_n8c:-0}" -gt 0 ] && [ -n "${TZ_CLASS:-}" ] && [ "${TZ_CLASS:-}" != CN ] && [ "${TZ_CLASS:-}" != HKMO ] && [ "${TZ_CLASS:-}" != E8 ]; then
      report SUSPICIOUS time/git-tz "git 提交作者时区含 +0800(共 $_n8c 条提交)而系统时区非东八 —— 作者本地环境残留"
    elif [ "${_n8c:-0}" -gt 0 ] && [ -z "${TZ_CLASS:-}" ]; then
      report INFO time/git-tz "git 作者时区偏移分布:$_n8c/$_tot7 条提交为 +0800(系统时区未探测,无法比对)"
    elif [ "${_n8c:-0}" -gt 0 ]; then
      report INFO time/git-tz "git 作者时区偏移分布:$_n8c/$_tot7 条提交为 +0800(与系统时区一致)"
    else
      report INFO time/git-tz "git 作者时区偏移分布:无 +0800 条目(共 $_tot7 条提交)"
    fi
  fi

  # ── 判定 3:复合升级(行为统计 + 独立记录性旁证 → 暴露级) ──
  # 单条作息不作暴露:东/东南亚 +7 时区(曼谷/雅加达/河内/珀斯)与 +8 在边界小时上原理性不可分;
  # 但「强统计矛盾 + 独立记录性 +8 证据」的复合,按既定 E8 政策(配置级 E8 矛盾 = 暴露)同权处理,
  # 残余误报为真正的 +8 非陆港澳用户(新加坡/马来西亚/台湾等),与 E8 规则同级。
  if [ "${_e8rel:-none}" != none ] && [ "${_tz_hit:-}" != hit ] && [ -n "${TZ_NAME:-}" ] \
     && [ -n "${_so:-}" ] && [ "${_conf:-}" = "高" ] && [ "${_ncl:-0}" -ge 60 ] \
     && awk "BEGIN{exit !(${_bs:-0} >= 0.85)}" && awk "BEGIN{exit !(${_d:-0} >= 1.5)}"; then
    _corr=""
    if [ "${_n8c:-0}" -ge 3 ]; then
      _corr="git 作者时区 +0800($_n8c 条提交,独立记录性证据)"
    elif [ "${_mkev:-0}" -ge 1 ] && [ "${_mkd:-0}" -ge 2 ] && [ "${_hev:-0}" -eq 0 ]; then
      _corr="内地调休日历遵循(补班日活跃 $_mkd 天且法定假日零活动,内地特有实践)"
    fi
    if [ -n "$_corr" ]; then
      report EXPOSED time/tz-consist-strong "作息区间 UTC+${_olo}–${_ohi}(得分 ${_bs},N=${_ncl},置信高)与系统时区 ${TZ_NAME}(UTC+${_so})偏差 ${_d}h,且有独立旁证:$_corr —— 行为与记录复合证据指向东八,时区设置无法解释实际使用节奏"
    fi
  fi
}

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

#────────────────────────────── macOS 适配层 ──────────────────────────────
# 模块: 70-macos.sh
# 定位:仅 macOS 平台 —— 补齐 Linux 检测覆盖不到的系统级地域痕迹
#       (系统区域/系统代理/launchctl 服务/输入法/用户字体/Homebrew 镜像)
# 原则:与 Linux 各类同语义同级别;时区/DNS/出口/浏览器/会话由既有类别原生覆盖
#       (/etc/localtime、scutil --dns、curl、who、~/Library 浏览器路径)

check_mac() {
  hdr "macOS · 系统级地域痕迹(scutil/defaults/launchctl,只读)"

  if [ "$PLATFORM" != "macos" ]; then
    report SKIP macos/all "(非 macOS 环境)"
    return
  fi

  # ── 系统区域/首选语言(defaults 只读;软信号) ──
  if have defaults; then
    _al=$(defaults read -g AppleLocale 2>/dev/null)
    case "${_al:-}" in
      zh_CN*|zh_HK*|zh_MO*|zh_Hans_CN*|zh-Hans-CN*) report SUSPICIOUS macos/locale "系统区域 AppleLocale=$_al(文化习惯类信号)" ;;
      "") : ;;
      *) report INFO macos/locale "系统区域 AppleLocale=$_al" ;;
    esac
    _alang=$(defaults read -g AppleLanguages 2>/dev/null | sed -n '/^[[:space:]]*[()]$/d; s/^[[:space:]]*"*\([^", ]*\)"*,*[[:space:]]*$/\1/p' | head -n 1)
    case "${_alang:-}" in
      zh-Hans*|zh-Hant-HK*|zh-Hant-MO*|zh-Hans-CN*) report SUSPICIOUS macos/lang-first "首选语言 $_alang(文化习惯类信号)" ;;
      "") : ;;
      *) report INFO macos/lang-first "首选语言 $_alang" ;;
    esac
    # 输入法(HIToolbox;系统自带拼音/五笔等中文输入源)
    _ime=$(defaults read com.apple.HIToolbox AppleEnabledInputSources 2>/dev/null)
    if printf '%s' "${_ime:-}" | grep -qiE 'SCIM|ITABC|WUBI|Pinyin|Shuangpin|Cangjie'; then
      if printf '%s' "$_ime" | grep -qE '"Input Source Kind" = "Keyboard Input Method"|com.apple.inputmethod'; then
        report SUSPICIOUS macos/ime "启用了中文输入法(SCIM/ITABC 等;文化习惯类信号)"
      fi
    fi
    _kb=$(defaults read com.apple.HIToolbox AppleCurrentKeyboardLayoutInputSourceID 2>/dev/null)
    [ -n "${_kb:-}" ] && report INFO macos/xkb "当前键盘布局: $_kb"
  else
    report SKIP macos/defaults "(defaults 不可用)"
  fi

  # ── 系统代理:尊重缩进;HTTP/HTTPS/SOCKS/PAC/WPAD 分开报告 ──
  if have scutil && _sp=$(scutil --proxy 2>/dev/null) && [ -n "$_sp" ]; then
    _enabled=0
    for _kind in HTTP HTTPS SOCKS; do
      if printf '%s\n' "$_sp" | awk -v k="${_kind}Enable" '$1==k && $2==":" && $3==1 {found=1} END {exit !found}'; then
        _enabled=1
        # Scoped dictionaries may contain several endpoints; do not pair unrelated fields.
        report INFO macos/proxy "${_kind} 系统代理已启用(scutil;含按接口配置,不据代理端口推断地区)"
      fi
    done
    for _key in ProxyAutoConfigEnable ProxyAutoDiscoveryEnable; do
      if printf '%s\n' "$_sp" | awk -v k="$_key" '$1==k && $2==":" && $3==1 {found=1} END {exit !found}'; then
        _enabled=1
        report INFO macos/proxy "自动代理 $_key 已启用(不读取 PAC 内容或输出 URL)"
      fi
    done
    [ "$_enabled" = 0 ] && report CLEAN macos/proxy "系统代理未启用(scutil)"
  else
    report SKIP macos/proxy "(scutil --proxy 不可用/无权限/无数据)"
  fi

  # ── launchctl 服务(同 C14 语义:代理栈 INFO / 国内消费软件可疑) ──
  if have launchctl; then
    _lc_out=$(launchctl list 2>/dev/null)
    if [ -n "${_lc_out:-}" ]; then
      _px=$(printf '%s' "$_lc_out" | awk '{print $3}' | grep -iE '(^|\.)(clash|mihomo|v2ray|xray|sing-box|singbox|trojan|hysteria|surge|shadowrocket|quantumult)(\.|$)' | head -n 5 | tr '\n' ' ')
      has_text "$_px" && report INFO macos/proxy-daemon "launchd 代理栈: $_px(角色语义见 path/proxy)"
      _cn=$(printf '%s' "$_lc_out" | awk '{print $3}' | mac_cn_labels | head -n 5 | tr '\n' ' ')
      has_text "$_cn" && report SUSPICIOUS macos/cn-daemon "launchd 已加载国内软件标签: $_cn(含运行中/按需服务,不等同于活动会话;文化习惯类信号)"
      report INFO macos/services "launchd 用户服务 $(printf '%s' "$_lc_out" | wc -l | tr -d ' ') 条(已做国内软件/代理栈匹配)"
    else
      report SKIP macos/services "(launchctl list 不可用/无可见服务)"
    fi
  else
    report SKIP macos/services "(无 launchctl)"
  fi

  # ── 用户字体(~/Library/Fonts;系统自带 PingFang/华文不计) ──
  if [ -d "$HOME/Library/Fonts" ]; then
    _cf=$(ls "$HOME/Library/Fonts" 2>/dev/null | grep -iE 'LXGW|Sarasa|Noto.*CJK|SourceHan|思源|霞鹜|文泉|wqy|方正|汉仪|造字工房' | head -n 4 | tr '\n' ' ')
    if has_text "$_cf"; then
      report SUSPICIOUS macos/fonts "用户安装 CJK 字体: $_cf(文化习惯类信号)"
    else
      report CLEAN macos/fonts "用户字体目录无常见中文字体"
    fi
  else
    report SKIP macos/fonts "(无用户字体目录)"
  fi

  # ── Homebrew 镜像(同 C9 语义) ──
  if have brew; then
    _brd=$(brew --repository 2>/dev/null)
    if [ -n "$_brd" ] && [ -r "$_brd/.git/config" ]; then
      _burl=$(git -C "$_brd" config --get remote.origin.url 2>/dev/null)
      case "${_burl:-}" in
        *tsinghua*|*tuna*|*ustc.edu*|*aliyun*|*tencent*|*bfsu*|*bjtu*|*cqu*) report SUSPICIOUS macos/brew-mirror "Homebrew remote 命中国内镜像: $(printf '%s' "$_burl" | sed 's|.*//||; s|/.*||')(文化习惯类信号)" ;;
        ""|*github.com*) report CLEAN macos/brew-mirror "Homebrew remote 为官方/默认源" ;;
        *) report INFO macos/brew-mirror "Homebrew remote: $(printf '%s' "$_burl" | sed 's|.*//||; s|/.*||')" ;;
      esac
    fi
  else
    report SKIP macos/brew "(未安装 Homebrew)"
  fi

}

#────────────────────────────── 汇总与主流程 ──────────────────────────────
# 模块: 90-main.sh

run_section() {
  case "$1" in
    sysinfo)  check_c1 ;;
    macos)    check_mac ;;
    cloud)    check_c2 ;;
    boot)     check_c16 ;;
    kernelnet) check_c17 ;;
    session)  check_c18 ;;
    wsl)      check_wsl ;;
    egress)   check_c3 ;;
    path)     check_c4 ;;
    proxy)    check_c5 ;;
    dns)      check_c6 ;;
    locale)   check_c8 ;;
    mirror)   check_c9 ;;
    fs)       check_c10 ;;
    anti)     check_c12 ;;
    services) check_c14 ;;
    gui)      check_c19 ;;
    browser)  check_c15 ;;
    hw)       check_c13 ;;
    time)     check_c11 ;;
    usegeo|c20) check_c20 ;;
    *) return 1 ;;
  esac
  return 0
}

summary() {
  printf '\n%s══ 汇总 ══%s\n' "$C_HDR" "$C_RST"
  if [ "$CNT_EXP" -gt 0 ]; then
    printf '%s[✗] 暴露 (%d):%s\n' "$C_EXP" "$CNT_EXP" "$C_RST"
    printf '%s' "$LOG_EXP" | awk -F'|' -v c="$C_EXP" -v r="$C_RST" \
      '{printf "%s  %d. [%s] %s%s\n", c, NR, $1, substr($0, index($0,"|")+1), r}'
  else
    printf '%s[✗] 暴露 (0)%s\n' "$C_CLN" "$C_RST"
  fi
  if [ "$CNT_SUS" -gt 0 ]; then
    printf '%s[!] 可疑 (%d):%s\n' "$C_SUS" "$CNT_SUS" "$C_RST"
    printf '%s' "$LOG_SUS" | awk -F'|' -v c="$C_SUS" -v r="$C_RST" \
      '{printf "%s  %d. [%s] %s%s\n", c, NR, $1, substr($0, index($0,"|")+1), r}'
  else
    printf '%s[!] 可疑 (0)%s\n' "$C_CLN" "$C_RST"
  fi
  if [ -n "${USEGEO_VIEW:-}" ]; then
    printf '%s\n实际使用地区视图(C20 融合)%s\n' "$C_HDR" "$C_RST"
    printf '%s\n' "$USEGEO_VIEW"
  fi
  printf '统计: 正常 %d | 可疑 %d | 暴露 %d | 信息 %d | 跳过 %d\n' \
    "$CNT_CLN" "$CNT_SUS" "$CNT_EXP" "$CNT_INF" "$CNT_SKP"
  printf 'v%s · 判定规则见 PLAN.md · 本工具为一致性体检,不评判、不承诺规避效果\n' "$VERSION"
}

main() {
  if [ "${JSON:-0}" != 1 ]; then
    printf '%sregion-trace-audit v%s — 陆港澳用户环境痕迹检测器(只读)%s\n' "$C_HDR" "$VERSION" "$C_RST"
    printf '模式: %s · 脱敏: %s · 检测项降级将标注原因\n\n' \
      "$([ "$OFFLINE" = 1 ] && printf '本地检测(--offline,无外联)' || printf '本地 + active-probe(外联: ip-api/ipinfo/api64)')" \
      "$([ "$REVEAL" = 1 ] && printf '关闭(--reveal)' || printf '开启(默认)')"
  fi

  detect_platform
  collector_context
  http_detect
  net_context
  if [ "$SECTION" = "all" ]; then
    for _s in sysinfo macos cloud boot kernelnet session egress path proxy dns wsl locale mirror fs anti services gui browser hw time usegeo; do run_section "$_s"; done
  else
    # 轻量前置上下文:time/usegeo 依赖时区与 locale,单项运行时就地采集,避免结论静默失真
    case "$SECTION" in
      time|usegeo|c20)
        _tzl=$(readlink /etc/localtime 2>/dev/null)
        [ -n "$_tzl" ] && TZ_NAME=$(printf '%s' "$_tzl" | sed 's|.*zoneinfo/||')
        [ -n "${TZ_NAME:-}" ] && TZ_CLASS=$(tz_class "$TZ_NAME")
        if [ -r /etc/locale.conf ]; then
          case "$(sed -n 's/^LANG=//p' /etc/locale.conf | tr -d '"' | head -n 1)" in
            zh_CN*|zh_HK*|zh_MO*) LOCALE_ZH=1 ;;
          esac
        fi
        ;;
    esac
    report INFO main/section-mode "单项模式($SECTION):跨类别上下文未完整采集,融合/一致性结论可能不完整(完整结论请全量运行)"
    run_section "$SECTION" || { printf '未知类别: %s(可用: sysinfo macos cloud boot kernelnet session egress path proxy dns wsl locale mirror fs anti services gui browser hw time usegeo/c20)\n' "$SECTION" >&2; exit 64; }
  fi

  if   [ "$CNT_EXP" -gt 0 ]; then EXIT_CODE=2
  elif [ "$CNT_SUS" -gt 0 ]; then EXIT_CODE=1
  else EXIT_CODE=0
  fi
  if [ "${JSON:-0}" = 1 ]; then
    json_emit
  else
    summary
  fi
  exit "$EXIT_CODE"
}

main
