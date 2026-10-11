# region-trace-audit

**陆港澳用户环境痕迹检测器** —— 一个只读的 POSIX sh 单文件脚本,检测当前机器上是否存在暴露「使用者来自中国大陆/香港/澳门」的痕迹,或伪装失败留下的矛盾痕迹。

> **立场:一致性体检。** 本工具回答「这台机器呈现的环境是否与一个非陆港澳背景的使用者自洽」,不评判使用者的身份与行为,**不承诺任何规避效果**。

## 快速使用

```sh
sh region-trace-audit.sh              # 完整检测(本地 + active-probe)
sh region-trace-audit.sh --offline    # 零外联(纯本地检测)
sh region-trace-audit.sh --brief      # 只看 可疑/暴露 行 + 汇总
sh region-trace-audit.sh --json       # 机器可读输出(单 JSON 对象)
sh region-trace-audit.sh --reveal     # 显示完整 IP(默认脱敏:IP 前两段)
sh region-trace-audit.sh --section session   # 只运行指定类别
sh region-trace-audit.sh --help
```

可选深检:`--deep-geo`(known_hosts/活跃连接对端批量 GeoIP)、`--radio`(无线监管域/WiFi 关联/WWAN MCC,桌面/物理机场景)。
**开启 `--deep-geo` 前请知悉:该模式会把待查 IP 发送给 ip-api.com。**

## 判定五态与退出码

| 级别 | 含义 | 退出码 |
|---|---|---|
| ✗ 暴露 | 位置/链路实锤(如系统时区为陆港澳确定时区、活跃控制端位于陆港澳) | 2 |
| ! 可疑 | 软信号(文化习惯类)、刻意痕迹、伪装矛盾 | 1 |
| ✓ 正常 | 检测完成且未命中 | 0 |
| * 信息 | 上下文注记(中资云、代理角色、链路断点等) | — |
| - 跳过 | 依赖缺失/不适用(注明原因) | — |

## 检测类别

| 类别 | 内容 |
|---|---|
| C1 sysinfo | 系统与平台、采集者边界(u0:本工具自身上下文) |
| MAC macos | macOS 适配:系统区域/系统代理(scutil)/launchd 服务/输入法/用户字体/Homebrew 镜像 |
| C2 cloud | 中资云与定制系统(**仅信息级**,含海外节点;普通 VPS 不作检测点) |
| C16 boot | 引导与初始化来源(归因:cloud-init/cmdline 注入含 TZ 判定) |
| C17 kernelnet | 内核/命名空间/路由全貌(**全信息级**,声明观测范围) |
| C18 session | 会话图与远程入口分类(IDE-remote/web/cloud-console;活跃 SSH 对端;自身对端 GeoIP) |
| C3 egress | 出口 GeoIP 双源交叉 + rDNS + 双栈一致性;`--deep-geo` 连接图谱 |
| C4 path | 路径检测:CN 骨干网、网关 OUI、MTU、CGNAT |
| C5 proxy | 代理/隧道/覆盖网络角色(Tailscale/cloudflared/WARP 等) |
| C6 dns | 解析器归属 + 污染探测(≥2 已知假 IP 才判暴露) |
| WS wsl | WSL interop:Windows 侧区域/时区/系统代理/Nls 语言/hosts(仅 WSL) |
| C8 locale | 时区三档判定、LANG/键盘、locale 生成记录 |
| C9 mirror | 发行版源/pip/npm/cargo/go/maven/docker 国内镜像 |
| C10 fs | 文件系统人类痕迹(known_hosts、history、下载目录、中文文件名) |
| C12 anti | 隐藏与伪造痕迹(马脚检测:wtmp 不可读、rc 伪造 SSH_*、landlock wrapper 等) |
| C14 services | 进程/端口/服务四态(国内软件、代理栈端口归属表) |
| C19 gui | 图形会话、输入法配置、CJK 字体、远程桌面 11 产品四态(connected 才可疑) |
| C15 browser | 浏览器 profile/默认搜索引擎/界面语言/历史国内域名计数(**不读 URL 明文**) |
| C13 hw | DMI/CPU 品牌;`--radio`:iw 监管域、WWAN MCC(460/461 = 暴露,物理在场实锤) |
| C11 time | 时间行为统计 → 作息时区推断 + **时区一致性** + **内地法定假日/调休日历检验** |
| C20 usegeo | 实际使用地区融合视图(会话链/出口/链路断点/证据家族/冲突链,见汇总区) |

## 判定对照表(核心规则速查)

**暴露级(位置/链路实锤):**
- 系统时区为陆港澳确定时区(Asia/Shanghai 及别名、Hong_Kong、Macau、Urumqi)
- 系统时区为东八(非陆港澳)+ 出口非东八 —— 时区与地区矛盾(东八特判)
- **作息+记录复合证据**:作息区间与系统时区强矛盾(偏差≥1.5h、得分≥0.85、N≥60 簇、置信高)且存在独立记录性旁证(git 作者时区 +0800 ≥3 条提交 / 内地调休日历遵循)—— 残余误报为真正 +8 非陆港澳用户(新/马/台),与既定 E8 政策同级
- **融合升级(C20)**:≥2 个非纯文化证据家族(链路/配置/行为级)一致指向陆港澳
- 出口 IPv4/IPv6 GeoIP 位于陆港澳(**需双源一致**;单源或不一致降为可疑)
- 活跃 SSH 会话控制端 GeoIP 位于陆港澳(controller-net)
- WWAN 蜂窝注册 MCC=460/461(`--radio`;local-access-net 物理在场)
- WSL:Windows 时区为 China Standard Time(陆/港/澳共用)
- cmdline 注入 TZ= 陆港澳确定时区
- DNS 污染探测 ≥2 个已知域名命中已知假 IP 表

**可疑级(软信号 · 刻意痕迹 · 矛盾):**
- 文化习惯类信号:zh locale、中文输入法/键盘、CJK 字体、中文 man、history 中文、qq/163 邮箱、国内搜索引擎、国内镜像源、调休补班日活跃等(**留子原则:软信号最多可疑,不判暴露**)
- 作息类:作息推断指向东八且与系统时区偏差 ≥1h;git 作者时区 +0800 残留而系统非东八
- 伪装矛盾类:wtmp 对当前用户不可读、rc 文件伪造 SSH_*、时区声明与使用节奏矛盾
- 出口/时区/字体以外的结构性矛盾(两端都保留上报,不用单一结论覆盖)

**信息级(上下文,不作风险判定):**
- 中资云 IDC(阿里/腾讯/华为云,含海外节点)、代理/隧道/overlay 角色、远程桌面产品、链路断点声明、虚拟化平台

**跳过:** 依赖缺失/平台不适用,逐项注明原因。

## 隐私与边界

**绝不读取:** 凭据/密钥、剪贴板、按键、窗口/终端内容、截屏、远控画面、IMEI/IMSI/ICCID、WiFi 密码、浏览器 URL 明文/查询词/书签标题/扩展内容。
**SSID/BSSID** 只本地比对、不输出;**时间统计**只取小时分桶。
**默认脱敏:** IP 前两段、邮箱用户名掩码(`--reveal` 显式关闭)。
**外联(active-probe,默认开):** 出口 IP 查询(ip-api/ipinfo/api64)与污染探测;`--offline` 全部转跳过。`--deep-geo` 会外发待查 IP 列表。

## 依赖与降级

POSIX sh + 常规 coreutils 即可运行;`curl` 或 `wget`、`awk`、`iproute2`、`systemd`、`traceroute`/`tracepath`、`fc-list`、`git`、`launchctl`(macOS)等按存在性启用对应检测,缺失即降级为跳过并注明。容器/WSL/MSYS 环境自动识别并缩减范围。

## macOS 支持

可直接使用系统 `/bin/sh`，不需要安装 GNU coreutils、Python 或提权。Python 仅用于开发回归测试。

```sh
sh dist/region-trace-audit.sh --offline   # 纯本地
sh dist/region-trace-audit.sh --json --radio # 本地 + 默认联网探测 + 本地无线状态
```

原生采集覆盖 `sw_vers`/`sysctl` 系统与硬件信息、启动时间、`route`/`ifconfig` 网络上下文、`netstat` TCP 监听端口、`scutil --dns` 动态解析器、`scutil --proxy` 的 HTTP/HTTPS/SOCKS/PAC/WPAD 开关、console 图形登录，以及现有的区域/输入源/launchd/用户字体/Homebrew 检查。仅报告代理开关，不读取 PAC 内容或输出 PAC URL。

macOS 内置的中文 locale 和系统 CJK 字体不是用户选择，不据此判可疑；`com.todesktop` 等 bundle ID 不再误匹配 ToDesk。浏览器路径支持 `Application Support`、`Microsoft Edge`、带空格的 Firefox profile。历史检测仍是文件前 30MB 的域名近似匹配计数，不代表访问次数，不输出 URL 或查询词。

进一步的原生采集包括：

- `lsof` 将 TCP socket 绑定到可见的 sshd/远控进程，支持 IPv4/IPv6；远控分别报告 installed、loaded、running、TCP-listening 和 TCP-established。覆盖 Apple Screen Sharing、RustDesk、AnyDesk、TeamViewer、ToDesk、Sunlogin、NoMachine、Chrome Remote Desktop、Parsec。活动 TCP 可能是心跳或中继，不直接认定有人正在远控；其他用户/root 进程可能不可见。
- `arp` 网关 OUI、`ifconfig` MTU、标准 Applications 目录内 bundle ID、当前用户 crontab。`.AppleSetupDone` 只作为设置助手标记时间，不冒充初次安装日期；TCP sysctl 只报告配置。
- 尝试读取 PF 根规则和 anchor，另查应用防火墙开关、Network Extension 系统扩展状态。PF 无权限时给出 `/dev/pf` 原因，不自动 sudo；Network Extension 清单不等于其内部规则，也不涵盖全部 app-extension VPN。
- IOBluetooth 只获取配对/连接计数及名称是否含非 ASCII；CoreWLAN 只在本地比对当前 SSID。`--radio` 额外读取 CoreWLAN/system_profiler 无线状态与监管域，不扫描历史网络，不输出 SSID/BSSID、蓝牙地址或序列号，不调用已弃用的 `airport`。监管域仅为弱信号，不作为实际地理位置。

Linux `/proc`、systemd、LSM/cgroup 等专属检查仍标为不适用；蜂窝基站信息未实现。macOS 定位隐私可能隐藏 SSID，即使 Wi-Fi 已连接；这时明确 SKIP，不解释为没有 Wi-Fi。脚本不主动申请定位或完整磁盘访问权限，TCC/沙箱限制仍可能缩小可读范围。`--deep-geo` 默认关闭；显式启用时可纳入 lsof 可见的 IPv4 对端，IPv6 不发送到现有 IPv4 批量查询接口。

DNS 解析器来自动态配置，包含 scoped/supplemental 记录；默认 `dig`/`nslookup` 探测不覆盖所有按域名或接口选路的应用解析路径。系统代理配置也不保证命令行 `curl` 使用相同代理，出口结果仅代表探测进程。

时间采集兼容 BSD/GNU `stat`，保留带空格/引号的采样路径，Git 时间直接使用 epoch，修复一二月日期转换、周末占比 `awk` 报错和多字节直方图乱码。文件采样仍使用有界的逐行路径列表，文件名含换行不受支持；作息推断仍是原有启发式，不等于实际位置。

### 开发验证

```sh
sh build.sh
python3 tests/test-macos.py
TEST_SHELL=/bin/dash python3 tests/test-macos.py # 本机有 dash 时
sh tests/test-json-injection.sh
sh tests/test-time-compound.sh
```

macOS 回归使用临时目录和命令夹具，覆盖启用/关闭/无权限、路径含空格、日期边界等正负例；不访问真实用户记录或联网。CI 在 macOS 和 Ubuntu 的 sh/bash 下运行。原生 macOS 26.1 Apple Silicon 已完成全量实测，JSON 可解析且 stderr 为空。

## 已知局限

- 多用户/共享服务器:会话与作息信号混合多人;作息置信度低时不作一致性判定
- GeoIP 精度与中转:出口/控制端判定受数据库与链路影响;中继后不可观察,输出链断点声明
- 作息推断:夜猫型作息会前移推断值;样本 <30 簇不判定;**东/东南亚 +7 时区(曼谷/雅加达/河内/珀斯)与 +8 在边界小时上原理性不可分** —— 单条作息仅可疑,升级需复合旁证
- 内地假日/调休表覆盖 2024–2026(国办发明电官方通知;2027 待公布)
- macOS 的 socket 归属限于可见进程；TCP 活动不是交互远控证明，PF 可能需管理员权限，SSID 受定位隐私限制，蜂窝基站信息未实现；具体采集边界见上文。
- 本工具检测「痕迹存在性」;痕迹缺失不等于无痕迹(见 C12 采集完整性旁证)

## 版本

- v0.5 —— macOS 适配层、`--json`、README
- v0.4 —— 时间行为统计(作息推断/时区一致性/内地假日与调休日历)、gui/browser/hw+--radio、usegeo 融合视图
- v0.3 —— 上下文层(boot/kernelnet/session)、WSL interop
- v0.2 —— active-probe 四类(egress/path/proxy/dns)
- v0.1 —— 框架 + 纯本地七类

## 免责声明

本工具仅为环境一致性体检,输出为概率性、启发式证据(尤其「可疑」级软信号),存在误报与漏报;判定不构成对任何个人背景的认定。使用者应自行核对证据链(每条输出附类目与理由)。在他人设备上运行前须获得授权。
