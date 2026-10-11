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

VERSION="0.7"
