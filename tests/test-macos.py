#!/usr/bin/env python3
"""Offline fixtures for Darwin adapters; stdlib only, no real user data/network."""
import datetime
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = os.environ.get('TEST_SHELL', '/bin/sh')


class MacOSAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='rta-macos-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home with spaces and 'quotes'"
        self.home.mkdir()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), PATH=f'{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL='C', TZ='UTC')
        for key in ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'LANG', 'http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
            self.env.pop(key, None)
        for name in ('last', 'loginctl', 'brew', 'dnf', 'git', 'crontab', 'pfctl', 'systemextensionsctl', 'osascript', 'system_profiler', 'arp'):
            self.mock(name, 'exit 1')
        for name in ('curl', 'wget', 'dig', 'nslookup'):
            self.mock(name, 'echo "unexpected network call" >&2; exit 99')
        self.mock('lsof', "printf 'p123\\ncEditor\\nf9\\nTST=LISTEN\\nn127.0.0.1:7890\\n'")
        self.mock('uname', 'echo Darwin')
        self.mock('who', 'echo "fixture console Oct 11 10:00"')
        self.mock('ps', 'echo /sbin/launchd')
        self.mock('sw_vers', 'case "$1" in -productName) echo macOS ;; *) echo 26.1 ;; esac')
        self.mock('scutil', '''case "$1" in
--proxy) cat <<EOF
<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
  HTTPPort : 7890
  HTTPSEnable : 1
  SOCKSEnable : 1
  ProxyAutoConfigEnable : 1
  ProxyAutoDiscoveryEnable : 1
}
EOF
;;
--dns) cat <<EOF
DNS configuration
resolver #1
  nameserver[0] : 192.168.1.1
resolver #2
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
EOF
;;
*) echo '  Name : fixture' ;;
esac''')
        self.mock('defaults', '''case "$*" in
'-g AppleLocale'| 'read -g AppleLocale') echo en_AU ;;
'read -g AppleLanguages') printf '(\\n    en-AU,\\n    "zh-Hans-AU"\\n)\\n' ;;
'read com.apple.HIToolbox AppleCurrentKeyboardLayoutInputSourceID') echo com.apple.keylayout.US ;;
*) exit 1 ;;
esac''')
        self.mock('launchctl', "printf 'PID Status Label\\n- 0 com.todesktop.editor\\n- 0 com.apple.parsecd\\n' ")
        self.mock('sysctl', '''case "$*" in
'-n kern.boottime') echo '{ sec = 1700000000, usec = 987654 }' ;;
'-n hw.model') echo MacFixture ;;
'-n machdep.cpu.brand_string') echo 'Apple Fixture' ;;
'-n net.inet.ip.forwarding') echo 0 ;;
*) exit 1 ;;
esac''')
        self.mock('networksetup', "printf 'Hardware Port: Wi-Fi\\nDevice: en0\\nEthernet Address: hidden\\n'")
        self.mock('route', "printf ' gateway: 192.168.1.1\\n interface: utun4\\n'")
        self.mock('ifconfig', '''case "$1" in -l) echo 'lo0 en0 utun4' ;; *) echo ' inet 192.168.1.2 netmask 0xffffff00' ;; esac''')
        self.mock('netstat', "printf 'tcp4 0 0 127.0.0.1.7890 *.* LISTEN\\ntcp6 0 0 ::1.7890 *.* LISTEN\\n'")

    def mock(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/sh\n' + body + '\n')
        p.chmod(0o755)

    def run_checks(self, body, json_mode=True):
        setup = 'BRIEF=0; NOCOLOR=1; REVEAL=0; OFFLINE=1; DEEP_GEO=0; RADIO=0; JSON=%d; VERSION=test\n' % json_mode
        # Definitions only; avoid main and CLI argument parser.
        for p in sorted((ROOT / 'src').glob('*.sh')):
            if 20 <= int(p.name[:2]) < 90:
                setup += '. ' + shlex.quote(str(p)) + '\n'
        setup += 'PLATFORM=macos; CUR_USER=fixture; CUR_UID=501; PS_SNAP="fixture 123 0 /Applications/Editor.app/Contents/MacOS/Editor"; HTTP_TOOL=""\n'
        setup += 'mac_app_inventory() { printf "Editor.app|com.todesktop.editor\\n"; }; mac_application_firewall_state() { echo "Firewall is disabled. (State = 0)"; }\n'
        script = setup + body
        if json_mode:
            script += '\nEXIT_CODE=0; json_emit\n'
        out = subprocess.run([SHELL, '-c', script], env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr + out.stdout)
        self.assertEqual(out.stderr, '', out.stderr)
        return json.loads(out.stdout)['items'] if json_mode else out.stdout

    def item(self, items, name):
        return [i for i in items if i['item'] == name]

    def test_proxy_indentation_and_bundle_boundaries(self):
        items = self.run_checks('check_mac')
        proxies = self.item(items, 'macos/proxy')
        self.assertEqual(len(proxies), 5)
        self.assertTrue(all(i['level'] == 'INFO' for i in proxies))
        self.assertFalse(self.item(items, 'macos/cn-daemon'))
        self.assertIn('en-AU', self.item(items, 'macos/lang-first')[0]['message'])
        self.mock('launchctl', "printf 'PID Status Label\\n- 0 com.tencent.xinWeChat\\n- 0 com.todesktop.editor\\n- 0 com.apple.parsecd\\n'")
        hit = self.item(self.run_checks('check_mac'), 'macos/cn-daemon')[0]
        self.assertEqual(hit['level'], 'SUSPICIOUS')
        self.assertNotIn('todesktop', hit['message'])

    def test_disabled_and_unavailable_proxy(self):
        self.mock('scutil', "printf '<dictionary> {\\n HTTPEnable : 0\\n}\\n'")
        self.assertEqual(self.item(self.run_checks('check_mac'), 'macos/proxy')[0]['level'], 'CLEAN')
        self.mock('scutil', 'exit 1')
        self.assertEqual(self.item(self.run_checks('check_mac'), 'macos/proxy')[0]['level'], 'SKIP')

    def test_native_desktop_hardware_boot_and_network(self):
        items = self.run_checks('net_context; check_c1; check_c16; check_c17; check_c19; check_c13; check_c14')
        self.assertIn('macOS', self.item(items, 'sysinfo/os')[0]['message'])
        self.assertNotIn('[sshd]', self.item(items, 'sysinfo/collector')[0]['message'])
        self.assertNotIn('[mux]', self.item(items, 'sysinfo/collector')[0]['message'])
        self.assertIn('launchd', self.item(items, 'boot/pid1')[0]['message'])
        self.assertIn('utun4', self.item(items, 'kernel/routes')[0]['message'])
        self.assertEqual(self.item(items, 'gui/session')[0]['level'], 'INFO')
        self.assertEqual(self.item(items, 'gui/rd')[0]['level'], 'INFO')
        self.assertIn('en0', self.item(items, 'hw/wireless')[0]['message'])
        self.assertIn('1 个端口', self.item(items, 'services/listen-ports')[0]['message'])
        self.assertIn('7890', self.item(items, 'services/proxy-ports')[0]['message'])
        self.assertNotIn('hidden', json.dumps(items))

    def test_permission_failures_are_not_clean(self):
        for name in ('scutil', 'sysctl', 'networksetup', 'netstat'):
            self.mock(name, 'exit 1')
        items = self.run_checks('check_c1; check_c13; check_c14; check_c19')
        for key in ('sysinfo/uptime', 'hw/model', 'hw/cpu', 'hw/wireless', 'services/listen-ports', 'gui/session'):
            self.assertEqual(self.item(items, key)[0]['level'], 'SKIP', key)

    def test_dns_dynamic_store_deduplicates_and_stays_offline(self):
        items = self.run_checks('HTTP_TOOL=curl; check_c6')
        dns = self.item(items, 'dns/resolvers')[0]['message']
        self.assertIn('scutil --dns', dns)
        self.assertEqual(dns.count('192.168.x.x'), 1)
        self.assertEqual(self.item(items, 'dns/pollution')[0]['level'], 'SKIP')
        self.assertIn('私网', self.item(items, 'dns/resolver-geo')[0]['message'])

    def test_bundled_locales_do_not_mean_selected_language(self):
        self.mock('locale', "printf 'en_AU.UTF-8\\nzh_CN.UTF-8\\n'")
        items = self.run_checks('check_c8')
        self.assertEqual(self.item(items, 'locale/localedef')[0]['level'], 'INFO')

    def test_who_fallback_keeps_local_and_remote_counts(self):
        self.mock('who', "printf 'fixture console Oct 11 10:00\\nremote ttys001 Oct 11 10:00 (203.0.113.7)\\n'")
        items = self.run_checks('check_c18; report INFO fixture/count "$SESS_LOCAL_N|$SESS_N|$SESS_REMOTES"')
        self.assertIn('1|2| 203.0.113.7', self.item(items, 'fixture/count')[0]['message'])
        self.assertEqual(self.item(items, 'session/ssh-peers')[0]['level'], 'INFO')

    def test_socket_fields_keep_multiple_fds_and_ipv6(self):
        self.mock('lsof', """cat <<'EOF'
p100
csshd
f3
n192.168.1.2:22->203.0.113.7:4000
TST=ESTABLISHED
f4
TST=LISTEN
n*:22
p200
cAnyDesk
f5
n[2001:db8::1]:5500->[2001:db8::2]:443
TST=ESTABLISHED
EOF""")
        items = self.run_checks('mac_socket_context; report INFO fixture/sockets "$MAC_SOCKETS"; report INFO fixture/ip "$(mac_endpoint_ip "[2001:db8::2]:443")"; check_c18; report INFO fixture/logins "$SESS_REMOTES"; check_c20; report INFO fixture/view "$USEGEO_VIEW"')
        rows = self.item(items, 'fixture/sockets')[0]['message'].splitlines()
        self.assertEqual(rows, ['100|sshd|ESTABLISHED|192.168.1.2:22|203.0.113.7:4000', '100|sshd|LISTEN|*:22|', '200|AnyDesk|ESTABLISHED|[2001:db8::1]:5500|[2001:db8::2]:443'])
        self.assertEqual(self.item(items, 'fixture/ip')[0]['message'], '2001:db8::2')
        ssh = self.item(items, 'session/ssh-peers')[0]
        self.assertEqual(ssh['level'], 'INFO')
        self.assertIn('1 个', ssh['message'])
        self.assertNotIn('203.0.113.7', ssh['message'])
        self.assertEqual(self.item(items, 'fixture/logins')[0]['message'], '')
        self.assertIn('不计入交互登录数量', self.item(items, 'fixture/view')[0]['message'])

    def test_unreadable_sockets_do_not_prove_absence(self):
        self.mock('lsof', 'exit 1')
        items = self.run_checks('check_c18; mac_check_remote_desktop')
        for key in ('session/ssh-peers', 'gui/rd'):
            self.assertEqual(self.item(items, key)[0]['level'], 'SKIP')

    def test_remote_desktop_states_are_separate_from_control(self):
        self.mock('ps', "printf ' 200 /Applications/AnyDesk.app/Contents/MacOS/AnyDesk\\n 300 screensharingd\\n'")
        self.mock('lsof', "printf 'p200\\ncAnyDesk\\nf4\\nn192.168.1.2:5000->203.0.113.8:443\\nTST=ESTABLISHED\\np300\\ncscreensharingd\\nf5\\nn*:5900\\nTST=LISTEN\\n'")
        items = self.run_checks('mac_app_inventory() { printf "AnyDesk.app|com.philandro.anydesk\\nEditor.app|com.todesktop.editor\\n"; }; mac_check_remote_desktop; report INFO fixture/control "$RD_CONNECTED"')
        rd = self.item(items, 'gui/rd')
        self.assertEqual(len(rd), 2)
        anydesk = next(i for i in rd if 'AnyDesk:' in i['message'])
        self.assertIn('installed=1 loaded=0 running=1 TCP-listening=0 TCP-established=1', anydesk['message'])
        apple = next(i for i in rd if 'Apple Screen Sharing:' in i['message'])
        self.assertIn('running=1 TCP-listening=1 TCP-established=0', apple['message'])
        self.assertTrue(all(i['level'] == 'INFO' for i in rd))
        self.assertNotEqual(self.item(items, 'fixture/control')[0]['message'], '1')
        self.assertNotIn('ToDesk:', json.dumps(items))
        self.assertNotIn('Parsec:', json.dumps(items))

    def test_firewall_permission_and_native_rules(self):
        self.mock('pfctl', 'echo "pfctl: /dev/pf: Permission denied" >&2; exit 1')
        denied = self.run_checks('mac_check_firewall')
        self.assertIn('/dev/pf', self.item(denied, 'proxy/pf')[0]['message'])
        self.assertEqual(self.item(denied, 'proxy/pf')[0]['level'], 'SKIP')
        self.assertFalse(self.item(denied, 'proxy/pf-rules'))
        self.mock('pfctl', '''case "$*" in
'-s info') echo 'Status: Enabled for 10 days' ;;
'-s nat') echo 'rdr on en0 hidden-rule-data' ;;
'-a * -s rules') echo 'pass label "chnroute hidden-rule-data"' ;;
*) : ;;
esac''')
        self.mock('systemextensionsctl', "printf '1 extension(s)\\n--- com.apple.system_extension.network_extension\\n* * TEAM com.example.filter [activated enabled]\\n'")
        items = self.run_checks('mac_check_firewall')
        self.assertIn('1 条', self.item(items, 'proxy/pf-rules')[0]['message'])
        self.assertEqual(self.item(items, 'proxy/chnroute')[0]['level'], 'SUSPICIOUS')
        self.assertIn('1 个', self.item(items, 'proxy/network-extension')[0]['message'])
        self.assertNotIn('hidden-rule-data', json.dumps(items))

    def test_app_bundle_ids_and_unreadable_inventory(self):
        items = self.run_checks('mac_app_inventory() { printf "WeChat.app|com.tencent.xinWeChat\\nEditor.app|com.todesktop.editor\\n"; }; mac_check_apps')
        hit = self.item(items, 'mirror/cn-apps')[0]
        self.assertEqual(hit['level'], 'SUSPICIOUS')
        self.assertIn('1 个', hit['message'])
        self.assertNotIn('todesktop', hit['message'])
        items = self.run_checks('mac_app_inventory() { echo "Unreadable.app|"; }; mac_check_apps')
        self.assertEqual(self.item(items, 'mirror/cn-apps')[0]['level'], 'SKIP')

    def test_bluetooth_and_wifi_privacy_restriction(self):
        items = self.run_checks('mac_bluetooth_summary() { echo "3|1|2"; }; mac_corewlan_summary() { echo "en0|1|1|unknown|0|0"; }; mac_check_devices')
        self.assertIn('3 个/连接中 1 个', self.item(items, 'fs/bluetooth-state')[0]['message'])
        self.assertEqual(self.item(items, 'fs/bluetooth')[0]['level'], 'SUSPICIOUS')
        self.assertEqual(self.item(items, 'fs/wifi-ssid')[0]['level'], 'SKIP')
        self.assertIn('定位隐私', self.item(items, 'fs/wifi-ssid')[0]['message'])
        items = self.run_checks('mac_bluetooth_summary() { echo "0|0|0"; }; mac_corewlan_summary() { echo "en0|1|1|AU|1|0"; }; mac_check_devices')
        self.assertEqual(self.item(items, 'fs/bluetooth')[0]['level'], 'CLEAN')
        self.assertEqual(self.item(items, 'fs/wifi-ssid')[0]['level'], 'CLEAN')

    def test_radio_opt_in_and_regulatory_country_is_weak_evidence(self):
        body = 'mac_corewlan_summary() { echo "en0|1|1|unknown|0|0"; }; mac_airport_summary() { echo "en0|CN|1"; }; '
        off = self.run_checks(body + 'check_c13')
        self.assertFalse(self.item(off, 'hw/reg-domain'))
        on = self.run_checks(body + 'RADIO=1; check_c13; report INFO fixture/cc "$RADIO_ACCESS_CC"')
        self.assertEqual(self.item(on, 'hw/reg-domain')[0]['level'], 'SUSPICIOUS')
        self.assertNotEqual(self.item(on, 'fixture/cc')[0]['message'], 'CN')

    @unittest.skipUnless(sys.platform == 'darwin', 'JXA parser requires macOS')
    def test_real_jxa_reads_profiler_pipe_without_identifiers(self):
        self.mock('osascript', 'exec /usr/bin/osascript "$@"')
        self.mock('system_profiler', '''cat <<'EOF'
{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0","spairport_wireless_country_code":"AU","spairport_current_network_information":{"_name":"private-network","bssid":"private-address"}},{"_name":"awdl0"}]}]}
EOF''')
        items = self.run_checks('report INFO fixture/airport "$(mac_airport_summary)"')
        self.assertEqual(self.item(items, 'fixture/airport')[0]['message'], 'en0|AU|1\nawdl0|unknown|0')
        self.mock('system_profiler', 'exit 1')
        items = self.run_checks('if mac_airport_summary; then report INFO fixture/result success; else report INFO fixture/result failed; fi')
        self.assertEqual(self.item(items, 'fixture/result')[0]['message'], 'failed')

    def test_arp_oui_and_mtu_with_bsd_output(self):
        self.mock('arp', "echo '? (192.168.1.1) at a:b:c:1:2:3 on en0 ifscope [ethernet]'")
        self.mock('ifconfig', "echo 'en0: flags=8863 mtu 1492'")
        items = self.run_checks('ROUTE_GW=192.168.1.1; ROUTE_IFACE=en0; GW_OUI_CN_LIST="0A:0B:0C"; check_c4')
        self.assertEqual(self.item(items, 'path/gw-oui')[0]['level'], 'SUSPICIOUS')
        self.assertIn('0A:0B:0C', self.item(items, 'path/gw-oui')[0]['message'])
        self.assertIn('MTU=1492', self.item(items, 'path/mtu')[0]['message'])

    def test_crontab_absence_is_distinct_from_denied(self):
        self.mock('crontab', 'echo "crontab: no crontab for fixture" >&2; exit 1')
        self.assertEqual(self.item(self.run_checks('check_c14'), 'services/cron')[0]['level'], 'INFO')
        self.mock('crontab', 'echo "permission denied" >&2; exit 1')
        self.assertEqual(self.item(self.run_checks('check_c14'), 'services/cron')[0]['level'], 'SKIP')
        self.mock('crontab', "echo '0 8 * * * /usr/bin/true'")
        self.assertEqual(self.item(self.run_checks('check_c14'), 'services/cron')[0]['level'], 'CLEAN')

    def test_deep_geo_uses_only_opted_in_public_ipv4_sockets(self):
        self.mock('lsof', "printf 'p100\\ncsshd\\nf3\\nn192.168.1.2:22->203.0.113.7:4000\\nTST=ESTABLISHED\\nf4\\nn192.168.1.2:22->192.168.1.3:4000\\nTST=ESTABLISHED\\nf5\\nn[2001:db8::1]:22->[2001:db8::2]:4000\\nTST=ESTABLISHED\\n'")
        items = self.run_checks('DEEP_GEO=1; HTTP_TOOL=curl; check_c3')
        self.assertEqual(self.item(items, 'egress/all')[0]['level'], 'SKIP')
        items = self.run_checks('''http_post() {
          [ "$2" = '["203.0.113.7"]' ] || { echo "unexpected batch: $2" >&2; return 1; }
          printf '[{"status":"success","countryCode":"AU"}]'
        }; deep_geo_scan''')
        self.assertEqual(self.item(items, 'egress/deep-geo')[0]['level'], 'CLEAN')
        self.assertIn('1 个', self.item(items, 'egress/deep-geo')[0]['message'])

    def test_edge_and_firefox_profiles_with_spaces(self):
        base = self.home / 'Library/Application Support'
        edge = base / 'Microsoft Edge/Default'
        edge.mkdir(parents=True)
        (edge / 'Preferences').write_text('{"application_locale":"zh-CN"}')
        (edge / 'History').write_text('https://www.baidu.com/private-query\n' * 12)
        ff = base / "Firefox/Profiles/person's profile"
        ff.mkdir(parents=True)
        (ff.parent.parent / 'profiles.ini').write_text("Path=Profiles/person's profile\n")
        (ff / 'places.sqlite').write_text('https://qq.com/private\n')
        items = self.run_checks('check_c15')
        self.assertIn('存在用户 profile', self.item(items, 'browser/edge')[0]['message'])
        self.assertEqual(self.item(items, 'browser/Microsoft Edge-lang')[0]['level'], 'SUSPICIOUS')
        self.assertIn('12 次', self.item(items, 'browser/Microsoft Edge-history')[0]['message'])
        self.assertIn('1 次', self.item(items, 'browser/firefox-history')[0]['message'])
        self.assertNotIn('private-query', json.dumps(items))

    def test_bsd_or_gnu_file_mtime_with_quotes(self):
        doc = self.home / "Documents/a 'quoted' file.txt"
        doc.parent.mkdir()
        doc.write_text('fixture')
        os.utime(doc, (1700000000, 1700000000))
        items = self.run_checks('report INFO fixture/mtime "$(find "$HOME/Documents" -type f | file_mtimes)"')
        self.assertEqual(self.item(items, 'fixture/mtime')[0]['message'], '1700000000')

    def test_january_february_timestamps_and_json_whitespace(self):
        path = self.home / ".claude/projects/project with spaces/session's file.jsonl"
        path.parent.mkdir(parents=True)
        dates = ['2026-01-15T12:30:00', '2024-02-29T12:30:00', '2026-09-15T12:30:00']
        path.write_text('\n'.join(json.dumps({'role': 'user', 'timestamp': t + 'Z'}) for t in dates))
        items = self.run_checks('check_c11; report INFO fixture/epochs "$_e3"')
        expected = '\n'.join(str(int(datetime.datetime.fromisoformat(t).replace(tzinfo=datetime.timezone.utc).timestamp())) for t in dates)
        self.assertEqual(self.item(items, 'fixture/epochs')[0]['message'], expected)

    def test_time_histogram_and_weekend_percentage(self):
        path = self.home / '.claude/projects/fixture/session.jsonl'
        path.parent.mkdir(parents=True)
        path.write_text('\n'.join(json.dumps({'role': 'user', 'timestamp': f'2026-09-{d:02}T{h:02}:30:00Z'}) for d in range(1, 21) for h in range(2, 17, 2)))
        text = self.run_checks('TZ_NAME=Asia/Tokyo; TZ_CLASS=OTHER; check_c11; :', json_mode=False)
        self.assertRegex(text, r'周末占比 [0-9]+%')
        self.assertNotIn('\ufffd', text)
        self.assertIn('AI用户输入=160', text)

    def test_git_uses_epoch_and_preserves_negative_author_offset(self):
        (self.home / 'repo with spaces/.git').mkdir(parents=True)
        self.mock('git', '''case "$*" in
*--pretty=*) echo '1768509000 2026-01-15 09:30:00 -0800' ;;
*) exit 1 ;;
esac''')
        items = self.run_checks('check_c11; report INFO fixture/git "$_e7|$_tz7"')
        msg = self.item(items, 'fixture/git')[0]['message']
        self.assertIn('1768509000|', msg)
        self.assertIn('-0800', msg)


if __name__ == '__main__':
    unittest.main(verbosity=2)
