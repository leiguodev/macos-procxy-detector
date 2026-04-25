#!/usr/bin/env python3
"""
macOS 代理检测工具
检测系统代理、TUN模式、各应用代理状态
"""

import subprocess
import json
import re
import argparse
import time
import shutil
import sys
import select
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from pathlib import Path

try:
    from wcwidth import wcswidth as display_width
except ImportError:
    def display_width(s: str) -> int:
        width = 0
        for c in s:
            code = ord(c)
            if code == 0:
                continue
            if 0x1100 <= code <= 0x115F:
                width += 2
            elif 0x2329 <= code <= 0x232A:
                width += 2
            elif 0x2E80 <= code <= 0x303E:
                width += 2
            elif 0x3040 <= code <= 0xA4CF:
                width += 2
            elif 0xAC00 <= code <= 0xD7A3:
                width += 2
            elif 0xF900 <= code <= 0xFAFF:
                width += 2
            elif 0xFE10 <= code <= 0xFE19:
                width += 2
            elif 0xFE30 <= code <= 0xFE6F:
                width += 2
            elif 0xFF00 <= code <= 0xFF60:
                width += 2
            elif 0xFFE0 <= code <= 0xFFE6:
                width += 2
            elif 0x20000 <= code <= 0x2FFFD:
                width += 2
            elif 0x30000 <= code <= 0x3FFFD:
                width += 2
            elif 0x4E00 <= code <= 0x9FFF:
                width += 2
            else:
                width += 1
        return width

def pad_right(s: str, width: int) -> str:
    actual = display_width(s)
    if actual >= width:
        return s
    return s + ' ' * (width - actual)


@dataclass
class SystemProxy:
    http_enabled: bool = False
    http_host: Optional[str] = None
    http_port: Optional[int] = None
    https_enabled: bool = False
    https_host: Optional[str] = None
    https_port: Optional[int] = None
    socks_enabled: bool = False
    socks_host: Optional[str] = None
    socks_port: Optional[int] = None
    pac_enabled: bool = False
    pac_url: Optional[str] = None
    exceptions: List[str] = field(default_factory=list)


@dataclass
class TunStatus:
    enabled: bool = False
    interface: Optional[str] = None
    ip_address: Optional[str] = None
    is_default_route: bool = False
    tun_type: str = "unknown"  # "clash", "tailscale", "other"


def is_tailscale_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    first = int(parts[0])
    second = int(parts[1])
    if first == 100 and 64 <= second <= 127:
        return True
    if first == 100 and 0 <= second <= 63:
        return True
    return False


def is_clash_tun_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    first = int(parts[0])
    second = int(parts[1])
    if first == 198 and 18 <= second <= 19:
        return True
    if first == 172 and second == 19:
        return True
    if first == 172 and second == 17:
        return True
    return False


@dataclass
class ClashStatus:
    running: bool = False
    pid: Optional[int] = None
    port: Optional[int] = None
    port_listening: bool = False
    mode: Optional[str] = None


@dataclass
class AppProxyStatus:
    name: str
    running: bool = False
    proxy_source: str = "none"
    custom_proxy: Optional[str] = None
    current_proxy: Optional[str] = None
    exit_ip: Optional[str] = None
    exit_location: Optional[str] = None


@dataclass
class ExitInfo:
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    success: bool = False


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def run_command(cmd: List[str], timeout: int = 10) -> tuple:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


class ProxyDetector:
    def __init__(self):
        self.system_proxy: Optional[SystemProxy] = None
        self.tun_status: Optional[TunStatus] = None
        self.clash_status: Optional[ClashStatus] = None
        self.app_status: Dict[str, AppProxyStatus] = {}
        self.proxy_exit: Optional[ExitInfo] = None
        self.direct_exit: Optional[ExitInfo] = None
        self.conclusion: str = ""

    def run_all_checks(self):
        self.system_proxy = self.detect_system_proxy()
        self.tun_status = self.detect_tun_mode()
        self.clash_status = self.detect_clash_process()
        
        self.app_status["Safari"] = self.detect_safari_proxy()
        self.app_status["Chrome"] = self.detect_chrome_proxy()
        self.app_status["VS Code"] = self.detect_vscode_proxy()
        
        self.proxy_exit = self.get_exit_ip(use_proxy=True)
        self.direct_exit = self.get_exit_ip(use_proxy=False)
        
        self.conclusion = self.determine_conclusion()

    def detect_system_proxy(self) -> SystemProxy:
        rc, stdout, _ = run_command(["scutil", "--proxy"])
        if rc != 0:
            return SystemProxy()
        
        proxy = SystemProxy()
        
        http_enable = re.search(r"HTTPEnable\s*:\s*(\d+)", stdout)
        http_proxy = re.search(r"HTTPProxy\s*:\s*([^\n]+)", stdout)
        http_port = re.search(r"HTTPPort\s*:\s*(\d+)", stdout)
        
        if http_enable and http_enable.group(1) == "1":
            proxy.http_enabled = True
            proxy.http_host = http_proxy.group(1).strip() if http_proxy else None
            proxy.http_port = int(http_port.group(1)) if http_port else None
        
        https_enable = re.search(r"HTTPSEnable\s*:\s*(\d+)", stdout)
        https_proxy = re.search(r"HTTPSProxy\s*:\s*([^\n]+)", stdout)
        https_port = re.search(r"HTTPSPort\s*:\s*(\d+)", stdout)
        
        if https_enable and https_enable.group(1) == "1":
            proxy.https_enabled = True
            proxy.https_host = https_proxy.group(1).strip() if https_proxy else None
            proxy.https_port = int(https_port.group(1)) if https_port else None
        
        socks_enable = re.search(r"SOCKSEnable\s*:\s*(\d+)", stdout)
        socks_proxy = re.search(r"SOCKSProxy\s*:\s*([^\n]+)", stdout)
        socks_port = re.search(r"SOCKSPort\s*:\s*(\d+)", stdout)
        
        if socks_enable and socks_enable.group(1) == "1":
            proxy.socks_enabled = True
            proxy.socks_host = socks_proxy.group(1).strip() if socks_proxy else None
            proxy.socks_port = int(socks_port.group(1)) if socks_port else None
        
        pac_enable = re.search(r"ProxyAutoConfigEnable\s*:\s*(\d+)", stdout)
        pac_url = re.search(r"ProxyAutoConfigURLString\s*:\s*([^\n]+)", stdout)
        
        if pac_enable and pac_enable.group(1) == "1":
            proxy.pac_enabled = True
            proxy.pac_url = pac_url.group(1).strip() if pac_url else None
        
        exceptions_match = re.search(r"ExceptionsList\s*:\s*<array>\s*\{([^}]+)\}", stdout, re.DOTALL)
        if exceptions_match:
            exceptions = re.findall(r"\d+\s*:\s*([^\n]+)", exceptions_match.group(1))
            proxy.exceptions = [e.strip() for e in exceptions]
        
        return proxy

    def detect_tun_mode(self) -> TunStatus:
        tun = TunStatus()
        
        rc, stdout, _ = run_command(["ifconfig"])
        if rc != 0:
            return tun
        
        clash_tun_interfaces = []
        current_iface = None
        current_block = []
        
        for line in stdout.split("\n"):
            iface_match = re.match(r"^(utun\d+):", line)
            if iface_match:
                if current_iface and current_block:
                    block_text = "\n".join(current_block)
                    inet_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", block_text)
                    if inet_match:
                        ip = inet_match.group(1)
                        if is_clash_tun_ip(ip):
                            clash_tun_interfaces.append((current_iface, ip))
                current_iface = iface_match.group(1)
                current_block = [line]
            elif current_iface:
                current_block.append(line)
        
        if current_iface and current_block:
            block_text = "\n".join(current_block)
            inet_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", block_text)
            if inet_match:
                ip = inet_match.group(1)
                if is_clash_tun_ip(ip):
                    clash_tun_interfaces.append((current_iface, ip))
        
        if clash_tun_interfaces:
            tun.interface = clash_tun_interfaces[0][0]
            tun.ip_address = clash_tun_interfaces[0][1]
            tun.tun_type = "clash"
            tun.enabled = True
        
        rc, stdout, _ = run_command(["netstat", "-rn"])
        if rc == 0:
            for line in stdout.split("\n"):
                if line.startswith("default"):
                    for iface, ip in clash_tun_interfaces:
                        if iface in line and ("UGS" in line or "UCSIg" in line or "g" in line.split(iface)[0][-5:]):
                            tun.is_default_route = True
                            tun.interface = iface
                            tun.ip_address = ip
                            return tun
        
        return tun

    def detect_clash_process(self) -> ClashStatus:
        clash = ClashStatus()
        
        rc, stdout, _ = run_command(["ps", "aux"])
        if rc != 0:
            return clash
        
        for line in stdout.split("\n"):
            if "clash-verge" in line.lower() or "mihomo" in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        clash.running = True
                        clash.pid = int(parts[1])
                        break
                    except ValueError:
                        continue
        
        if self.system_proxy and self.system_proxy.http_port:
            port = self.system_proxy.http_port
            rc, stdout, _ = run_command(["lsof", "-i", f":{port}"])
            if rc == 0 and stdout:
                for line in stdout.split("\n"):
                    if "LISTEN" in line:
                        clash.port = port
                        clash.port_listening = True
                        break
                if not clash.port_listening and stdout.strip():
                    clash.port = port
                    clash.port_listening = True
        
        return clash

    def detect_safari_proxy(self) -> AppProxyStatus:
        app = AppProxyStatus(name="Safari")
        
        rc, stdout, _ = run_command(["pgrep", "-x", "Safari"])
        app.running = rc == 0 and bool(stdout.strip())
        
        app.proxy_source = "system"
        if self.system_proxy:
            if self.system_proxy.http_enabled:
                app.current_proxy = f"{self.system_proxy.http_host}:{self.system_proxy.http_port}"
            elif self.system_proxy.pac_enabled:
                app.current_proxy = f"PAC: {self.system_proxy.pac_url}"
        
        return app

    def detect_chrome_proxy(self) -> AppProxyStatus:
        app = AppProxyStatus(name="Chrome")
        
        rc, stdout, _ = run_command(["pgrep", "-x", "Google Chrome"])
        app.running = rc == 0 and bool(stdout.strip())
        
        if app.running:
            rc, stdout, _ = run_command(["ps", "-p", stdout.strip(), "-o", "command="])
            if rc == 0 and "--proxy-server" in stdout:
                proxy_match = re.search(r"--proxy-server[=\s]+([^\s]+)", stdout)
                if proxy_match:
                    app.proxy_source = "custom"
                    app.custom_proxy = proxy_match.group(1)
                    app.current_proxy = app.custom_proxy
        
        if not app.current_proxy:
            chrome_prefs = Path.home() / "Library/Application Support/Google/Chrome/Default/Preferences"
            if chrome_prefs.exists():
                try:
                    with open(chrome_prefs, "r") as f:
                        prefs = json.load(f)
                        proxy_config = prefs.get("proxy", {})
                        if proxy_config.get("mode") == "fixed_servers":
                            app.proxy_source = "custom"
                            app.custom_proxy = proxy_config.get("server", "")
                            app.current_proxy = app.custom_proxy
                except:
                    pass
        
        if not app.current_proxy:
            app.proxy_source = "system"
            if self.system_proxy:
                if self.system_proxy.http_enabled:
                    app.current_proxy = f"{self.system_proxy.http_host}:{self.system_proxy.http_port}"
                elif self.system_proxy.pac_enabled:
                    app.current_proxy = f"PAC: {self.system_proxy.pac_url}"
        
        return app

    def detect_vscode_proxy(self) -> AppProxyStatus:
        app = AppProxyStatus(name="VS Code")
        
        rc, stdout, _ = run_command(["pgrep", "-x", "Code"])
        app.running = rc == 0 and bool(stdout.strip())
        
        vscode_settings = Path.home() / "Library/Application Support/Code/User/settings.json"
        if vscode_settings.exists():
            try:
                with open(vscode_settings, "r") as f:
                    settings = json.load(f)
                    http_proxy = settings.get("http.proxy")
                    if http_proxy:
                        app.proxy_source = "custom"
                        app.custom_proxy = http_proxy
                        app.current_proxy = http_proxy
            except:
                pass
        
        if not app.current_proxy:
            app.proxy_source = "system"
            if self.system_proxy:
                if self.system_proxy.http_enabled:
                    app.current_proxy = f"{self.system_proxy.http_host}:{self.system_proxy.http_port}"
                elif self.system_proxy.pac_enabled:
                    app.current_proxy = f"PAC: {self.system_proxy.pac_url}"
        
        return app

    def get_exit_ip(self, use_proxy: bool = True) -> ExitInfo:
        info = ExitInfo()
        
        curl_path = shutil.which("curl")
        if not curl_path:
            return info
        
        cmd = [curl_path, "-s", "--max-time", "5"]
        if not use_proxy:
            cmd.extend(["--noproxy", "*"])
        cmd.append("http://ip-api.com/json")
        
        rc, stdout, _ = run_command(cmd, timeout=10)
        if rc != 0 or not stdout:
            return info
        
        try:
            data = json.loads(stdout)
            if data.get("status") == "success":
                info.success = True
                info.ip = data.get("query")
                info.country = data.get("country")
                info.city = data.get("city")
                info.isp = data.get("isp")
        except:
            pass
        
        return info

    def determine_conclusion(self) -> str:
        if self.tun_status and self.tun_status.enabled and self.tun_status.is_default_route:
            return "Clash TUN模式生效，所有流量通过虚拟网卡接管"
        
        if self.proxy_exit and self.direct_exit:
            if self.proxy_exit.success and self.direct_exit.success:
                if self.proxy_exit.ip == self.direct_exit.ip:
                    if self.tun_status and self.tun_status.enabled:
                        return "Clash TUN模式生效，流量在更底层被接管"
                    else:
                        if self.system_proxy and self.system_proxy.http_enabled:
                            return "系统代理生效，但出口IP相同（可能是代理节点与直连出口相同）"
                        return "代理可能未生效，出口IP相同"
        
        if self.system_proxy:
            if self.system_proxy.http_enabled:
                proxy_addr = f"{self.system_proxy.http_host}:{self.system_proxy.http_port}"
                if self.clash_status and self.clash_status.running:
                    return f"系统代理生效: Clash Verge ({proxy_addr})"
                return f"系统代理生效: {proxy_addr}"
            elif self.system_proxy.pac_enabled:
                return f"PAC代理生效: {self.system_proxy.pac_url}"
        
        return "无代理，直连"

    def generate_report(self) -> str:
        lines = []
        
        width = 70
        border = "═" * width
        top = f"╔{border}╗"
        bottom = f"╚{border}╝"
        sep = f"╠{border}╣"
        
        def row(text: str) -> str:
            clean_text = re.sub(r'\033\[[0-9;]+m', '', text)
            padding = width - 2 - display_width(clean_text)
            return f"║ {text}{' ' * max(0, padding)} ║"
        
        lines.append(top)
        lines.append(row(colorize("macOS 代理状态检测报告", Colors.BOLD + Colors.CYAN)))
        lines.append(sep)
        
        lines.append(row("[系统代理设置]"))
        if self.system_proxy:
            if self.system_proxy.http_enabled:
                status = colorize("✓ 已启用", Colors.GREEN)
                lines.append(row(f"  HTTP 代理:  {self.system_proxy.http_host}:{self.system_proxy.http_port} {status}"))
            else:
                lines.append(row(f"  HTTP 代理:  {colorize('✗ 未启用', Colors.RED)}"))
            
            if self.system_proxy.https_enabled:
                status = colorize("✓ 已启用", Colors.GREEN)
                lines.append(row(f"  HTTPS 代理: {self.system_proxy.https_host}:{self.system_proxy.https_port} {status}"))
            else:
                lines.append(row(f"  HTTPS 代理: {colorize('✗ 未启用', Colors.RED)}"))
            
            if self.system_proxy.socks_enabled:
                status = colorize("✓ 已启用", Colors.GREEN)
                lines.append(row(f"  SOCKS 代理: {self.system_proxy.socks_host}:{self.system_proxy.socks_port} {status}"))
            else:
                lines.append(row(f"  SOCKS 代理: {colorize('✗ 未启用', Colors.RED)}"))
            
            if self.system_proxy.pac_enabled:
                lines.append(row(f"  PAC URL:    {colorize(self.system_proxy.pac_url, Colors.CYAN)}"))
            else:
                lines.append(row(f"  PAC URL:    未配置"))
        else:
            lines.append(row("  无法获取系统代理设置"))
        
        lines.append(sep)
        lines.append(row("[Clash TUN 模式]"))
        if self.tun_status:
            if self.tun_status.enabled and self.tun_status.is_default_route:
                status = colorize("✓ 已启用", Colors.GREEN)
                lines.append(row(f"  状态: {status}"))
                lines.append(row(f"  接口: {self.tun_status.interface} ({self.tun_status.ip_address})"))
                lines.append(row(f"  默认路由: 指向 {self.tun_status.interface}"))
            elif self.tun_status.enabled:
                status = colorize("⚠ 存在但未启用", Colors.YELLOW)
                lines.append(row(f"  状态: {status}"))
                lines.append(row(f"  接口: {self.tun_status.interface} ({self.tun_status.ip_address})"))
                lines.append(row(f"  默认路由: 不指向 Clash TUN"))
            else:
                lines.append(row(f"  状态: {colorize('✗ 未启用', Colors.RED)}"))
        else:
            lines.append(row("  无法检测 TUN 模式"))
        
        lines.append(sep)
        lines.append(row("[Clash 进程]"))
        if self.clash_status:
            if self.clash_status.running:
                status = colorize("✓ 运行中", Colors.GREEN)
                lines.append(row(f"  状态: {status} (PID: {self.clash_status.pid})"))
                if self.clash_status.port_listening:
                    lines.append(row(f"  端口: {self.clash_status.port} {colorize('✓ 监听中', Colors.GREEN)}"))
                else:
                    lines.append(row(f"  端口: {colorize('✗ 未监听', Colors.RED)}"))
            else:
                lines.append(row(f"  状态: {colorize('✗ 未运行', Colors.RED)}"))
        
        lines.append(sep)
        lines.append(row("[应用代理状态]"))
        
        for app_name, app in self.app_status.items():
            running_str = colorize("✓", Colors.GREEN) if app.running else colorize("✗", Colors.RED)
            lines.append(row(f"  [{app_name}] {running_str}"))
            
            if app.proxy_source == "custom":
                lines.append(row(f"    代理来源: {colorize('独立配置', Colors.YELLOW)}"))
                lines.append(row(f"    配置: {app.custom_proxy}"))
            elif app.proxy_source == "system":
                lines.append(row(f"    代理来源: 系统代理"))
            else:
                lines.append(row(f"    代理来源: 无"))
            
            if app.current_proxy:
                lines.append(row(f"    当前代理: {app.current_proxy}"))
        
        lines.append(sep)
        lines.append(row("[实际出口检测]"))
        
        if self.proxy_exit and self.proxy_exit.success:
            loc = f"{self.proxy_exit.city}, {self.proxy_exit.country}"
            lines.append(row(f"  走代理出口: {loc} ({self.proxy_exit.ip})"))
        else:
            lines.append(row(f"  走代理出口: {colorize('检测失败', Colors.RED)}"))
        
        if self.direct_exit and self.direct_exit.success:
            loc = f"{self.direct_exit.city}, {self.direct_exit.country}"
            lines.append(row(f"  直连出口:   {loc} ({self.direct_exit.ip})"))
        else:
            lines.append(row(f"  直连出口:   {colorize('检测失败', Colors.RED)}"))
        
        lines.append(sep)
        lines.append(row("[结论]"))
        
        if self.proxy_exit and self.direct_exit and self.proxy_exit.success and self.direct_exit.success:
            if self.proxy_exit.ip == self.direct_exit.ip:
                lines.append(row(f"  {colorize('⚠ 两个出口IP相同', Colors.YELLOW)}"))
        
        conclusion_color = Colors.GREEN if "生效" in self.conclusion else Colors.YELLOW
        lines.append(row(f"  {colorize(self.conclusion, conclusion_color)}"))
        
        lines.append(sep)
        lines.append(row(colorize("操作说明", Colors.BOLD)))
        lines.append(row("  r: 刷新  |  q: 退出  |  j: JSON输出"))
        lines.append(row("  --watch: 持续监控  |  --json: JSON格式"))
        
        lines.append(bottom)
        
        return "\n".join(lines)

    def to_json(self) -> dict:
        return {
            "system_proxy": {
                "http": {
                    "enabled": self.system_proxy.http_enabled if self.system_proxy else False,
                    "host": self.system_proxy.http_host if self.system_proxy else None,
                    "port": self.system_proxy.http_port if self.system_proxy else None,
                },
                "https": {
                    "enabled": self.system_proxy.https_enabled if self.system_proxy else False,
                    "host": self.system_proxy.https_host if self.system_proxy else None,
                    "port": self.system_proxy.https_port if self.system_proxy else None,
                },
                "socks": {
                    "enabled": self.system_proxy.socks_enabled if self.system_proxy else False,
                    "host": self.system_proxy.socks_host if self.system_proxy else None,
                    "port": self.system_proxy.socks_port if self.system_proxy else None,
                },
                "pac": {
                    "enabled": self.system_proxy.pac_enabled if self.system_proxy else False,
                    "url": self.system_proxy.pac_url if self.system_proxy else None,
                },
            },
            "tun": {
                "enabled": self.tun_status.enabled if self.tun_status else False,
                "interface": self.tun_status.interface if self.tun_status else None,
                "ip_address": self.tun_status.ip_address if self.tun_status else None,
                "is_default_route": self.tun_status.is_default_route if self.tun_status else False,
            },
            "clash": {
                "running": self.clash_status.running if self.clash_status else False,
                "pid": self.clash_status.pid if self.clash_status else None,
                "port": self.clash_status.port if self.clash_status else None,
                "port_listening": self.clash_status.port_listening if self.clash_status else False,
            },
            "apps": {
                name: {
                    "running": app.running,
                    "proxy_source": app.proxy_source,
                    "custom_proxy": app.custom_proxy,
                    "current_proxy": app.current_proxy,
                }
                for name, app in self.app_status.items()
            },
            "exit": {
                "proxy": {
                    "ip": self.proxy_exit.ip if self.proxy_exit else None,
                    "country": self.proxy_exit.country if self.proxy_exit else None,
                    "city": self.proxy_exit.city if self.proxy_exit else None,
                },
                "direct": {
                    "ip": self.direct_exit.ip if self.direct_exit else None,
                    "country": self.direct_exit.country if self.direct_exit else None,
                    "city": self.direct_exit.city if self.direct_exit else None,
                },
            },
            "conclusion": self.conclusion,
        }


def clear_screen():
    print("\033[2J\033[H", end="")


def kbhit():
    return select.select([sys.stdin], [], [], 0)[0] != []


def getch():
    return sys.stdin.read(1)


def interactive_mode(detector: ProxyDetector, interval: int = 5):
    import tty
    import termios
    
    old_settings = termios.tcgetattr(sys.stdin)
    json_mode = False
    last_refresh = time.time()
    
    try:
        tty.setcbreak(sys.stdin.fileno())
        
        while True:
            clear_screen()
            detector.run_all_checks()
            if json_mode:
                print(json.dumps(detector.to_json(), indent=2, ensure_ascii=False))
            else:
                print(detector.generate_report())
            print(f"\n上次刷新: {time.strftime('%H:%M:%S')} | 刷新间隔: {interval}秒")
            last_refresh = time.time()
            
            while True:
                if kbhit():
                    key = getch()
                    if key == 'q' or key == '\x03':
                        clear_screen()
                        print("已退出")
                        return
                    elif key == 'r':
                        break
                    elif key == 'j':
                        json_mode = not json_mode
                        break
                
                if time.time() - last_refresh >= interval:
                    break
                time.sleep(0.1)
    
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)


def main():
    parser = argparse.ArgumentParser(
        description="macOS 代理检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                  一次性检测
  %(prog)s --watch          持续监控，每5秒刷新
  %(prog)s --watch -i 3     持续监控，每3秒刷新
  %(prog)s --json           JSON格式输出
        """,
    )
    parser.add_argument(
        "--watch", "-w", action="store_true", help="持续监控模式"
    )
    parser.add_argument(
        "--interval", "-i", type=int, default=5, help="监控间隔秒数 (默认: 5)"
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="JSON格式输出"
    )
    args = parser.parse_args()
    
    detector = ProxyDetector()
    
    if args.watch:
        interactive_mode(detector, args.interval)
    else:
        detector.run_all_checks()
        if args.json:
            print(json.dumps(detector.to_json(), indent=2, ensure_ascii=False))
        else:
            print(detector.generate_report())


if __name__ == "__main__":
    main()
