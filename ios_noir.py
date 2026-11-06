#!/usr/bin/env python3
"""
iOS-NOIR: Local-first iPhone Privacy, Entitlements, Sandbox & Telemetry Auditor
Inspired by Verlintas/NOIR (https://github.com/Verlintas/NOIR)
Author: Arnold
License: MIT
"""
import argparse
import asyncio
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.os_trace import OsTraceService
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = """[bold cyan]
  ██╗ ██████╗ ███████╗      ███╗   ██╗ ██████╗ ██╗██████╗ 
  ██║██╔═══██╗██╔════╝      ████╗  ██║██╔═══██╗██║██╔══██╗
  ██║██║   ██║███████╗█████╗██╔██╗ ██║██║   ██║██║██████╔╝
  ██║██║   ██║╚════██║╚════╝██║╚██╗██║██║   ██║██║██╔══██╗
  ██║╚██████╔╝███████║      ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝ ╚═════╝ ╚══════╝      ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝[/bold cyan]
  [dim]Local-First iPhone Privacy, Entitlements, Sandbox & Telemetry Auditor[/dim]
  [dim]Inspired by https://github.com/Verlintas/NOIR[/dim]"""

TRACKER_KEYWORDS = [
    "umeng", "miaozhen", "admaster", "gridsum", "tanx", "rtbasia", "udbac",
    "shuzilm", "jspatch", "mob.com", "tealium", "omtrdc", "doubleclick",
    "radiumone", "cmpassport", "wostore", "id6.me", "wo.cn", "pangolin",
    "snssdk", "gdt.qq.com", "btrace.qq.com", "beacon.qq.com", "mmstat.com",
    "online-metrix.net", "jpush", "jiguang", "getui", "igexin", "sensorsdata",
]

SDK_FINGERPRINTS = [
    ("Bytedance Pangolin / 穿山甲广告", lambda s: s.startswith("snssdk") or "bdsdk" in s or "pangolin" in s),
    ("Tencent GDT / 广点通与开放平台", lambda s: s.startswith("tencent") or s.startswith("mqqopensdk") or s.startswith("wtlogin")),
    ("Weibo SDK / 微博追踪组件", lambda s: s.startswith("weibosdk") or s.startswith("wb")),
    ("Alibaba Baichuan / 阿里百川组件", lambda s: s.startswith("tbopen") or s.startswith("alipays") or "baichuan" in s),
    ("CyberIdentity / 国家网络身份认证或数币", lambda s: s in ["cyberidentity", "dcep"]),
    ("UnionPay / 银联云闪付组件", lambda s: s.startswith("uppay")),
    ("AMap & BaiduMap / 高德百度定位SDK", lambda s: s in ["iosamap", "amapuri", "baidumap"]),
    ("Meta FBSDK / Facebook 追踪组件", lambda s: s.startswith("fbapi") or s.startswith("fbauth") or s.startswith("fbshare")),
]

PRIVACY_PATTERNS = [
    (re.compile(r"kTCCService(\w+)", re.I), "🛡️ TCC 权限校验"),
    (re.compile(r"pasteboard|pbserver|UIPasteboard", re.I), "📋 剪贴板访问"),
    (re.compile(r"locationd|CLLocation", re.I), "📍 定位调用"),
    (re.compile(r"Contacts|AddressBook|CNContact", re.I), "📒 通讯录访问"),
    (re.compile(r"Photos|PHPhotoLibrary|PhotoLibrary", re.I), "🖼️ 相册访问"),
    (re.compile(r"AVAudioSession|microphone|audiomxd", re.I), "🎙️ 音频/麦克风"),
    (re.compile(r"cameracaptured|AVCapture", re.I), "📷 相机硬件调用"),
    (re.compile(r"idfa|advertisingIdentifier|ATTrackingManager", re.I), "🎯 IDFA 追踪请求"),
]


async def cmd_scan(out_dir: str, redact: bool = False, check_sandbox: bool = True):
    os.makedirs(out_dir, exist_ok=True)
    console.print(BANNER)

    lockdown = await create_using_usbmux()
    vals = await lockdown.get_value()
    dev_name = "iPhone (Redacted)" if redact else lockdown.display_name
    ios_ver = lockdown.product_version
    region = vals.get("RegionInfo", "Unknown")
    model_num = vals.get("ModelNumber", "Unknown")

    console.print(Panel(
        f"📱 Device: [bold green]{dev_name}[/bold green] | OS: [bold yellow]iOS {ios_ver}[/bold yellow] | Hardware Region: [bold cyan]{model_num} ({region})[/bold cyan]",
        title="iOS-NOIR Doctor", border_style="cyan"
    ))

    async with InstallationProxyService(lockdown=lockdown) as service:
        apps = await service.get_apps(application_type="User", calculate_sizes=False)

    results = []
    trackers_domains = set()
    functional_domains = set()
    shared_groups = defaultdict(list)
    scheme_owners = defaultdict(list)
    usb_exposed = []

    for bid, info in apps.items():
        name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or bid
        ent = info.get("Entitlements", {})
        bg = info.get("UIBackgroundModes", [])
        queried = info.get("LSApplicationQueriesSchemes", [])
        bonjour = info.get("NSBonjourServices", [])
        ats = info.get("NSAppTransportSecurity", {})
        cleartext = isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True
        exc_domains = (
            list(ats.get("NSExceptionDomains", {}).keys())
            if isinstance(ats, dict) and isinstance(ats.get("NSExceptionDomains"), dict)
            else []
        )

        for d in exc_domains:
            if any(t in d.lower() for t in TRACKER_KEYWORDS):
                trackers_domains.add(d)
            else:
                functional_domains.add(d)

        # App Groups
        for g in ent.get("com.apple.security.application-groups", []):
            shared_groups[g].append((name, bid))

        # URL Schemes
        for ut in info.get("CFBundleURLTypes", []):
            if isinstance(ut, dict):
                for s in ut.get("CFBundleURLSchemes", []):
                    scheme_owners[s].append(name)

        # High-risk entitlements & capabilities
        flags = []
        if ent.get("com.apple.developer.pushkit.unrestricted-voip-regulatory"):
            flags.append("🚨 监管特批: 无限制静默VoIP唤醒 (unrestricted-voip-regulatory)")
        if "com.apple.developer.networking.HotspotHelper" in ent:
            flags.append("📶 系统级Wi-Fi扫描唤醒钩子 (HotspotHelper)")
        if "com.apple.developer.networking.multipath" in ent or "network-authentication" in bg:
            flags.append("📡 绕过Wi-Fi直连运营商蜂窝网关 (multipath/net-auth)")
        if "com.apple.developer.networking.multicast" in ent:
            flags.append("🏠 局域网全屋设备多播探测 (multicast)")
        if "com.apple.developer.ubiquity-kvstore-identifier" in ent:
            flags.append("☁️ iCloud防卸载跨机持久化烙印 (ubiquity-kvstore)")
        if "nearby-interaction" in bg:
            flags.append("📍 U1/U2芯片厘米级UWB空间雷达 (nearby-interaction)")
        if ent.get("com.apple.developer.healthkit.background-delivery"):
            flags.append("❤️ 锁屏后台静默实时读取健康数据 (healthkit-bg)")
        if "content-filter-provider" in ent.get("com.apple.developer.networking.networkextension", []):
            flags.append("🕵️ 内置全局网络流量内容审查器 (content-filter)")
        if info.get("UIFileSharingEnabled") or info.get("LSSupportsOpeningDocumentsInPlace"):
            flags.append("📂 暴露USB/Wi-Fi免密直读沙盒 (UIFileSharingEnabled)")
            if check_sandbox:
                try:
                    ha = await HouseArrestService.create(lockdown=lockdown, bundle_id=bid, documents_only=True)
                    files = await ha.listdir("/Documents")
                    await ha.close()
                    if files:
                        shown = [f"<redacted_{i}>" for i in range(len(files))] if redact else files[:8]
                        usb_exposed.append((name, bid, len(files), shown))
                except Exception:
                    pass

        score = (
            len(flags) * 15
            + len(bg) * 4
            + min(len(queried) // 2, 40)
            + (10 if cleartext else 0)
            + len(exc_domains) * 2
        )

        results.append({
            "name": name,
            "bundle_id": bid,
            "score": score,
            "bg_modes": bg,
            "bg_count": len(bg),
            "queried_count": len(queried),
            "queried_schemes": queried,
            "bonjour_services": bonjour,
            "cleartext_http": cleartext,
            "ats_exception_domains": exc_domains,
            "flags": flags,
        })

    results.sort(key=lambda x: x["score"], reverse=True)

    # 1. Top Risk Table
    table = Table(title="🛡️ iOS-NOIR 隐私越界与隐藏后门风险榜 (Top 20)", show_lines=True)
    table.add_column("风险分", justify="right", style="bold red")
    table.add_column("应用名称", style="bold white")
    table.add_column("后台/嗅探", justify="center", style="yellow")
    table.add_column("检出的底层特权后门与硬编码豁免域", style="cyan")

    for r in results[:20]:
        score_str = f"[bold red]{r['score']}[/bold red]" if r["score"] >= 80 else f"[yellow]{r['score']}[/yellow]"
        stat_str = f"后台:{r['bg_count']} | 嗅探:{r['queried_count']}"
        flags_str = "\n".join(r["flags"]) if r["flags"] else "[dim]常规权限[/dim]"
        if r["ats_exception_domains"]:
            flags_str += f"\n[magenta]ATS豁免域: {', '.join(r['ats_exception_domains'][:4])}[/magenta]"
        table.add_row(score_str, f"{r['name']}\n[dim]{r['bundle_id']}[/dim]", stat_str, flags_str)

    console.print(table)

    # 2. Shared App Groups Table
    shared_table = Table(title="🔗 跨 App 共享数据池 (突破沙盒暗中串通容器)", show_lines=True)
    shared_table.add_column("共享容器 ID (App Group)", style="cyan")
    shared_table.add_column("同伙应用列表", style="yellow")
    for gid, members in sorted(shared_groups.items(), key=lambda x: len(x[1]), reverse=True):
        uniq = list({b: n for n, b in members}.items())
        if len(uniq) > 1:
            shared_table.add_row(gid, "、".join([f"[bold]{n}[/bold] ({b})" for b, n in uniq]))
    console.print(shared_table)

    # 3. USB Exposed Sandbox Alert
    if usb_exposed:
        usb_table = Table(title="💣 免 FaceID 通过 USB/Wi-Fi 直接裸奔可读的沙盒目录 (HouseArrest)", show_lines=True)
        usb_table.add_column("应用名称", style="bold red")
        usb_table.add_column("暴露文件数", justify="right", style="yellow")
        usb_table.add_column("直接可读文件样本 (--redact 可脱敏)", style="white")
        for n, b, cnt, sample in usb_exposed:
            usb_table.add_row(f"{n}\n[dim]{b}[/dim]", str(cnt), ", ".join(sample))
        console.print(usb_table)

    # Write output files
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now().isoformat(),
            "device": {"name": dev_name, "ios": ios_ver, "model": model_num, "region": region},
            "total_user_apps": len(results),
            "apps": results,
        }, f, ensure_ascii=False, indent=2)

    with open(os.path.join(out_dir, "domains-trackers.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(trackers_domains)) + "\n")

    with open(os.path.join(out_dir, "domains-functional.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(functional_domains)) + "\n")

    console.print(f"\n✅ [bold green]审计完成！[/bold green] 结构化报告已导出至 `[bold]{out_dir}/report.json[/bold]`。")


async def cmd_radar(duration: int = 30):
    console.print(BANNER)
    lockdown = await create_using_usbmux()
    console.print(f"📡 [bold green]实时隐私抓现行雷达已启动[/bold green] (持续 {duration} 秒)...")
    console.print("👉 [bold yellow]现在请在手机上点开任意待测 App，实时观测其毫秒级权限与传感器调用！[/bold yellow]\n")

    start = asyncio.get_event_loop().time()
    count = 0
    async with OsTraceService(lockdown=lockdown) as service:
        async for entry in service.syslog():
            if asyncio.get_event_loop().time() - start > duration:
                break
            proc = entry.filename or ""
            msg = entry.message or ""
            matched = None
            for regex, tag in PRIVACY_PATTERNS:
                if regex.search(msg) or regex.search(proc):
                    matched = tag
                    break
            if matched:
                count += 1
                ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                short = msg.strip().replace("\n", " ")[:120]
                console.print(f"[dim]{ts}[/dim] | [bold cyan]{matched}[/bold cyan] | [yellow]{proc}[/yellow]: {short}")

    console.print(f"\n✅ 雷达监控结束，共捕获 [bold]{count}[/bold] 条底层隐私调用事件。")


def main():
    parser = argparse.ArgumentParser(description="iOS-NOIR: Local-first iPhone Privacy Auditor")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Run full static, entitlement, endpoint & sandbox exposure audit")
    p_scan.add_argument("--out", default="noir-out", help="Output directory (default: noir-out)")
    p_scan.add_argument("--redact", action="store_true", help="Redact personal device name and exposed filenames for screenshots")
    p_scan.add_argument("--no-sandbox", action="store_true", help="Skip HouseArrest USB sandbox file listing")

    p_radar = sub.add_parser("radar", help="Run real-time TCC/Sensor/IDFA syslog privacy radar")
    p_radar.add_argument("--duration", type=int, default=30, help="Radar duration in seconds (default: 30)")

    args = parser.parse_args()
    if args.command == "radar":
        asyncio.run(cmd_radar(args.duration))
    else:
        out = getattr(args, "out", "noir-out")
        redact = getattr(args, "redact", False)
        no_sb = getattr(args, "no_sandbox", False)
        asyncio.run(cmd_scan(out, redact=redact, check_sandbox=not no_sb))


if __name__ == "__main__":
    main()
