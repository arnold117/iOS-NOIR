#!/usr/bin/env python3
"""
iOS-NOIR: Local-First iPhone Privacy, Entitlements, Sandbox & Telemetry Auditor
Inspired by https://github.com/Verlintas/NOIR & https://github.com/RootSir/claude-ios-privacy-analysis

Author: Arnold
PGP Fingerprint: C3D9 CA55 2798 2586 BB20  F2DB 7B25 BE32 527E FEA1
License: MIT
"""

import argparse
import asyncio
import datetime
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.os_trace import OsTraceService

console = Console()

BANNER_ZH = """[bold bright_blue]
  ██╗ ██████╗ ███████╗      ███╗   ██╗ ██████╗ ██╗██████╗ 
  ██║██╔═══██╗██╔════╝      ████╗  ██║██╔═══██╗██║██╔══██╗
  ██║██║   ██║███████╗█████╗██╔██╗ ██║██║   ██║██║██████╔╝
  ██║██║   ██║╚════██║╚════╝██║╚██╗██║██║   ██║██║██╔══██╗
  ██║╚██████╔╝███████║      ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝ ╚═════╝ ╚══════╝      ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝[/bold bright_blue]
[dim]Local-First Stock iOS Privacy, Entitlement, Sandbox & Telemetry Auditor[/dim]
[dim]Inspired by [underline]https://github.com/Verlintas/NOIR[/underline] & [underline]https://github.com/RootSir/claude-ios-privacy-analysis[/underline][/dim]
[dim]证据分级: [bold green]【实锤】[/bold green]静态配置/沙盒直读确证  [bold yellow]【机制实锤】[/bold yellow]苹果签名内核特权就绪  [bold cyan]【推断】[/bold cyan]基于SDK/跨容器特征关联[/dim]
"""

BANNER_EN = """[bold bright_blue]
  ██╗ ██████╗ ███████╗      ███╗   ██╗ ██████╗ ██╗██████╗ 
  ██║██╔═══██╗██╔════╝      ████╗  ██║██╔═══██╗██║██╔══██╗
  ██║██║   ██║███████╗█████╗██╔██╗ ██║██║   ██║██║██████╔╝
  ██║██║   ██║╚════██║╚════╝██║╚██╗██║██║   ██║██║██╔══██╗
  ██║╚██████╔╝███████║      ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝ ╚═════╝ ╚══════╝      ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝[/bold bright_blue]
[dim]Local-First Stock iOS Privacy, Entitlement, Sandbox & Telemetry Auditor[/dim]
[dim]Inspired by [underline]https://github.com/Verlintas/NOIR[/underline] & [underline]https://github.com/RootSir/claude-ios-privacy-analysis[/underline][/dim]
[dim]Evidence Tiers: [bold green][VERIFIED][/bold green] Static Plist/Sandbox Proof  [bold yellow][CAPABILITY][/bold yellow] Apple-Signed Kernel Entitlement  [bold cyan][INFERRED][/bold cyan] Cross-Container/SDK Correlation[/dim]
"""

# (zh_label, en_label, points, tier_code, zh_explain, en_explain)
HIGH_RISK_ENTITLEMENTS = {
    "com.apple.developer.pushkit.unrestricted-voip-regulatory": (
        "🚨 [机制实锤] 监管特批: 无限制静默VoIP唤醒 (unrestricted-voip-regulatory)",
        "🚨 [CAPABILITY] Regulatory Exemption: Unrestricted Silent VoIP Wakeup (unrestricted-voip-regulatory)",
        35,
        "CAPABILITY",
        "不用弹全屏来电界面，服务器可随时下发无声指令把划掉的死进程静默拉活（屏幕不亮不响）。",
        "Bypasses iOS 13+ mandatory full-screen CallKit UI rules; allows servers to silently wake dead background processes via PushKit without lighting up the screen.",
    ),
    "com.apple.developer.pushkit.unrestricted-voip": (
        "🚨 [机制实锤] 旧版无限制静默VoIP唤醒 (unrestricted-voip)",
        "🚨 [CAPABILITY] Legacy Unrestricted Silent VoIP Wakeup (unrestricted-voip)",
        30,
        "CAPABILITY",
        "允许通过 VoIP 语音推送通道在后台静默唤醒已关闭的应用。",
        "Allows background process wakeups via silent VoIP PushKit payloads without user interaction.",
    ),
    "com.apple.developer.networking.HotspotHelper": (
        "📶 [机制实锤] 系统级Wi-Fi扫描唤醒钩子 (HotspotHelper)",
        "📶 [CAPABILITY] System-Level Wi-Fi Scan Hook (HotspotHelper)",
        30,
        "CAPABILITY",
        "只要你打开系统 Wi-Fi 设置或走过商场，iOS 内核自动唤醒它并把周围所有路由器的 MAC 地址 (BSSID) 喂给它，没开 GPS 也能定位你。",
        "Automatically woken by the iOS kernel whenever Wi-Fi networks are scanned, receiving nearby router SSIDs & hardware MAC addresses (BSSIDs) for GPS-free physical location tracking.",
    ),
    "com.apple.developer.networking.multipath": (
        "📡 [机制实锤] 绕过Wi-Fi并发拉起蜂窝通道 (multipath)",
        "📡 [CAPABILITY] Multipath Cellular VPN/Wi-Fi Bypass (multipath)",
        18,
        "CAPABILITY",
        "哪怕你连着家里 Wi-Fi 或挂着 VPN，它也能同时强行开启 4G/5G 蜂窝流量通道直连服务器（常用于绕过代理或配合基站取号）。",
        "Can force concurrent cellular (pdp_ip0) connections even while on Wi-Fi or VPN — often used to hit carrier gateways for silent SIM/phone-number extraction.",
    ),
    "com.apple.developer.CellularNetwork.network-authentication": (
        "📱 [机制实锤] 蜂窝基站免密取号认证特权 (network-authentication)",
        "📱 [CAPABILITY] Cellular Carrier Silent SIM/MDN Auth (network-authentication)",
        22,
        "CAPABILITY",
        "直连移动/联通/电信基站网关，静默核验你的 SIM 卡身份或提取本机真实手机号。",
        "Grants direct cellular carrier gateway authentication to silently verify SIM identity or extract the device phone number (MDN).",
    ),
    "com.apple.developer.networking.multicast": (
        "🏠 [机制实锤] 局域网全屋设备多播探测 (multicast)",
        "🏠 [CAPABILITY] Local Network Multicast Device Discovery (multicast)",
        20,
        "CAPABILITY",
        "向你家里或办公室的 Wi-Fi 发送局域网广播包，探测你家里有哪些智能电视、NAS、音响、打印机，精准描绘家庭资产画像。",
        "Allows sending mDNS/SSDP/UDP multicast packets on your Wi-Fi to enumerate smart TVs, NAS drives, speakers, and routers for household profiling.",
    ),
    "com.apple.developer.ubiquity-kvstore-identifier": (
        "☁️ [实锤] iCloud防卸载跨机持久化烙印 (ubiquity-kvstore)",
        "☁️ [VERIFIED] Uninstall- & New-iPhone-Proof iCloud KVS Token (ubiquity-kvstore)",
        15,
        "VERIFIED",
        "把唯一追踪码偷偷写进你的私人 iCloud 云空间——就算你卸载重装 App，甚至换了一台新 iPhone，它也能秒认出还是你。",
        "Writes persistent device tokens into your private iCloud Key-Value Store that survive app uninstallation and automatically sync to brand-new iPhones.",
    ),
    "com.apple.developer.healthkit.background-delivery": (
        "❤️ [机制实锤] 锁屏后台静默实时推送健康数据 (healthkit-bg)",
        "❤️ [CAPABILITY] Lock-Screen Real-Time HealthKit Background Delivery (healthkit-bg)",
        20,
        "CAPABILITY",
        "锁屏状态下，只要你的步数、心率或睡眠数据更新，系统就会在后台静默唤醒它同步生理数据。",
        "Wakes the app in the background even while the screen is locked whenever HealthKit step, heart-rate, or sleep metrics update.",
    ),
    "com.apple.developer.nearby-interaction": (
        "📍 [机制实锤] U1/U2芯片厘米级UWB空间雷达 (nearby-interaction)",
        "📍 [CAPABILITY] U1/U2 Ultra-Wideband (UWB) Centimeter Spatial Radar (nearby-interaction)",
        20,
        "CAPABILITY",
        "调用 iPhone 的 U1/U2 超宽带雷达芯片，以厘米级精度测算手机与周围其他设备的空间距离和方向。",
        "Accesses the U1/U2 Ultra-Wideband chip to measure centimeter-level distance and angle to nearby devices.",
    ),
    "com.apple.developer.networking.networkextension": (
        "🛡️ [机制实锤] 底层网络扩展与虚拟网卡控制 (networkextension)",
        "🛡️ [CAPABILITY] Kernel Network Extension & Virtual Tunnel Control (networkextension)",
        20,
        "CAPABILITY",
        "在系统底层注册虚拟网卡或流量隧道，具备接管、分流系统网络流量的底层能力。",
        "Can register Packet Tunnel, App Proxy, or DNS Proxy extensions to intercept or route system network traffic.",
    ),
    "com.apple.developer.networking.content-filter": (
        "🕵️ [机制实锤] 内置网络流量内容审查过滤器 (content-filter)",
        "🕵️ [CAPABILITY] On-Device Network Content Filter & Inspector (content-filter)",
        25,
        "CAPABILITY",
        "在设备端挂载内容审查过滤器，可监控或拦截进出设备的网络请求。",
        "Allows installing an on-device network content filter to inspect or block network flows.",
    ),
    "com.apple.developer.devicecheck.appattest-environment": (
        "🔐 [实锤] 硬件级安全隔区设备证明 (AppAttest)",
        "🔐 [VERIFIED] Secure Enclave Hardware Device Attestation (AppAttest)",
        10,
        "VERIFIED",
        "调用苹果安全隔区硬件芯片生成不可篡改的设备身份证，常用于防作弊与硬件级封号关联。",
        "Uses Apple's Secure Enclave to generate cryptographic hardware attestation keys bound to the physical device.",
    ),
}

PLAIN_EXPLANATIONS = {
    "unrestricted-voip-regulatory": (
        "不用弹全屏来电界面，服务器可随时下发无声指令把划掉的死进程静默拉活（屏幕不亮不响）。",
        "Bypasses iOS 13+ mandatory CallKit UI rules; allows servers to silently wake terminated background processes via PushKit without lighting up the screen.",
    ),
    "unrestricted-voip": (
        "允许通过 VoIP 语音推送通道在后台静默唤醒已关闭的应用。",
        "Allows waking closed background processes via silent VoIP PushKit payloads.",
    ),
    "HotspotHelper": (
        "只要你打开系统 Wi-Fi 设置或走过商场，iOS 内核自动唤醒它并把周围所有路由器的 MAC 地址 (BSSID) 喂给它，没开 GPS 也能定位你。",
        "Automatically woken by iOS whenever Wi-Fi networks are scanned, receiving nearby router MAC addresses (BSSIDs) for GPS-free physical location tracking.",
    ),
    "multipath": (
        "哪怕你连着家里 Wi-Fi 或挂着 VPN，它也能同时强行开启 4G/5G 蜂窝流量通道直连服务器（常用于绕过代理或配合基站取号）。",
        "Forces concurrent 4G/5G cellular (pdp_ip0) connections even while on Wi-Fi or VPN — bypassing proxies to hit carrier gateways.",
    ),
    "network-authentication": (
        "直连移动/联通/电信基站网关，静默核验你的 SIM 卡身份或提取本机真实手机号。",
        "Connects directly to telecom carrier gateways to silently authenticate SIM identity or extract your phone number (MDN).",
    ),
    "multicast": (
        "向你家里或办公室的 Wi-Fi 发送局域网广播包，探测你家里有哪些智能电视、NAS、音响、打印机，精准描绘家庭资产画像。",
        "Sends mDNS/SSDP/UDP multicast probes across your local Wi-Fi to discover smart TVs, NAS drives, speakers, and routers.",
    ),
    "ubiquity-kvstore": (
        "把唯一追踪码偷偷写进你的私人 iCloud 云空间——就算你卸载重装 App，甚至换了一台新 iPhone，它也能秒认出还是你。",
        "Stores persistent tracking tokens in your private iCloud Key-Value Store that survive app uninstallation and restore on new iPhones.",
    ),
    "healthkit-bg": (
        "锁屏状态下，只要你的步数、心率或睡眠数据更新，系统就会在后台静默唤醒它同步生理数据。",
        "Silently wakes the app in the background while locked whenever HealthKit step, heart-rate, or sleep records change.",
    ),
    "nearby-interaction": (
        "调用 iPhone 的 U1/U2 超宽带雷达芯片，以厘米级精度测算手机与周围其他设备的空间距离和方向。",
        "Uses the U1/U2 Ultra-Wideband (UWB) chip to measure centimeter-precision distance and direction to nearby devices.",
    ),
    "networkextension": (
        "在系统底层注册虚拟网卡或流量隧道，具备接管、分流系统网络流量的底层能力。",
        "Registers system-level virtual network interfaces or tunnels capable of routing or inspecting device traffic.",
    ),
    "content-filter": (
        "在设备端挂载内容审查过滤器，可监控或拦截进出设备的网络请求。",
        "Attaches an on-device content filter to inspect or block incoming/outgoing network connections.",
    ),
    "AppAttest": (
        "调用苹果安全隔区硬件芯片生成不可篡改的设备身份证，常用于防作弊与硬件级封号关联。",
        "Uses the Apple Secure Enclave to bind accounts to an unforgeable hardware attestation key.",
    ),
    "HouseArrest": (
        "应用把内部文档目录直接暴露在 USB 与局域网 Wi-Fi 同步接口下，插上电脑无需解锁 FaceID 就能直接拷走里面的文件。",
        "Exposes the app's /Documents directory over USB and local Wi-Fi sync without requiring FaceID or app unlock.",
    ),
    "UIFileSharingEnabled": (
        "开启了外部文件共享接口，信任过的电脑可通过 USB 或同一局域网 Wi-Fi 免密访问其 /Documents 目录。",
        "Enables external file sharing; any trusted computer on USB or local Wi-Fi can read/copy its /Documents folder without FaceID.",
    ),
}

BG_MODE_LABELS = {
    "location": ("📍location (后台持续定位追踪)", "📍location (Continuous background GPS tracking)"),
    "audio": ("🔊audio (后台音频播放/无声保活/录音)", "🔊audio (Background audio / silent keep-alive / mic)"),
    "voip": ("📞voip (网络电话后台常驻唤醒)", "📞voip (Background VoIP call keep-alive & wakeup)"),
    "remote-notification": ("🔔remote-notification (静默推送唤醒后台)", "🔔remote-notification (Silent push background wakeup)"),
    "fetch": ("🔄fetch (系统定期后台唤醒拉取数据)", "🔄fetch (Periodic background data fetch)"),
    "processing": ("⚙️processing (锁屏充电后台耗时任务)", "⚙️processing (Background processing tasks while locked)"),
    "bluetooth-central": ("🦷bluetooth-central (后台持续扫描周边蓝牙设备/信标)", "🦷bluetooth-central (Background Bluetooth beacon scanning)"),
    "bluetooth-peripheral": ("📡bluetooth-peripheral (后台作为蓝牙信标对外广播)", "📡bluetooth-peripheral (Background Bluetooth beacon broadcasting)"),
    "external-accessory": ("🔌external-accessory (后台持续通信外接硬件配件)", "🔌external-accessory (Background hardware accessory comm)"),
    "nearby-interaction": ("📏nearby-interaction (后台超宽带空间测距)", "📏nearby-interaction (Background UWB spatial ranging)"),
    "push-to-talk": ("🎙️push-to-talk (后台对讲机实时语音唤醒)", "🎙️push-to-talk (Background walkie-talkie audio wakeup)"),
}


def build_html_report(report_data: dict, redact: bool = False, default_lang: str = "zh") -> str:
    """Generate a standalone, bilingual (ZH/EN instant toggle) 6-tab HTML report."""
    dev = report_data["device"]
    summary = report_data["summary"]
    apps = report_data["apps"]
    shared_groups = report_data["shared_app_groups"]
    shared_keychains = report_data.get("shared_keychains", {})

    layer_icloud = [a for a in apps if a.get("has_icloud_kvs")]
    layer_multipath = [a for a in apps if a.get("has_multipath") or a.get("has_net_auth")]
    layer_hotspot = [a for a in apps if a.get("has_hotspot_helper")]
    layer_voip = [a for a in apps if a.get("has_unrestricted_voip")]
    layer_ats = [a for a in apps if a.get("ats_exception_domains")]
    layer_sandbox = [a for a in apps if a.get("exposed_files_count", 0) > 0]
    all_probers = [
        a for a in sorted(apps, key=lambda x: len(x.get("queried_schemes", [])), reverse=True)
        if a.get("queried_schemes")
    ]
    flagged_apps = [
        a for a in apps
        if a["score"] > 0 or a["findings"] or a["ats_exception_domains"] or a["queried_schemes"] or a["bg_modes"]
    ]

    top_rows_html = []
    for idx, a in enumerate(apps, 1):
        findings_badges = []
        findings_en_list = a.get("findings_en", [])
        for f_idx, f in enumerate(a["findings"]):
            f_en = findings_en_list[f_idx] if f_idx < len(findings_en_list) else f
            if "[实锤]" in f:
                badge_zh = f'<span class="evi evi-seen">【实锤】</span> <b>{html.escape(f.replace("[实锤] ", ""))}</b>'
                badge_en = f'<span class="evi evi-seen">[VERIFIED]</span> <b>{html.escape(f_en.replace("[VERIFIED] ", ""))}</b>'
            elif "[机制实锤]" in f:
                badge_zh = f'<span class="evi evi-cap">【机制实锤】</span> <b>{html.escape(f.replace("[机制实锤] ", ""))}</b>'
                badge_en = f'<span class="evi evi-cap">[CAPABILITY]</span> <b>{html.escape(f_en.replace("[CAPABILITY] ", ""))}</b>'
            else:
                badge_zh = f'<span class="evi evi-inf">【推断】</span> <b>{html.escape(f)}</b>'
                badge_en = f'<span class="evi evi-inf">[INFERRED]</span> <b>{html.escape(f_en)}</b>'

            plain_desc = ""
            for key, (exp_zh, exp_en) in PLAIN_EXPLANATIONS.items():
                if key in f or (key == "HouseArrest" and "裸露文件" in f):
                    plain_desc = (
                        f'<div class="text-small text-muted" style="margin:1px 0 6px 18px;">'
                        f'<span class="i18n-zh">👉 <b>能干什么：</b>{html.escape(exp_zh)}</span>'
                        f'<span class="i18n-en">👉 <b>What it does: </b>{html.escape(exp_en)}</span>'
                        f"</div>"
                    )
                    break
            findings_badges.append(
                f'<div><span class="i18n-zh">{badge_zh}</span><span class="i18n-en">{badge_en}</span>{plain_desc}</div>'
            )

        if a["queried_schemes"]:
            sc_preview = ", ".join(html.escape(s) for s in a["queried_schemes"][:8])
            more_zh = f" 等共 {len(a['queried_schemes'])} 个" if len(a["queried_schemes"]) > 8 else ""
            more_en = f" (+{len(a['queried_schemes']) - 8} more)" if len(a["queried_schemes"]) > 8 else ""
            findings_badges.append(
                f"<div>"
                f'<span class="i18n-zh"><span class="evi evi-seen">【实锤】</span> <b>🕵️ 查户口嗅探已安装应用 ({len(a["queried_schemes"])} 个暗号)</b></span>'
                f'<span class="i18n-en"><span class="evi evi-seen">[VERIFIED]</span> <b>🕵️ Installed-App URL Scheme Probing ({len(a["queried_schemes"])} schemes)</b></span>'
                f'<div class="text-small text-muted" style="margin:1px 0 6px 18px;">'
                f'<span class="i18n-zh">👉 <b>能干什么：</b>在后台挨个试探你手机里有没有装特定 App（如 <code>{sc_preview}{more_zh}</code>），用来给你的资产、翻墙习惯或社交圈画像。</span>'
                f'<span class="i18n-en">👉 <b>What it does: </b>Silently probes whether specific apps (<code>{sc_preview}{more_en}</code>) are installed via <code>canOpenURL:</code> to profile your wealth, VPN usage, or social graph.</span>'
                f"</div></div>"
            )

        if a["ats_exception_domains"]:
            doms = ", ".join(html.escape(d) for d in a["ats_exception_domains"])
            findings_badges.append(
                f"<div>"
                f'<span class="i18n-zh"><span class="evi evi-seen">【实锤】</span> <b>🎯 ATS 加密降级/豁免后门域 ({len(a["ats_exception_domains"])} 个):</b> <code>{doms}</code></span>'
                f'<span class="i18n-en"><span class="evi evi-seen">[VERIFIED]</span> <b>🎯 ATS HTTPS-Downgrade Exception Domains ({len(a["ats_exception_domains"])}):</b> <code>{doms}</code></span>'
                f'<div class="text-small text-muted" style="margin:1px 0 6px 18px;">'
                f'<span class="i18n-zh">👉 <b>能干什么：</b>开发者专门向苹果申请对这些域名关闭强制 HTTPS 保护（允许明文传输或忽略证书校验），常暴露出第三方追踪 SDK、运营商取号接口或热更新后门。</span>'
                f'<span class="i18n-en">👉 <b>What it does: </b>Domains where the developer explicitly disabled Apple\'s strict HTTPS requirement — often exposing embedded attribution SDKs, carrier auth gateways, or legacy hot-patch backdoors.</span>'
                f"</div></div>"
            )

        if a["bg_modes"]:
            bgs_zh = " · ".join(f"<code>{html.escape(BG_MODE_LABELS.get(b, (b, b))[0])}</code>" for b in a["bg_modes"])
            bgs_en = " · ".join(f"<code>{html.escape(BG_MODE_LABELS.get(b, (b, b))[1])}</code>" for b in a["bg_modes"])
            findings_badges.append(
                f'<div class="text-small" style="margin-top:4px;">'
                f'<span class="i18n-zh"><span class="text-muted">🔄 声明的后台常驻能力 ({len(a["bg_modes"])} 项):</span> {bgs_zh}</span>'
                f'<span class="i18n-en"><span class="text-muted">🔄 Declared Background Modes ({len(a["bg_modes"])}):</span> {bgs_en}</span>'
                f"</div>"
            )

        score_color = "var(--red)" if a["score"] >= 80 else ("var(--orange)" if a["score"] >= 30 else "var(--muted-foreground)")
        empty_badge = '<span class="text-muted"><span class="i18n-zh">零特权越界 (Clean)</span><span class="i18n-en">Zero Privileged Overreach (Clean)</span></span>'
        top_rows_html.append(
            f'<tr class="audit-row" data-score="{a["score"]}">'
            f'<td class="text-end text-muted">{idx}</td>'
            f'<td class="text-end"><b style="color:{score_color}">{a["score"]}</b></td>'
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code> <span class="text-muted text-small">v{html.escape(str(a["version"]))}</span></td>'
            f'<td class="text-nowrap">'
            f'<span class="i18n-zh">后台: <b>{len(a["bg_modes"])}</b><br>嗅探: <b>{len(a["queried_schemes"])}</b><br>插件: <b>{a.get("extensions_count", 0)}</b></span>'
            f'<span class="i18n-en">BG Modes: <b>{len(a["bg_modes"])}</b><br>Probes: <b>{len(a["queried_schemes"])}</b><br>Plugins: <b>{a.get("extensions_count", 0)}</b></span>'
            f"</td>"
            f'<td>{"".join(findings_badges) or empty_badge}</td>'
            f"</tr>"
        )

    ats_rows_html = []
    for a in sorted(layer_ats, key=lambda x: len(x["ats_exception_domains"]), reverse=True):
        doms_code = " ".join(f"<code>{html.escape(d)}</code>" for d in a["ats_exception_domains"])
        ats_rows_html.append(
            f"<tr>"
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code></td>'
            f'<td class="text-end"><b>{len(a["ats_exception_domains"])}</b></td>'
            f"<td>{doms_code}</td>"
            f'<td><span class="evi evi-seen"><span class="i18n-zh">【实锤】Info.plist 静态抽取</span><span class="i18n-en">[VERIFIED] Info.plist Static Extraction</span></span></td>'
            f"</tr>"
        )

    group_rows_html = []
    for gid, members in sorted(shared_groups.items(), key=lambda x: len(x[1]), reverse=True):
        m_str = "、".join(f"<b>{html.escape(m.split(' (')[0])}</b> (<code>{html.escape(m.split(' (')[1][:-1])}</code>)" for m in members)
        group_rows_html.append(
            f"<tr>"
            f'<td class="mono"><code>{html.escape(gid)}</code></td>'
            f'<td class="text-end"><b>{len(members)}</b></td>'
            f"<td>{m_str}</td>"
            f'<td><span class="evi evi-seen"><span class="i18n-zh">【实锤】容器互通</span><span class="i18n-en">[VERIFIED] Shared Container</span></span> / <span class="evi evi-inf"><span class="i18n-zh">【推断】指纹共享</span><span class="i18n-en">[INFERRED] ID Sync</span></span></td>'
            f"</tr>"
        )

    sandbox_rows_html = []
    for a in sorted(layer_sandbox, key=lambda x: x["exposed_files_count"], reverse=True):
        samples = ", ".join(f"<code>{html.escape(s)}</code>" for s in a["exposed_files_sample"])
        sandbox_rows_html.append(
            f"<tr>"
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code></td>'
            f'<td class="text-end"><b style="color:var(--red)">{a["exposed_files_count"]}</b></td>'
            f"<td>{samples}</td>"
            f'<td><span class="evi evi-seen"><span class="i18n-zh">【实锤】HouseArrest 免密枚举</span><span class="i18n-en">[VERIFIED] Unauthenticated HouseArrest</span></span></td>'
            f"</tr>"
        )

    prober_rows_html = []
    for a in all_probers:
        sample_sc = ", ".join(f"<code>{html.escape(s)}</code>" for s in a["queried_schemes"])
        prober_rows_html.append(
            f"<tr>"
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code></td>'
            f'<td class="text-end"><b>{len(a["queried_schemes"])}</b></td>'
            f"<td>{sample_sc}</td>"
            f'<td><span class="evi evi-seen"><span class="i18n-zh">【实锤】LSApplicationQueriesSchemes</span><span class="i18n-en">[VERIFIED] LSApplicationQueriesSchemes</span></span></td>'
            f"</tr>"
        )

    init_lang = "en" if default_lang == "en" else "zh"

    return f"""<!doctype html>
<html lang="{init_lang}" data-lang="{init_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iOS-NOIR Forensic Privacy Audit Report — {html.escape(dev['name'])} (iOS {html.escape(dev['ios_version'])})</title>
<style>
:root {{
  --background: #f7f7f8; --foreground: #18181b;
  --card: #ffffff; --card-foreground: #18181b;
  --muted: #f4f4f5; --muted-foreground: #71717a;
  --border: #e4e4e7; --ring: #a1a1aa;
  --blue: #2563eb; --orange: #ea580c; --green: #16a34a; --red: #dc2626; --purple: #7c3aed;
  --font-size-base: 15px;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --background: #121216; --foreground: #fafafa;
    --card: #1c1c22; --card-foreground: #fafafa;
    --muted: #272730; --muted-foreground: #a1a1aa;
    --border: #32323e; --ring: #52525b;
    --blue: #60a5fa; --orange: #fb923c; --green: #4ade80; --red: #f87171; --purple: #a78bfa;
  }}
}}
html[data-lang="zh"] .i18n-en {{ display: none !important; }}
html[data-lang="en"] .i18n-zh {{ display: none !important; }}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 28px clamp(16px, 4vw, 56px) 64px;
  background: var(--background); color: var(--foreground);
  font-size: var(--font-size-base); line-height: 1.6;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
}}
h1 {{ font-size: calc(var(--font-size-base) + 9px); margin: 0 0 6px; letter-spacing: -0.02em; }}
h2 {{ font-size: calc(var(--font-size-base) + 4px); margin: 12px 0 8px; }}
h3, h4 {{ font-size: calc(var(--font-size-base) + 1px); margin: 18px 0 8px; }}
p {{ margin: 8px 0; }}
ul, ol {{ margin: 8px 0; padding-left: 22px; }}
li {{ margin: 4px 0; }}
code {{
  background: var(--muted); color: var(--card-foreground);
  border-radius: 4px; padding: 1px 5px;
  font-size: 0.85em; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  word-break: break-all;
}}
hr {{ border: 0; border-top: 1px solid var(--border); margin: 20px 0; }}
.card {{
  background: var(--card); color: var(--card-foreground);
  border: 1px solid var(--border); border-radius: 12px; margin-bottom: 14px;
}}
.card-body {{ padding: 14px 18px; }}
.text-muted {{ color: var(--muted-foreground); }}
.text-small {{ font-size: 13px; }}
.text-end {{ text-align: right; }}
.text-nowrap {{ white-space: nowrap; }}
.mono {{ font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
.viz-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); margin: 16px 0; }}
.viz-stat-value {{ font-size: calc(var(--font-size-base) + 8px); font-weight: 600; line-height: 1.3; }}
.nav-pills {{ display: flex; flex-wrap: wrap; gap: 6px; padding: 5px; background: var(--muted); border-radius: 10px; width: fit-content; max-width: 100%; margin: 18px 0; }}
.nav-link {{
  appearance: none; border: 0; background: transparent; color: var(--muted-foreground);
  border-radius: 7px; padding: 6px 14px; font-size: 14px; cursor: pointer; font-family: inherit;
}}
.nav-link.active {{ background: var(--card); color: var(--card-foreground); font-weight: 600; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
.lang-switch {{
  display: inline-flex; gap: 4px; padding: 3px; background: var(--muted); border-radius: 8px; border: 1px solid var(--border);
}}
.lang-btn {{
  appearance: none; border: 0; background: transparent; color: var(--muted-foreground);
  border-radius: 6px; padding: 4px 10px; font-size: 13px; cursor: pointer; font-weight: 600;
}}
.lang-btn.active {{ background: var(--card); color: var(--foreground); box-shadow: 0 1px 2px rgba(0,0,0,0.12); }}
.table-responsive {{ overflow-x: auto; margin: 10px 0; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 4px; }}
.table {{ border-collapse: collapse; width: 100%; font-size: 13.5px; }}
.table th {{ text-align: left; color: var(--muted-foreground); font-weight: 600; border-bottom: 1px solid var(--border); padding: 10px 12px; }}
.table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
.table tr:last-child td {{ border-bottom: 0; }}
.evi {{ display: inline-flex; align-items: center; gap: 3px; font-weight: 600; font-size: 12px; white-space: nowrap; }}
.evi-seen {{ color: var(--green); }}
.evi-cap  {{ color: var(--orange); }}
.evi-inf  {{ color: var(--purple); }}
</style>
</head>
<body>
<div id="ios-noir-report">
  <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
    <div>
      <h1>
        <span class="i18n-zh">🛡️ iOS-NOIR 未越狱 iPhone 底层隐私与遥测取证报告</span>
        <span class="i18n-en">🛡️ iOS-NOIR Stock iPhone Privacy, Entitlement &amp; Telemetry Forensic Report</span>
      </h1>
      <p class="text-muted text-small">
        <span class="i18n-zh">设备: <code>{html.escape(dev['name'])}</code> · 系统: <code>iOS {html.escape(dev['ios_version'])}</code> · 硬件区域: <code>{html.escape(dev['model'])} ({html.escape(dev['region'])})</code> · 生成时间: <code>{html.escape(report_data['generated_at'][:19])}</code></span>
        <span class="i18n-en">Device: <code>{html.escape(dev['name'])}</code> · OS: <code>iOS {html.escape(dev['ios_version'])}</code> · Hardware Region: <code>{html.escape(dev['model'])} ({html.escape(dev['region'])})</code> · Generated: <code>{html.escape(report_data['generated_at'][:19])}</code></span>
      </p>
    </div>
    <div style="display:flex; flex-direction:column; align-items:flex-end; gap:8px;">
      <div class="lang-switch" role="group" aria-label="Language Switch">
        <button type="button" class="lang-btn {'active' if init_lang == 'zh' else ''}" data-set-lang="zh">🇨🇳 简体中文</button>
        <button type="button" class="lang-btn {'active' if init_lang == 'en' else ''}" data-set-lang="en">🇺🇸 English</button>
      </div>
      <div class="text-small text-muted">
        Inspired by <a href="https://github.com/Verlintas/NOIR" style="color:var(--blue)">Verlintas/NOIR</a> &amp; <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir/claude-ios-privacy-analysis</a>
      </div>
    </div>
  </div>

  <div class="viz-grid">
    <div class="card"><div class="card-body">
      <div class="text-muted text-small"><span class="i18n-zh">已审计用户安装应用</span><span class="i18n-en">Audited User Apps</span></div>
      <div class="viz-stat-value">{summary['total_user_apps']}</div>
      <div class="text-small text-muted"><span class="i18n-zh">全量提取 Apple 签名 Entitlements</span><span class="i18n-en">Apple-signed Entitlements extracted</span></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small"><span class="i18n-zh">监管特批无声 VoIP 唤醒</span><span class="i18n-en">Silent VoIP Exemption</span></div>
      <div class="viz-stat-value" style="color:var(--red)">{len(layer_voip)}</div>
      <div class="text-small text-muted"><code>unrestricted-voip-regulatory</code></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small"><span class="i18n-zh">系统级 Wi-Fi 扫描钩子</span><span class="i18n-en">Wi-Fi BSSID Scan Hooks</span></div>
      <div class="viz-stat-value" style="color:var(--orange)">{len(layer_hotspot)}</div>
      <div class="text-small text-muted"><code>HotspotHelper</code></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small"><span class="i18n-zh">穿 VPN 蜂窝并发/免密取号</span><span class="i18n-en">Cellular VPN Bypass / SIM Auth</span></div>
      <div class="viz-stat-value" style="color:var(--purple)">{len(layer_multipath)}</div>
      <div class="text-small text-muted"><code>multipath</code> / <code>network-auth</code></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small"><span class="i18n-zh">跨应用共享容器串通池</span><span class="i18n-en">Cross-App Shared Pools</span></div>
      <div class="viz-stat-value" style="color:var(--blue)">{summary['shared_app_groups_count']}</div>
      <div class="text-small text-muted"><span class="i18n-zh">突破沙盒共享本地存储与钥匙串</span><span class="i18n-en">Shared App Groups &amp; Keychains</span></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small"><span class="i18n-zh">免 FaceID 暴露沙盒目录</span><span class="i18n-en">Exposed Sandbox Containers</span></div>
      <div class="viz-stat-value" style="color:var(--red)">{len(layer_sandbox)}</div>
      <div class="text-small text-muted"><span class="i18n-zh">USB/Wi-Fi 直接可读写文件</span><span class="i18n-en">Readable via USB/Wi-Fi without FaceID</span></div>
    </div></div>
  </div>

  <div class="nav-pills" role="tablist">
    <button class="nav-link active" role="tab" aria-selected="true" aria-controls="p-overview" id="tab-overview">
      <span class="i18n-zh">1. 全量应用审计榜 ({len(flagged_apps)} 检出 / {len(apps)} 总计)</span>
      <span class="i18n-en">1. Full App Audit ({len(flagged_apps)} Flagged / {len(apps)} Total)</span>
    </button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-identity" id="tab-identity">
      <span class="i18n-zh">2. 五层持久设备身份与穿 VPN 链</span>
      <span class="i18n-en">2. 5-Layer Persistent Identity &amp; VPN Bypass</span>
    </button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-probers" id="tab-probers">
      <span class="i18n-zh">3. URL Scheme 查户口嗅探 ({len(all_probers)})</span>
      <span class="i18n-en">3. URL Scheme App Probing ({len(all_probers)})</span>
    </button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-ats" id="tab-ats">
      <span class="i18n-zh">4. ATS 加密降级与隐秘端点 ({len(layer_ats)})</span>
      <span class="i18n-en">4. ATS Exceptions &amp; Hidden Endpoints ({len(layer_ats)})</span>
    </button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-collusion" id="tab-collusion">
      <span class="i18n-zh">5. 跨应用串通 ({len(shared_groups)}) 与沙盒裸奔 ({len(layer_sandbox)})</span>
      <span class="i18n-en">5. Cross-App Collusion ({len(shared_groups)}) &amp; Sandbox Exposure ({len(layer_sandbox)})</span>
    </button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-method" id="tab-method">
      <span class="i18n-zh">6. 证据分级与方法论局限</span>
      <span class="i18n-en">6. Evidence Grading &amp; Methodology</span>
    </button>
  </div>

  <!-- TAB 1: OVERVIEW -->
  <div id="p-overview" role="tabpanel" aria-labelledby="tab-overview">
    <div class="card"><div class="card-body">
      <h3>
        <span class="i18n-zh">📌 证据分级说明（参考 <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir 证据审计标准</a>）</span>
        <span class="i18n-en">📌 Three-Tier Evidence Grading (Inspired by <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir's Forensic Standard</a>)</span>
      </h3>
      <p class="text-small i18n-zh">
        为避免将「静态配置存在」夸大为「实时作恶实锤」，本报告对每项结论实施严格的三级证据标注，并在下方每条检出项下直接附带<b>「👉 能干什么」大白话解释</b>：<br>
        • <span class="evi evi-seen">【实锤 / VERIFIED】</span>：直接从 Apple 签名二进制 Entitlements、<code>Info.plist</code> 静态白名单或 <code>HouseArrest</code> 沙盒文件系统中提取到的确凿配置与暴露文件。<br>
        • <span class="evi evi-cap">【机制实锤 / CAPABILITY】</span>：应用持有 Apple 官方签发的特殊内核级豁免签名（如 <code>unrestricted-voip-regulatory</code>、<code>HotspotHelper</code>、<code>multipath</code>），具备随时绕过常规沙盒限制的底层能力（具体触发频率取决于服务端下发指令）。<br>
        • <span class="evi evi-inf">【推断 / INFERRED】</span>：基于共享 App Group 容器、Keychain 共享组及第三方风控/广告域名（如 <code>shuzilm.cn</code>、<code>id6.me</code>）的标准 SDK 行为推断其跨应用关联逻辑。
      </p>
      <p class="text-small i18n-en">
        To avoid conflating static capability with active runtime abuse, every finding is graded into 3 forensic tiers with a plain-English <b>"👉 What it does"</b> explanation:<br>
        • <span class="evi evi-seen">[VERIFIED]</span>: Directly extracted from Apple-signed Entitlements, <code>Info.plist</code> static whitelists, or unauthenticated <code>HouseArrest</code> sandbox enumeration.<br>
        • <span class="evi evi-cap">[CAPABILITY]</span>: The app holds an Apple-signed privileged kernel entitlement (<code>unrestricted-voip-regulatory</code>, <code>HotspotHelper</code>, <code>multipath</code>) unlocking the bypass mechanism; trigger frequency depends on server policies.<br>
        • <span class="evi evi-inf">[INFERRED]</span>: Cross-app identity correlation inferred from shared App Group containers, shared Keychain prefixes, and embedded attribution/risk SDK domains.
      </p>
      <details style="margin-top:10px; border-top:1px solid var(--border); padding-top:10px;">
        <summary style="cursor:pointer; font-weight:600; font-size:14px; color:var(--blue);">
          <span class="i18n-zh">📖 看不懂专业术语？点此展开《iOS 底层特权与后台黑话「人话」危害速查词典》</span>
          <span class="i18n-en">📖 Plain-English Glossary: What Do These iOS Entitlements &amp; Background Modes Actually Do?</span>
        </summary>
        <div class="table-responsive" style="margin-top:10px;">
          <table class="table text-small">
            <thead>
              <tr>
                <th><span class="i18n-zh">底层特权 / 标志位名称</span><span class="i18n-en">Entitlement / Plist Key</span></th>
                <th><span class="i18n-zh">大白话解释：它到底能干什么？</span><span class="i18n-en">Plain-Language Explanation: What Can It Do To You?</span></th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>unrestricted-voip-regulatory</code></td>
                <td>
                  <span class="i18n-zh">从 iOS 13 起苹果规定借道语音电话通道唤醒 App 必须弹出全屏来电界面，否则封杀；但持有该特批签名的超级 App（微信/QQ/钉钉），<b>服务器随时可以下发无声指令把你彻底划掉的后台死进程拉活干活，手机屏幕不亮、不响、毫无痕迹</b>。</span>
                  <span class="i18n-en">Since iOS 13, Apple requires VoIP pushes to display a full-screen call UI. Apps holding this undocumented regulatory exemption (WeChat, QQ, DingTalk) <b>can be silently woken from a dead state by their servers 10,000+ times without lighting up or ringing your screen</b>.</span>
                </td>
              </tr>
              <tr>
                <td><code>HotspotHelper</code></td>
                <td>
                  <span class="i18n-zh">本来是给连公共 Wi-Fi 工具用的接口，如果外卖/支付/社交软件持有它，<b>只要你打开系统 Wi-Fi 列表或走过商场，iOS 内核就会自动唤醒它，把周围所有路由器的硬件 MAC 地址 (BSSID) 喂给它——哪怕你关了 GPS 定位，它也能反推出你在哪栋楼哪家店</b>。</span>
                  <span class="i18n-en">Intended for Wi-Fi portal utilities. When held by food-delivery or payment apps, <b>iOS automatically wakes the app whenever Wi-Fi is scanned and feeds it nearby router MAC addresses (BSSIDs) — pinpointing your physical building/floor even with GPS turned off</b>.</span>
                </td>
              </tr>
              <tr>
                <td><code>multipath</code> / <code>network-authentication</code></td>
                <td>
                  <span class="i18n-zh">允许 App 在连着家里 Wi-Fi 或挂着 VPN 代理时，<b>单独强行开启 4G/5G 蜂窝流量网卡直连移动/联通/电信网关</b>，不仅瞬间暴露你的真实 SIM 卡归属地和基站 IP，还能配合运营商网关静默提取你的本机手机号。</span>
                  <span class="i18n-en">Allows an app to <b>force a 4G/5G cellular data connection (<code>pdp_ip0</code>) even while connected to Wi-Fi or a VPN</b>, exposing your real carrier IP and enabling silent SIM phone-number extraction via telecom gateways.</span>
                </td>
              </tr>
              <tr>
                <td><code>ubiquity-kvstore-identifier</code></td>
                <td>
                  <span class="i18n-zh">把唯一设备追踪码偷偷写进你的私人 iCloud 云盘隐藏空间。<b>就算你卸载重装 App，甚至去苹果店买了一台全新 iPhone 登录同一个 Apple ID，它也能在后台秒级认出你还是原来那个人</b>。</span>
                  <span class="i18n-en">Writes unique tracking tokens into your private iCloud key-value storage. <b>Even if you uninstall the app or buy a brand-new iPhone with the same Apple ID, the token automatically syncs back to re-identify you</b>.</span>
                </td>
              </tr>
              <tr>
                <td><code>multicast</code></td>
                <td>
                  <span class="i18n-zh">允许向你家里或公司的 Wi-Fi 发送多播探测包，<b>摸清你家里装了什么牌子的电视、NAS 存储、智能音箱、打印机或路由器</b>，用来精准评估你的家庭消费力与社会关系。</span>
                  <span class="i18n-en">Sends mDNS/SSDP multicast discovery packets across your local Wi-Fi to <b>enumerate smart TVs, NAS servers, speakers, and routers in your home</b>.</span>
                </td>
              </tr>
              <tr>
                <td><code>LSApplicationQueriesSchemes</code></td>
                <td>
                  <span class="i18n-zh">通过向系统挨个询问“能不能打开某个暗号（如 <code>shadowrocket://</code>、<code>binance://</code>、<code>porsche://</code>）”，<b>在不弹窗的情况下摸清你手机里有没有装翻墙软件、境外银行、冷钱包或豪车车企 App</b>。</span>
                  <span class="i18n-en">Hardcodes up to 280+ URL schemes to silently query iOS (without any popup) whether you have <b>VPN apps (<code>shadowrocket</code>), crypto wallets, offshore banks, or luxury car apps installed</b>.</span>
                </td>
              </tr>
              <tr>
                <td><code>UIFileSharingEnabled</code> / <code>HouseArrest</code></td>
                <td>
                  <span class="i18n-zh">App 把内部 <code>/Documents</code> 文件夹直接暴露在外部同步接口下。<b>只要手机插上信任过的电脑（或在同一局域网开启 Wi-Fi 同步），无需解锁 App 或验证 FaceID，1 秒钟就能直接列出甚至拷走里面的密码库、账单 PDF 与本地数据库</b>。</span>
                  <span class="i18n-en">Exposes the app's <code>/Documents</code> container over USB and local Wi-Fi sync. <b>Any previously trusted computer can list and copy its files (.kdbx vaults, bank PDFs, SQLite logs) in 1 second without FaceID</b>.</span>
                </td>
              </tr>
              <tr>
                <td><code>NSExceptionDomains</code></td>
                <td>
                  <span class="i18n-zh">苹果默认强制所有请求走安全 HTTPS；如果开发者在配置里专门点名某些域名允许明文 HTTP 或忽略证书校验，<b>顺藤摸瓜就能直接抓出它内部接入的第三方设备指纹库（如数字联盟 <code>shuzilm.cn</code>）、商业广告网（如秒针 <code>miaozhen.com</code>）甚至残留的热更新后门（<code>jspatch.com</code>）</b>。</span>
                  <span class="i18n-en">Domains where developers explicitly bypass Apple's HTTPS App Transport Security — <b>directly exposing embedded device-DNA SDKs (<code>shuzilm.cn</code>), ad-tech trackers (<code>miaozhen.com</code>), or hot-patching backdoors (<code>jspatch.com</code>)</b>.</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </div></div>

    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin:16px 0 8px;">
      <h3 style="margin:0;">
        <span class="i18n-zh">🔥 全量应用隐私越界与隐秘后门审计表（共 {len(apps)} 款，检出权限/后台/嗅探行为 {len(flagged_apps)} 款）</span>
        <span class="i18n-en">🔥 Full App Privacy &amp; Entitlement Audit Table ({len(flagged_apps)} Flagged / {len(apps)} Total Installed)</span>
      </h3>
      <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <input id="app-search" type="search" placeholder="🔍 Search app / Bundle ID / entitlement / domain..." style="padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--card); color:var(--foreground); min-width:260px; font-size:13.5px;">
        <label class="text-small" style="cursor:pointer; user-select:none;">
          <input type="checkbox" id="only-flagged" checked>
          <span class="i18n-zh">仅显示检出特权/后台/嗅探项 ({len(flagged_apps)} 款)</span>
          <span class="i18n-en">Show only flagged apps ({len(flagged_apps)})</span>
        </label>
      </div>
    </div>
    <div class="table-responsive">
      <table class="table" id="audit-table">
        <thead>
          <tr>
            <th class="text-end">#</th>
            <th class="text-end"><span class="i18n-zh">风险分</span><span class="i18n-en">Score</span></th>
            <th><span class="i18n-zh">应用名称 / Bundle ID</span><span class="i18n-en">App Name / Bundle ID</span></th>
            <th><span class="i18n-zh">后台/嗅探/插件</span><span class="i18n-en">BG / Probes / Plugins</span></th>
            <th><span class="i18n-zh">检出的底层特权与硬编码证据（全量无截断，含证据等级与人话解释）</span><span class="i18n-en">Detected Privileged Entitlements &amp; Hardcoded Evidence (Full List + Plain-English Impact)</span></th>
          </tr>
        </thead>
        <tbody>
          {"".join(top_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 2: 5-LAYER PERSISTENT IDENTITY -->
  <div id="p-identity" role="tabpanel" aria-labelledby="tab-identity" hidden>
    <h3>
      <span class="i18n-zh">🧬 五层持久设备身份链与穿 VPN 路径分析</span>
      <span class="i18n-en">🧬 The 5-Layer Persistent Device Identity &amp; VPN-Bypass Chain</span>
    </h3>
    <p class="text-muted text-small i18n-zh">为什么在 iOS 上「关闭广告追踪 (IDFA) + 开启 VPN + 卸载重装 App」依然无法阻止国内大厂与风控 SDK 精准识别同一台物理手机？以下为本机实测检出的五层硬件/系统级锚点（全量列出）：</p>
    <p class="text-muted text-small i18n-en">Why does disabling IDFA, turning on a VPN, and reinstalling an app still fail to prevent cross-app device tracking on stock iOS? Below are the 5 hardware/OS-level persistence layers detected on this device:</p>

    <div class="card"><div class="card-body">
      <h4>
        <span class="i18n-zh">第 1 层：跨设备、防恢复出厂的「iCloud 云端隐藏烙印」（全量检出 {len(layer_icloud)} 款） <span class="evi evi-seen">【实锤】</span></span>
        <span class="i18n-en">Layer 1: Uninstall- &amp; New-iPhone-Proof iCloud KVS Tokens ({len(layer_icloud)} Apps) <span class="evi evi-seen">[VERIFIED]</span></span>
      </h4>
      <p class="text-small i18n-zh">持有 <code>com.apple.developer.ubiquity-kvstore-identifier</code> 签名的应用可将唯一设备 Token 写入用户私人 iCloud KVS 云空间。<b>即便卸载重装 App，甚至购买新 iPhone 登录同一 Apple ID，该追踪烙印也会在后台秒级同步恢复。</b></p>
      <p class="text-small i18n-en">Apps holding <code>com.apple.developer.ubiquity-kvstore-identifier</code> write persistent tracking tokens into your private iCloud Key-Value Store. <b>Even if you uninstall the app or migrate to a brand-new iPhone on the same Apple ID, the tracking token automatically syncs back.</b></p>
      <p class="text-small"><b><span class="i18n-zh">本机检出全部应用：</span><span class="i18n-en">All Detected Apps: </span></b> {", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_icloud)}</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>
        <span class="i18n-zh">第 2 层：防卸载的「同厂商钥匙串持久化 (`keychain-access-groups`)」（全量检出 {len(shared_keychains)} 个跨应用钥匙串前缀） <span class="evi evi-seen">【实锤】</span></span>
        <span class="i18n-en">Layer 2: Uninstall-Proof Shared Keychain Groups ({len(shared_keychains)} Shared Prefixes) <span class="evi evi-seen">[VERIFIED]</span></span>
      </h4>
      <p class="text-small i18n-zh">iOS 系统级特性：应用写入 Keychain 的数据在<b>卸载 App 后依然永久保留在系统钥匙串数据库中</b>；且同一开发者 Team ID 下的多款应用可共享同一 Keychain 组。重装或安装同系新 App 时瞬间恢复老设备身份 ID。</p>
      <p class="text-small i18n-en">On iOS, Keychain entries <b>persist permanently even after the app is uninstalled</b>, and apps signed by the same developer Team ID can share Keychain groups to immediately re-link your device identity upon reinstall.</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>
        <span class="i18n-zh">第 3 层：跨应用沙盒串通池 (`com.apple.security.application-groups`)（全量检出 {summary['shared_app_groups_count']} 个多应用共享池） <span class="evi evi-seen">【实锤】</span></span>
        <span class="i18n-en">Layer 3: Cross-App Sandbox Collusion Pools ({summary['shared_app_groups_count']} Multi-App Groups) <span class="evi evi-seen">[VERIFIED]</span></span>
      </h4>
      <p class="text-small i18n-zh">只要同一集团矩阵（如阿里系、腾讯系、字节系、Google 系、Meta 系）中有<b>任意 1 款</b>应用留在手机上，共享容器 <code>group.*</code> 内的设备指纹与会话文件就不会被系统清理。</p>
      <p class="text-small i18n-en">As long as <b>any single sister app</b> from the same corporate family remains installed on your iPhone, shared <code>group.*</code> container files and device DNA fingerprints remain intact across uninstalls.</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>
        <span class="i18n-zh">第 4 层：绕过 Wi-Fi 与普通 VPN 的「蜂窝基站直连通道」（全量检出 {len(layer_multipath)} 款） <span class="evi evi-cap">【机制实锤】</span></span>
        <span class="i18n-en">Layer 4: Cellular Gateway VPN Bypass (`multipath` / `network-authentication`) ({len(layer_multipath)} Apps) <span class="evi evi-cap">[CAPABILITY]</span></span>
      </h4>
      <p class="text-small i18n-zh">持有 <code>com.apple.developer.networking.multipath</code> 或 <code>network-authentication</code> 特权的应用，可在连接 Wi-Fi 或开启代理时，强行指定底层 Socket 绑定蜂窝数据网卡 (<code>pdp_ip0</code>) 直连三大运营商网关（<code>cmpassport.com</code> / <code>wostore.cn</code> / <code>id6.me</code>），不仅暴露真实 SIM 卡归属地与基站出口 IP，还可配合网关完成本机号码校验。</p>
      <p class="text-small i18n-en">Apps holding <code>multipath</code> or <code>network-authentication</code> can bind sockets directly to the cellular interface (<code>pdp_ip0</code>) even while on Wi-Fi or VPN — exposing real carrier IP and hitting telecom gateways (<code>cmpassport.com</code>, <code>wostore.cn</code>, <code>id6.me</code>) for silent SIM/phone-number authentication.</p>
      <p class="text-small"><b><span class="i18n-zh">本机检出全部应用：</span><span class="i18n-en">All Detected Apps: </span></b> {", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_multipath)}</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>
        <span class="i18n-zh">第 5 层：无视定位开关的「物理空间锚点」（Wi-Fi BSSID 钩子 {len(layer_hotspot)} 款 / 局域网多播探测） <span class="evi evi-cap">【机制实锤】</span></span>
        <span class="i18n-en">Layer 5: GPS-Free Physical Location Anchors ({len(layer_hotspot)} `HotspotHelper` Apps) <span class="evi evi-cap">[CAPABILITY]</span></span>
      </h4>
      <p class="text-small i18n-zh">即使关闭 GPS 定位权限，持有 <code>HotspotHelper</code> 的应用（{", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_hotspot)}）也能在系统扫描 Wi-Fi 时获取周边路由器硬件 MAC 地址（BSSID），结合云端 Wi-Fi 地理库即可反推精确到楼层的物理位置。</p>
      <p class="text-small i18n-en">Even with GPS permission denied, apps holding <code>HotspotHelper</code> ({", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_hotspot)}) receive nearby Wi-Fi router hardware MAC addresses (BSSIDs) whenever iOS scans Wi-Fi networks, enabling floor-level physical geolocation.</p>
    </div></div>
  </div>

  <!-- TAB 3: URL SCHEME PROBERS -->
  <div id="p-probers" role="tabpanel" aria-labelledby="tab-probers" hidden>
    <h3>
      <span class="i18n-zh">🕵️ URL Scheme “查户口式”已安装应用嗅探榜（共 {len(all_probers)} 款）</span>
      <span class="i18n-en">🕵️ Installed-App URL Scheme Probing (`LSApplicationQueriesSchemes`) ({len(all_probers)} Apps)</span>
    </h3>
    <p class="text-muted text-small i18n-zh">iOS 9+ 规定应用必须在 <code>Info.plist</code> 的 <code>LSApplicationQueriesSchemes</code> 中静态声明要探测的 URL Scheme，才能调用 <code>canOpenURL:</code> 判断用户是否安装了目标软件（如小火箭 <code>shadowrocket</code>、海外银行、加密钱包、豪车 App）。此表为 100% 静态实锤证据：</p>
    <p class="text-muted text-small i18n-en">Since iOS 9, apps must statically declare every URL scheme they wish to probe via <code>canOpenURL:</code> inside <code>Info.plist</code> (<code>LSApplicationQueriesSchemes</code>). This table provides 100% verified static proof of which apps each developer is probing for:</p>
    <div class="table-responsive">
      <table class="table">
        <thead>
          <tr>
            <th><span class="i18n-zh">应用名称 / Bundle ID</span><span class="i18n-en">App Name / Bundle ID</span></th>
            <th class="text-end"><span class="i18n-zh">嗅探暗号数量</span><span class="i18n-en">Queried Schemes</span></th>
            <th><span class="i18n-zh">声明探测的全部 URL Schemes 清单</span><span class="i18n-en">Full List of Declared URL Schemes</span></th>
            <th><span class="i18n-zh">证据等级</span><span class="i18n-en">Evidence</span></th>
          </tr>
        </thead>
        <tbody>
          {"".join(prober_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 4: ATS EXCEPTIONS -->
  <div id="p-ats" role="tabpanel" aria-labelledby="tab-ats" hidden>
    <h3>
      <span class="i18n-zh">🌐 ATS 加密降级与硬编码隐秘端点 (`NSExceptionDomains`)</span>
      <span class="i18n-en">🌐 ATS HTTPS-Downgrade Exceptions &amp; Hardcoded Endpoints (`NSExceptionDomains`)</span>
    </h3>
    <p class="text-muted text-small i18n-zh">苹果强制要求 App 默认使用安全 HTTPS (App Transport Security)。如果开发者在 <code>Info.plist</code> 中专门为特定域名配置了 <code>NSExceptionDomains</code>（允许明文 HTTP 或忽略证书校验），往往直接暴露出其底层接入的<b>第三方设备指纹库（如数字联盟 <code>shuzilm.cn</code>）、运营商取号网关（<code>id6.me</code> / <code>wo.cn</code>）、历史遗留热更新后门（<code>jspatch.com</code>）或商业广告监测网（秒针 <code>miaozhen.com</code>）</b>：</p>
    <p class="text-muted text-small i18n-en">Apple enforces HTTPS by default via App Transport Security (ATS). When developers explicitly declare <code>NSExceptionDomains</code> in <code>Info.plist</code> to allow cleartext HTTP or custom trust, they inadvertently reveal embedded <b>device-DNA trackers (<code>shuzilm.cn</code>), carrier auth gateways (<code>id6.me</code>, <code>wo.cn</code>), legacy hot-patch backdoors (<code>jspatch.com</code>), and ad-tech networks (<code>miaozhen.com</code>)</b>:</p>
    <div class="table-responsive">
      <table class="table">
        <thead>
          <tr>
            <th><span class="i18n-zh">应用名称 / Bundle ID</span><span class="i18n-en">App Name / Bundle ID</span></th>
            <th class="text-end"><span class="i18n-zh">豁免域名数</span><span class="i18n-en">Domains Count</span></th>
            <th><span class="i18n-zh">静态抽取的 NSExceptionDomains 域名清单</span><span class="i18n-en">Statically Extracted NSExceptionDomains</span></th>
            <th><span class="i18n-zh">证据等级</span><span class="i18n-en">Evidence</span></th>
          </tr>
        </thead>
        <tbody>
          {"".join(ats_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 5: COLLUSION & SANDBOX -->
  <div id="p-collusion" role="tabpanel" aria-labelledby="tab-collusion" hidden>
    <h3>
      <span class="i18n-zh">🔗 跨应用共享容器串通池 (`com.apple.security.application-groups`)</span>
      <span class="i18n-en">🔗 Cross-App Shared Storage Pools (`com.apple.security.application-groups`)</span>
    </h3>
    <div class="table-responsive">
      <table class="table">
        <thead>
          <tr>
            <th><span class="i18n-zh">共享容器 ID (App Group)</span><span class="i18n-en">Shared Container ID (App Group)</span></th>
            <th class="text-end"><span class="i18n-zh">共谋应用数</span><span class="i18n-en">Apps Count</span></th>
            <th><span class="i18n-zh">共享该底层读写池的应用列表</span><span class="i18n-en">Apps Sharing This Read/Write Pool</span></th>
            <th><span class="i18n-zh">证据等级</span><span class="i18n-en">Evidence</span></th>
          </tr>
        </thead>
        <tbody>
          {"".join(group_rows_html)}
        </tbody>
      </table>
    </div>

    <h3 style="margin-top:28px;">
      <span class="i18n-zh">💣 免 FaceID 通过 USB / 局域网 Wi-Fi 直接裸露的沙盒目录 (`HouseArrest`)</span>
      <span class="i18n-en">💣 Unauthenticated USB / Wi-Fi Sandbox Exposure (`HouseArrest`)</span>
    </h3>
    <p class="text-muted text-small i18n-zh">以下应用在 <code>Info.plist</code> 中开启了 <code>UIFileSharingEnabled</code> 或 <code>LSSupportsOpeningDocumentsInPlace</code>。任何曾点击过「信任此电脑」的主机（或开启 Wi-Fi 同步后的同一局域网主机）无需解锁 App 或验证 FaceID，即可直接通过苹果原生 <code>HouseArrest</code> 协议读取甚至拷走其 <code>/Documents</code> 容器内的全部文件：</p>
    <p class="text-muted text-small i18n-en">These apps enabled <code>UIFileSharingEnabled</code> or <code>LSSupportsOpeningDocumentsInPlace</code>. Any paired computer over USB (or local Wi-Fi sync) can directly list and copy all files inside their <code>/Documents</code> sandbox container via Apple's <code>HouseArrest</code> service without FaceID:</p>
    <div class="table-responsive">
      <table class="table">
        <thead>
          <tr>
            <th><span class="i18n-zh">应用名称 / Bundle ID</span><span class="i18n-en">App Name / Bundle ID</span></th>
            <th class="text-end"><span class="i18n-zh">裸露文件/目录数</span><span class="i18n-en">Exposed Entries</span></th>
            <th><span class="i18n-zh">实测可直接枚举的顶层文件样本 {'(已启用 --redact 脱敏)' if redact else ''}</span><span class="i18n-en">Top-Level Exposed Files {'(Redacted via --redact)' if redact else ''}</span></th>
            <th><span class="i18n-zh">证据等级</span><span class="i18n-en">Evidence</span></th>
          </tr>
        </thead>
        <tbody>
          {"".join(sandbox_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 6: METHODOLOGY & LIMITATIONS -->
  <div id="p-method" role="tabpanel" aria-labelledby="tab-method" hidden>
    <div class="card"><div class="card-body">
      <h3>
        <span class="i18n-zh">🔬 取证方法论（未越狱 iOS 设备）</span>
        <span class="i18n-en">🔬 Forensic Methodology (Non-Jailbroken Stock iOS)</span>
      </h3>
      <ol class="text-small i18n-zh">
        <li><b>Lockdown &amp; InstallationProxy 全量元数据穿透</b>：通过 <code>usbmuxd</code> 建立配对通道，枚举全机所有用户态与系统态 Bundle 的完整属性字典、Apple 签名 <code>Entitlements</code> 权限树、<code>Info.plist</code> 静态声明与 App Extension 插件拓扑。</li>
        <li><b>HouseArrest 沙盒容器可访问性实测</b>：对声明文件共享的容器逐一发起非破坏性只读挂载测试，统计无需生物识别即可在外部直接枚举的敏感数据文件。</li>
        <li><b>OsTrace 实时内核日志流雷达</b>：通过 <code>ios_noir.py radar</code> 实时订阅 <code>tccd</code>（隐私权限仲裁守护进程）、<code>cameracaptured</code>、<code>locationd</code> 与 <code>lsd</code>，毫秒级捕获运行时权限预检与传感器探针。</li>
      </ol>
      <ol class="text-small i18n-en">
        <li><b>Lockdown &amp; InstallationProxy Metadata Extraction</b>: Connects over <code>usbmuxd</code> to enumerate all installed user bundles, Apple-signed Mach-O <code>Entitlements</code>, <code>Info.plist</code> declarations, and App Extension topologies.</li>
        <li><b>HouseArrest Sandbox Container Audit</b>: Performs non-destructive read-only directory enumeration against containers with file-sharing enabled to verify unauthenticated exposure.</li>
        <li><b>OsTrace Real-Time Kernel Syslog Radar</b>: Subscribes to <code>tccd</code>, <code>cameracaptured</code>, <code>locationd</code>, and <code>lsd</code> via <code>ios_noir.py radar</code> to capture live permission preflights and sensor probes.</li>
      </ol>
    </div></div>

    <div class="card"><div class="card-body">
      <h3>
        <span class="i18n-zh">⚖️ 方法论局限与严谨性边界（必读）</span>
        <span class="i18n-en">⚖️ Methodology Limitations &amp; Forensic Boundaries</span>
      </h3>
      <ol class="text-small i18n-zh">
        <li><b>未越狱 FairPlay 壳限制</b>：未越狱设备上的 App Store 二进制受 Apple FairPlay DRM 硬件加密保护，本工具不进行脱壳或 Ghidra 反编译；如需针对单款已脱壳 IPA 进行函数级反编译与字符串交叉引用，请参考并结合 <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir/claude-ios-privacy-analysis</a> 的 Ghidra 自动化管线。</li>
        <li><b>特权存在性【机制实锤】 ≠ 全天候触发【实锤】</b>：应用持有 <code>unrestricted-voip-regulatory</code> 或 <code>HotspotHelper</code> 证明苹果官方为其签发了突破常规限制的底层准入证，但是否在特定时刻下发静默唤醒或上报 BSSID 取决于服务端指令与运行时逻辑。</li>
        <li><b>ATS 豁免域名 ≠ 当前活跃抓包流量</b>：<code>NSExceptionDomains</code> 中的域名（如 <code>jspatch.com</code>、<code>shuzilm.cn</code>）为开发者在 <code>Info.plist</code> 中显式声明的白名单，部分可能是历史遗留配置或按条件触发的备用通道。</li>
      </ol>
      <ol class="text-small i18n-en">
        <li><b>FairPlay DRM Boundary on Stock iOS</b>: App Store binaries on non-jailbroken devices are FairPlay-encrypted. <code>iOS-NOIR</code> audits whole-device entitlements, plists, sandbox containers, and kernel telemetry without decrypting Mach-O code sections. For function-level Ghidra decompilation of decrypted IPAs, combine with <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir/claude-ios-privacy-analysis</a>.</li>
        <li><b>Capability ([CAPABILITY]) ≠ Continuous Runtime Trigger ([VERIFIED])</b>: Holding an Apple-signed entitlement proves the kernel bypass is unlocked, whereas actual trigger frequency depends on server-side push commands.</li>
        <li><b>Static ATS Domains ≠ Live Traffic</b>: Domains in <code>NSExceptionDomains</code> are statically declared developer exceptions in <code>Info.plist</code>; some may be legacy or conditional endpoints.</li>
      </ol>
    </div></div>
  </div>
</div>

<script>
(function () {{
  var tabs = document.querySelectorAll('.nav-link[role="tab"]');
  tabs.forEach(function (t) {{
    t.addEventListener('click', function () {{
      tabs.forEach(function (x) {{
        x.classList.remove('active');
        x.setAttribute('aria-selected', 'false');
        var p = document.getElementById(x.getAttribute('aria-controls'));
        if (p) p.hidden = true;
      }});
      t.classList.add('active');
      t.setAttribute('aria-selected', 'true');
      var panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.hidden = false;
    }});
  }});

  var langBtns = document.querySelectorAll('.lang-btn[data-set-lang]');
  langBtns.forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      var lang = btn.getAttribute('data-set-lang');
      document.documentElement.setAttribute('data-lang', lang);
      document.documentElement.setAttribute('lang', lang);
      langBtns.forEach(function (b) {{
        b.classList.toggle('active', b.getAttribute('data-set-lang') === lang);
      }});
    }});
  }});

  var searchInput = document.getElementById('app-search');
  var onlyFlagged = document.getElementById('only-flagged');
  function filterRows() {{
    var q = (searchInput ? searchInput.value : '').toLowerCase().trim();
    var flaggedOnly = onlyFlagged ? onlyFlagged.checked : false;
    var rows = document.querySelectorAll('#audit-table tbody tr.audit-row');
    rows.forEach(function (r) {{
      var score = parseInt(r.getAttribute('data-score') || '0', 10);
      var text = r.textContent.toLowerCase();
      var matchQuery = !q || text.indexOf(q) !== -1;
      var matchFlag = !flaggedOnly || score > 0 || text.indexOf('clean') === -1;
      r.style.display = (matchQuery && matchFlag) ? '' : 'none';
    }});
  }}
  if (searchInput) searchInput.addEventListener('input', filterRows);
  if (onlyFlagged) onlyFlagged.addEventListener('change', filterRows);
  filterRows();
}})();
</script>
</body>
</html>
"""


async def run_scan(output_dir: Path, redact: bool = False, check_sandbox: bool = True, lang: str = "zh"):
    is_en = lang == "en"
    console.print(BANNER_EN if is_en else BANNER_ZH)
    output_dir.mkdir(parents=True, exist_ok=True)

    lockdown = await create_using_usbmux()
    vals = lockdown.all_values
    dev_name = "iPhone (Redacted)" if redact else vals.get("DeviceName", "iPhone")
    ios_ver = vals.get("ProductVersion", "Unknown")
    model = vals.get("ModelNumber", "")
    region = vals.get("RegionInfo", "")

    console.print(
        Panel(
            f"📱 Device: [bold cyan]{dev_name}[/bold cyan] | OS: [bold green]iOS {ios_ver}[/bold green] | Hardware Region: [bold yellow]{model} ({region})[/bold yellow]",
            title="iOS-NOIR Doctor",
            border_style="bright_blue",
        )
    )

    async with InstallationProxyService(lockdown=lockdown) as iproxy:
        apps = await iproxy.get_apps(application_type="User", calculate_sizes=False)

    results = []
    app_groups_map = defaultdict(list)
    keychain_map = defaultdict(list)
    url_scheme_owners = defaultdict(list)
    all_ats_domains = set()

    for bid, info in apps.items():
        name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or bid
        version = info.get("CFBundleShortVersionString", "")
        ent = info.get("Entitlements", {}) or {}
        bg_modes = info.get("UIBackgroundModes", []) or []
        if isinstance(bg_modes, str):
            bg_modes = [bg_modes]
        queried_schemes = info.get("LSApplicationQueriesSchemes", []) or []
        file_sharing = bool(info.get("UIFileSharingEnabled", False))
        open_in_place = bool(info.get("LSSupportsOpeningDocumentsInPlace", False))
        plugins = info.get("PluginKitPlugins", {}) or {}

        score = 0
        findings_zh = []
        findings_en = []

        for k, (label_zh, label_en, pts, _tier, _exp_zh, _exp_en) in HIGH_RISK_ENTITLEMENTS.items():
            if ent.get(k):
                score += pts
                findings_zh.append(label_zh)
                findings_en.append(label_en)

        groups = ent.get("com.apple.security.application-groups", []) or []
        if isinstance(groups, str):
            groups = [groups]
        for g in groups:
            app_groups_map[g].append(f"{name} ({bid})")

        kcs = ent.get("keychain-access-groups", []) or []
        if isinstance(kcs, str):
            kcs = [kcs]
        for kc in kcs:
            keychain_map[kc].append(f"{name} ({bid})")

        for ut in info.get("CFBundleURLTypes", []) or []:
            if isinstance(ut, dict):
                for s in ut.get("CFBundleURLSchemes", []) or []:
                    url_scheme_owners[str(s).lower()].append(f"{name} ({bid})")

        score += len(bg_modes) * 4
        if len(queried_schemes) >= 20:
            score += min(30, len(queried_schemes) // 2)

        exposed_files = []
        if check_sandbox and (file_sharing or open_in_place):
            try:
                ha = await HouseArrestService.create(
                    lockdown=lockdown, bundle_id=bid, documents_only=True
                )
                items = await ha.listdir("/Documents")
                exposed_files = [
                    x for x in items if x not in (".", "..", ".com.apple.mobile_container_manager.metadata.plist")
                ]
                await ha.close()
            except Exception:
                pass

        if file_sharing or open_in_place:
            score += 15
            if exposed_files:
                score += 10
                findings_zh.append(
                    f"📂 [实锤] 免FaceID暴露USB/Wi-Fi沙盒目录 ({len(exposed_files)} 个裸露文件)"
                )
                findings_en.append(
                    f"📂 [VERIFIED] Unauthenticated USB/Wi-Fi Sandbox Exposure ({len(exposed_files)} exposed files)"
                )
            else:
                findings_zh.append("📂 [实锤] 开启USB/Wi-Fi沙盒共享 (UIFileSharingEnabled)")
                findings_en.append("📂 [VERIFIED] USB/Wi-Fi File Sharing Enabled (UIFileSharingEnabled)")

        ats = info.get("NSAppTransportSecurity", {}) or {}
        exc_domains = []
        if isinstance(ats, dict):
            doms = ats.get("NSExceptionDomains", {}) or {}
            if isinstance(doms, dict):
                exc_domains = list(doms.keys())
                all_ats_domains.update(exc_domains)
        if exc_domains:
            score += min(25, len(exc_domains) * 5)

        results.append(
            {
                "bundle_id": bid,
                "name": name,
                "version": version,
                "score": score,
                "bg_modes": bg_modes,
                "queried_schemes": queried_schemes,
                "findings": findings_zh,
                "findings_en": findings_en,
                "ats_exception_domains": exc_domains,
                "app_groups": groups,
                "keychain_groups": kcs,
                "extensions_count": len(plugins),
                "file_sharing": file_sharing or open_in_place,
                "exposed_files_count": len(exposed_files),
                "exposed_files_sample": (
                    [f"<redacted_{i}>" for i in range(len(exposed_files))]
                    if redact
                    else exposed_files[:20]
                ),
                "has_icloud_kvs": bool(ent.get("com.apple.developer.ubiquity-kvstore-identifier")),
                "has_multipath": bool(ent.get("com.apple.developer.networking.multipath")),
                "has_net_auth": bool(
                    ent.get("com.apple.developer.CellularNetwork.network-authentication")
                ),
                "has_hotspot_helper": bool(ent.get("com.apple.developer.networking.HotspotHelper")),
                "has_unrestricted_voip": bool(
                    ent.get("com.apple.developer.pushkit.unrestricted-voip-regulatory")
                    or ent.get("com.apple.developer.pushkit.unrestricted-voip")
                ),
            }
        )

    results.sort(key=lambda x: x["score"], reverse=True)

    flagged_results = [
        r for r in results
        if r["score"] > 0 or r["findings"] or r["ats_exception_domains"]
    ]
    t = Table(
        title=(
            f"🚨 iOS-NOIR Full Privacy & Entitlement Audit ({len(flagged_results)} / {len(results)} Apps Flagged)"
            if is_en
            else f"🚨 iOS-NOIR 隐私越界与隐秘后门全量检出榜 (共检出 {len(flagged_results)} / {len(results)} 款应用)"
        ),
        box=box.ROUNDED,
        show_lines=True,
    )
    t.add_column("Score" if is_en else "风险分", style="bold red", justify="right", width=6)
    t.add_column("App Name / Bundle ID" if is_en else "应用名称 / Bundle ID", style="bold white", width=28)
    t.add_column("BG / Probes" if is_en else "后台/嗅探", style="yellow", width=16)
    t.add_column(
        "Detected Privileged Entitlements & Evidence" if is_en else "检出的底层特权与硬编码证据 (附证据分级)",
        style="cyan",
    )

    for r in flagged_results:
        flist = r["findings_en"] if is_en else r["findings"]
        fallback = "[dim]Background / URL Scheme Probing[/dim]" if is_en else "[dim]后台常驻 / URL 嗅探[/dim]"
        desc = "\n".join(flist) if flist else fallback
        if r["ats_exception_domains"]:
            dom_preview = ", ".join(r["ats_exception_domains"][:6])
            ats_lbl = "[VERIFIED] ATS Exceptions" if is_en else "[实锤] ATS豁免域"
            desc += f"\n[magenta]🎯 {ats_lbl}: {dom_preview}[/magenta]"
        bg_lbl = f"BG:{len(r['bg_modes'])} | Probes:{len(r['queried_schemes'])}" if is_en else f"后台:{len(r['bg_modes'])} | 嗅探:{len(r['queried_schemes'])}"
        t.add_row(
            str(r["score"]),
            f"{r['name']}\n[dim]{r['bundle_id']}[/dim]",
            bg_lbl,
            desc,
        )
    console.print(t)

    shared_groups = {k: v for k, v in app_groups_map.items() if len(v) >= 2}
    shared_kcs = {k: v for k, v in keychain_map.items() if len(v) >= 2}
    scheme_collisions = {k: v for k, v in url_scheme_owners.items() if len(v) >= 2}

    t2 = Table(
        title=(
            f"🔗 Cross-App Shared Storage Pools ({len(shared_groups)} App Groups)"
            if is_en
            else f"🔗 跨 App 共享数据池 (突破沙盒暗中串通容器 共 {len(shared_groups)} 组)"
        ),
        box=box.SIMPLE_HEAVY,
    )
    t2.add_column("Shared Container ID (App Group)" if is_en else "共享容器 ID (App Group)", style="bold magenta", width=38)
    t2.add_column("Colluding Apps" if is_en else "同伙应用列表", style="white")
    for g, members in sorted(shared_groups.items(), key=lambda x: len(x[1]), reverse=True):
        t2.add_row(g, "、".join(members))
    console.print(t2)

    exposed_apps = [r for r in results if r["exposed_files_count"] > 0]
    if exposed_apps:
        t3 = Table(
            title=(
                f"💣 Unauthenticated USB/Wi-Fi Sandbox Exposure (HouseArrest) [VERIFIED] ({len(exposed_apps)} Apps)"
                if is_en
                else f"💣 免 FaceID 通过 USB/Wi-Fi 直接裸奔可读的沙盒目录 (HouseArrest) [实锤] (共 {len(exposed_apps)} 款)"
            ),
            box=box.ROUNDED,
            show_lines=True,
        )
        t3.add_column("App Name" if is_en else "应用名称", style="bold red", width=26)
        t3.add_column("Exposed Files" if is_en else "暴露文件数", style="bold yellow", justify="right", width=12)
        t3.add_column("Sample Exposed Files (--redact supported)" if is_en else "直接可读文件样本 (--redact 可脱敏)", style="white")
        for r in exposed_apps:
            t3.add_row(
                f"{r['name']}\n[dim]{r['bundle_id']}[/dim]",
                str(r["exposed_files_count"]),
                ", ".join(r["exposed_files_sample"][:10]),
            )
        console.print(t3)

    report_data = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device": {
            "name": dev_name,
            "ios_version": ios_ver,
            "model": model,
            "region": region,
        },
        "summary": {
            "total_user_apps": len(results),
            "high_risk_apps": sum(1 for r in results if r["score"] >= 80),
            "shared_app_groups_count": len(shared_groups),
            "shared_keychains_count": len(shared_kcs),
            "exposed_sandbox_apps_count": len(exposed_apps),
            "total_ats_exception_domains": len(all_ats_domains),
        },
        "apps": results,
        "shared_app_groups": shared_groups,
        "shared_keychains": shared_kcs,
        "scheme_collisions": scheme_collisions,
    }

    report_path = output_dir / "audit_report.json"
    domains_path = output_dir / "ats_exception_domains.txt"
    html_path = output_dir / "ios-noir-report.html"

    report_path.write_text(json.dumps(report_data, ensure_ascii=False, indent=2))
    domains_path.write_text("\n".join(sorted(all_ats_domains)))
    html_path.write_text(build_html_report(report_data, redact=redact, default_lang=lang), encoding="utf-8")

    console.print(
        Panel(
            (
                f"✅ Audit complete! Outputs saved to:\n"
                f"  • Interactive Bilingual HTML Report (ZH/EN switchable): [bold bright_green]{html_path}[/bold bright_green]\n"
                f"  • Structured JSON Report: [bold green]{report_path}[/bold green]\n"
                f"  • Extracted ATS Exception Domains ({len(all_ats_domains)}): [bold yellow]{domains_path}[/bold yellow]"
            )
            if is_en
            else (
                f"✅ 扫描完成！产出已保存至:\n"
                f"  • 中英双语交互式 HTML 报告 (右上角一键切中/英文): [bold bright_green]{html_path}[/bold bright_green]\n"
                f"  • 结构化审计报告: [bold green]{report_path}[/bold green]\n"
                f"  • 静态抽取的后门/豁免域名集 ({len(all_ats_domains)} 个): [bold yellow]{domains_path}[/bold yellow]"
            ),
            border_style="green",
        )
    )


async def run_radar(duration: int = 30, lang: str = "zh"):
    is_en = lang == "en"
    console.print(BANNER_EN if is_en else BANNER_ZH)
    lockdown = await create_using_usbmux()
    console.print(
        Panel(
            (
                f"📡 [bold red]iOS-NOIR Live Privacy Radar started (listening for {duration}s)...[/bold red]\n"
                "Open any app on your iPhone now to watch real-time TCC permission preflights & sensor probes!"
            )
            if is_en
            else (
                f"📡 [bold red]iOS-NOIR 实时隐私抓现行雷达已启动 (监听 {duration} 秒)...[/bold red]\n"
                "现在请在手机上点开任意你想测试的 App，观察它毫秒级触发的底层传感器与权限请求！"
            ),
            border_style="red",
        )
    )

    keywords = re.compile(
        r"(tccd|kTCCService|Pasteboard|AudioUnit|AVCapture|CLLocation|Contacts|Photos|"
        r"HotspotHelper|NEHelper|PushKit|CallKit|sysctl|canOpenURL|advertisingIdentifier|IDFA)",
        re.IGNORECASE,
    )
    loop = asyncio.get_event_loop()
    start = loop.time()

    async with OsTraceService(lockdown=lockdown) as ostrace:
        async for entry in ostrace.syslog():
            if loop.time() - start > duration:
                break
            msg = getattr(entry, "message", "") or ""
            proc = getattr(entry, "filename", "") or getattr(entry, "image_name", "") or ""
            label = ""
            if getattr(entry, "label", None):
                label = f"{entry.label.subsystem}:{entry.label.category}"

            if keywords.search(msg) or keywords.search(proc) or keywords.search(label):
                if "runningboardd" in proc and "tccd" not in msg:
                    continue
                ts = entry.timestamp.strftime("%H:%M:%S.%f")[:-3]
                console.print(
                    f"[dim]{ts}[/dim] [bold yellow]{proc}[/bold yellow] ([cyan]{label}[/cyan]): {msg[:200]}"
                )


def main():
    parser = argparse.ArgumentParser(
        prog="ios-noir",
        description="iOS-NOIR: Local-First iPhone Privacy, Entitlements, Sandbox & Telemetry Auditor",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run full static & sandbox privacy audit")
    scan_parser.add_argument(
        "-o", "--output", default="noir-out", help="Output directory for JSON/HTML reports (default: noir-out)"
    )
    scan_parser.add_argument(
        "--redact", action="store_true", help="Redact device name and exposed filenames for screenshots"
    )
    scan_parser.add_argument(
        "--no-sandbox", action="store_true", help="Skip HouseArrest /Documents sandbox inspection"
    )
    scan_parser.add_argument(
        "--lang", choices=["zh", "en"], default="zh", help="Terminal & default HTML report language (zh or en)"
    )

    radar_parser = subparsers.add_parser(
        "radar", help="Run live real-time TCC permission & sensor access radar"
    )
    radar_parser.add_argument(
        "-d", "--duration", type=int, default=30, help="Duration in seconds (default: 30)"
    )
    radar_parser.add_argument(
        "--lang", choices=["zh", "en"], default="zh", help="Output language (zh or en)"
    )

    args = parser.parse_args()
    try:
        lang = getattr(args, "lang", "zh")
        if args.command == "radar":
            asyncio.run(run_radar(duration=args.duration, lang=lang))
        else:
            out_dir = Path(getattr(args, "output", "noir-out"))
            redact = getattr(args, "redact", False)
            check_sb = not getattr(args, "no_sandbox", False)
            asyncio.run(run_scan(output_dir=out_dir, redact=redact, check_sandbox=check_sb, lang=lang))
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted by user.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
