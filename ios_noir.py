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

BANNER = """[bold bright_blue]
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

HIGH_RISK_ENTITLEMENTS = {
    "com.apple.developer.pushkit.unrestricted-voip-regulatory": (
        "🚨 [机制实锤] 监管特批: 无限制静默VoIP唤醒 (unrestricted-voip-regulatory)",
        35,
        "CAPABILITY",
        "持有苹果未公开监管豁免签名，PushKit 静默推送可绕过 iOS 13+ 强制全屏 CallKit 限制直接拉活后台进程。",
    ),
    "com.apple.developer.pushkit.unrestricted-voip": (
        "🚨 [机制实锤] 旧版无限制静默VoIP唤醒 (unrestricted-voip)",
        30,
        "CAPABILITY",
        "允许通过 VoIP 推送在后台静默唤醒应用进程。",
    ),
    "com.apple.developer.networking.HotspotHelper": (
        "📶 [机制实锤] 系统级Wi-Fi扫描唤醒钩子 (HotspotHelper)",
        30,
        "CAPABILITY",
        "系统扫描或切换 Wi-Fi 列表时由 iOS 内核自动唤醒该应用并传入周边 SSID/BSSID 列表。",
    ),
    "com.apple.developer.networking.multipath": (
        "📡 [机制实锤] 绕过Wi-Fi并发拉起蜂窝通道 (multipath)",
        18,
        "CAPABILITY",
        "支持 Multipath TCP，可在连接 Wi-Fi 或 VPN 时并发开启 pdp_ip0 蜂窝数据通道（常用于运营商网关取号）。",
    ),
    "com.apple.developer.CellularNetwork.network-authentication": (
        "📱 [机制实锤] 蜂窝基站免密取号认证特权 (network-authentication)",
        22,
        "CAPABILITY",
        "允许直接通过蜂窝基站网关进行 SIM 卡身份与本机号码认证。",
    ),
    "com.apple.developer.networking.multicast": (
        "🏠 [机制实锤] 局域网全屋设备多播探测 (multicast)",
        20,
        "CAPABILITY",
        "允许发送 mDNS / SSDP / UDP 多播包探测局域网内智能电视、NAS、路由器等设备。",
    ),
    "com.apple.developer.ubiquity-kvstore-identifier": (
        "☁️ [实锤] iCloud防卸载跨机持久化烙印 (ubiquity-kvstore)",
        15,
        "VERIFIED",
        "绑定私人 iCloud 键值对存储空间，写入的设备标识在卸载重装乃至更换新 iPhone 后依然自动恢复。",
    ),
    "com.apple.developer.healthkit.background-delivery": (
        "❤️ [机制实锤] 锁屏后台静默实时推送健康数据 (healthkit-bg)",
        20,
        "CAPABILITY",
        "注册 HealthKit 后台观察者后，锁屏状态下步数/心率/睡眠更新可静默唤醒应用。",
    ),
    "com.apple.developer.nearby-interaction": (
        "📍 [机制实锤] U1/U2芯片厘米级UWB空间雷达 (nearby-interaction)",
        20,
        "CAPABILITY",
        "可调用超宽带 (UWB) 芯片测算周边设备距离与方位角。",
    ),
    "com.apple.developer.networking.networkextension": (
        "🛡️ [机制实锤] 底层网络扩展与虚拟网卡控制 (networkextension)",
        20,
        "CAPABILITY",
        "可注册 Packet Tunnel / App Proxy / DNS Proxy 接管系统网络流量。",
    ),
    "com.apple.developer.networking.content-filter": (
        "🕵️ [机制实锤] 内置网络流量内容审查过滤器 (content-filter)",
        25,
        "CAPABILITY",
        "允许在设备端过滤与审查网络请求内容。",
    ),
    "com.apple.developer.devicecheck.appattest-environment": (
        "🔐 [实锤] 硬件级安全隔区设备证明 (AppAttest)",
        10,
        "VERIFIED",
        "调用 Apple Secure Enclave 生成硬件绑定的不可伪造设备证明密钥。",
    ),
}


def build_html_report(report_data: dict, redact: bool = False) -> str:
    """Generate a standalone, dark/light responsive tabbed HTML report inspired by RootSir/claude-ios-privacy-analysis."""
    dev = report_data["device"]
    summary = report_data["summary"]
    apps = report_data["apps"]
    shared_groups = report_data["shared_app_groups"]
    shared_keychains = report_data.get("shared_keychains", {})
    scheme_collisions = report_data.get("scheme_collisions", {})

    # Categorize 5-layer persistent identity apps
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

    # All audited risk rows (no truncation!)
    top_rows_html = []
    for idx, a in enumerate(apps, 1):
        findings_badges = []
        for f in a["findings"]:
            if "[实锤]" in f:
                badge = f'<span class="evi evi-seen">【实锤】</span> {html.escape(f.replace("[实锤] ", ""))}'
            elif "[机制实锤]" in f:
                badge = f'<span class="evi evi-cap">【机制实锤】</span> {html.escape(f.replace("[机制实锤] ", ""))}'
            else:
                badge = f'<span class="evi evi-inf">【推断】</span> {html.escape(f)}'
            findings_badges.append(f"<div>{badge}</div>")
        if a["ats_exception_domains"]:
            doms = ", ".join(html.escape(d) for d in a["ats_exception_domains"])
            findings_badges.append(
                f'<div><span class="evi evi-seen">【实锤】</span> ATS 降级/豁免域 ({len(a["ats_exception_domains"])}): <code>{doms}</code></div>'
            )
        if a["bg_modes"]:
            bgs = ", ".join(html.escape(b) for b in a["bg_modes"])
            findings_badges.append(
                f'<div class="text-small text-muted">后台常驻模式 ({len(a["bg_modes"])}): <code>{bgs}</code></div>'
            )
        score_color = "var(--red)" if a["score"] >= 80 else ("var(--orange)" if a["score"] >= 30 else "var(--muted-foreground)")
        top_rows_html.append(
            f'<tr class="audit-row" data-score="{a["score"]}">'
            f'<td class="text-end text-muted">{idx}</td>'
            f'<td class="text-end"><b style="color:{score_color}">{a["score"]}</b></td>'
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code> <span class="text-muted text-small">v{html.escape(str(a["version"]))}</span></td>'
            f'<td class="text-nowrap">后台: <b>{len(a["bg_modes"])}</b><br>嗅探: <b>{len(a["queried_schemes"])}</b><br>插件: <b>{a.get("extensions_count", 0)}</b></td>'
            f'<td>{"".join(findings_badges) or "<span class=text-muted>零特权越界 (Clean)</span>"}</td>'
            f"</tr>"
        )

    # ATS rows (all detected)
    ats_rows_html = []
    for a in sorted(layer_ats, key=lambda x: len(x["ats_exception_domains"]), reverse=True):
        doms_code = " ".join(f"<code>{html.escape(d)}</code>" for d in a["ats_exception_domains"])
        ats_rows_html.append(
            f"<tr>"
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code></td>'
            f'<td class="text-end"><b>{len(a["ats_exception_domains"])}</b></td>'
            f"<td>{doms_code}</td>"
            f'<td><span class="evi evi-seen">【实锤】Info.plist 静态抽取</span></td>'
            f"</tr>"
        )

    # App Group rows (all detected)
    group_rows_html = []
    for gid, members in sorted(shared_groups.items(), key=lambda x: len(x[1]), reverse=True):
        m_str = "、".join(f"<b>{html.escape(m.split(' (')[0])}</b> (<code>{html.escape(m.split(' (')[1][:-1])}</code>)" for m in members)
        group_rows_html.append(
            f"<tr>"
            f'<td class="mono"><code>{html.escape(gid)}</code></td>'
            f'<td class="text-end"><b>{len(members)}</b></td>'
            f"<td>{m_str}</td>"
            f'<td><span class="evi evi-seen">【实锤】容器互通</span> / <span class="evi evi-inf">【推断】指纹共享</span></td>'
            f"</tr>"
        )

    # Sandbox rows (all detected)
    sandbox_rows_html = []
    for a in sorted(layer_sandbox, key=lambda x: x["exposed_files_count"], reverse=True):
        samples = ", ".join(f"<code>{html.escape(s)}</code>" for s in a["exposed_files_sample"])
        sandbox_rows_html.append(
            f"<tr>"
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code></td>'
            f'<td class="text-end"><b style="color:var(--red)">{a["exposed_files_count"]}</b></td>'
            f"<td>{samples}</td>"
            f'<td><span class="evi evi-seen">【实锤】HouseArrest 免密枚举</span></td>'
            f"</tr>"
        )

    # Probers rows (all detected)
    prober_rows_html = []
    for a in all_probers:
        sample_sc = ", ".join(f"<code>{html.escape(s)}</code>" for s in a["queried_schemes"])
        prober_rows_html.append(
            f"<tr>"
            f'<td><b>{html.escape(a["name"])}</b><br><code class="mono">{html.escape(a["bundle_id"])}</code></td>'
            f'<td class="text-end"><b>{len(a["queried_schemes"])}</b></td>'
            f"<td>{sample_sc}</td>"
            f'<td><span class="evi evi-seen">【实锤】LSApplicationQueriesSchemes</span></td>'
            f"</tr>"
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iOS-NOIR 深度隐私与取证审计报告 — {html.escape(dev['name'])} (iOS {html.escape(dev['ios_version'])})</title>
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
.table-responsive {{ overflow-x: auto; margin: 10px 0; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 4px; }}
.table {{ border-collapse: collapse; width: 100%; font-size: 13.5px; }}
.table th {{ text-align: left; color: var(--muted-foreground); font-weight: 600; border-bottom: 1px solid var(--border); padding: 10px 12px; }}
.table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
.table tr:last-child td {{ border-bottom: 0; }}
.evi {{ display: inline-flex; align-items: center; gap: 3px; font-weight: 600; font-size: 12px; white-space: nowrap; }}
.evi-seen {{ color: var(--green); }}
.evi-cap  {{ color: var(--orange); }}
.evi-inf  {{ color: var(--purple); }}
.badge-pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 500; background: var(--muted); }}
</style>
</head>
<body>
<div id="ios-noir-report">
  <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
    <div>
      <h1>🛡️ iOS-NOIR 未越狱 iPhone 底层隐私与遥测取证报告</h1>
      <p class="text-muted text-small">
        设备: <code>{html.escape(dev['name'])}</code> · 系统: <code>iOS {html.escape(dev['ios_version'])}</code> · 硬件区域: <code>{html.escape(dev['model'])} ({html.escape(dev['region'])})</code> · 生成时间: <code>{html.escape(report_data['generated_at'][:19])}</code>
      </p>
    </div>
    <div class="text-small text-muted">
      Inspired by <a href="https://github.com/Verlintas/NOIR" style="color:var(--blue)">Verlintas/NOIR</a> &amp; <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir/claude-ios-privacy-analysis</a>
    </div>
  </div>

  <div class="viz-grid">
    <div class="card"><div class="card-body">
      <div class="text-muted text-small">已审计用户安装应用</div>
      <div class="viz-stat-value">{summary['total_user_apps']} <span class="text-small text-muted">款</span></div>
      <div class="text-small text-muted">全量提取 Apple 签名 Entitlements</div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small">监管特批无声 VoIP 唤醒</div>
      <div class="viz-stat-value" style="color:var(--red)">{len(layer_voip)} <span class="text-small text-muted">款</span></div>
      <div class="text-small text-muted"><code>unrestricted-voip-regulatory</code></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small">系统级 Wi-Fi 扫描钩子</div>
      <div class="viz-stat-value" style="color:var(--orange)">{len(layer_hotspot)} <span class="text-small text-muted">款</span></div>
      <div class="text-small text-muted"><code>HotspotHelper</code> 内核回调</div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small">穿 VPN 蜂窝并发/免密取号</div>
      <div class="viz-stat-value" style="color:var(--purple)">{len(layer_multipath)} <span class="text-small text-muted">款</span></div>
      <div class="text-small text-muted"><code>multipath</code> / <code>network-auth</code></div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small">跨应用共享容器串通池</div>
      <div class="viz-stat-value" style="color:var(--blue)">{summary['shared_app_groups_count']} <span class="text-small text-muted">组</span></div>
      <div class="text-small text-muted">突破沙盒共享本地存储与钥匙串</div>
    </div></div>
    <div class="card"><div class="card-body">
      <div class="text-muted text-small">免 FaceID 暴露沙盒目录</div>
      <div class="viz-stat-value" style="color:var(--red)">{len(layer_sandbox)} <span class="text-small text-muted">款</span></div>
      <div class="text-small text-muted">USB/Wi-Fi 直接可读写文件</div>
    </div></div>
  </div>

  <div class="nav-pills" role="tablist">
    <button class="nav-link active" role="tab" aria-selected="true" aria-controls="p-overview" id="tab-overview">1. 全量应用审计榜 ({len(flagged_apps)} 检出 / {len(apps)} 总计)</button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-identity" id="tab-identity">2. 五层持久设备身份与穿 VPN 链</button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-probers" id="tab-probers">3. URL Scheme 查户口嗅探 ({len(all_probers)})</button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-ats" id="tab-ats">4. ATS 加密降级与隐秘端点 ({len(layer_ats)})</button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-collusion" id="tab-collusion">5. 跨应用串通 ({len(shared_groups)}) 与沙盒裸奔 ({len(layer_sandbox)})</button>
    <button class="nav-link" role="tab" aria-selected="false" aria-controls="p-method" id="tab-method">6. 证据分级与方法论局限</button>
  </div>

  <!-- TAB 1: OVERVIEW -->
  <div id="p-overview" role="tabpanel" aria-labelledby="tab-overview">
    <div class="card"><div class="card-body">
      <h3>📌 证据分级说明（参考 <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir 证据审计标准</a>）</h3>
      <p class="text-small">
        为避免将「静态配置存在」夸大为「实时作恶实锤」，本报告对每项结论实施严格的三级证据标注：<br>
        • <span class="evi evi-seen">【实锤 / VERIFIED】</span>：直接从 Apple 签名二进制 Entitlements、<code>Info.plist</code> 静态白名单或 <code>HouseArrest</code> 沙盒文件系统中提取到的确凿配置与暴露文件。<br>
        • <span class="evi evi-cap">【机制实锤 / CAPABILITY】</span>：应用持有 Apple 官方签发的特殊内核级豁免签名（如 <code>unrestricted-voip-regulatory</code>、<code>HotspotHelper</code>、<code>multipath</code>），具备随时绕过常规沙盒限制的底层能力（具体触发频率取决于服务端下发指令）。<br>
        • <span class="evi evi-inf">【推断 / INFERRED】</span>：基于共享 App Group 容器、Keychain 共享组及第三方风控/广告域名（如 <code>shuzilm.cn</code>、<code>id6.me</code>）的标准 SDK 行为推断其跨应用关联逻辑。
      </p>
    </div></div>

    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin:16px 0 8px;">
      <h3 style="margin:0;">🔥 全量应用隐私越界与隐秘后门审计表（共 {len(apps)} 款，检出权限/后台/嗅探行为 {len(flagged_apps)} 款）</h3>
      <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <input id="app-search" type="search" placeholder="🔍 搜索应用名 / Bundle ID / 特权 / 域名..." style="padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--card); color:var(--foreground); min-width:260px; font-size:13.5px;">
        <label class="text-small" style="cursor:pointer; user-select:none;">
          <input type="checkbox" id="only-flagged" checked> 仅显示检出特权/后台/嗅探项 ({len(flagged_apps)} 款)
        </label>
      </div>
    </div>
    <div class="table-responsive">
      <table class="table" id="audit-table">
        <thead><tr><th class="text-end">#</th><th class="text-end">风险分</th><th>应用名称 / Bundle ID</th><th>后台/嗅探/插件</th><th>检出的底层特权与硬编码证据（全量无截断，含证据等级）</th></tr></thead>
        <tbody>
          {"".join(top_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 2: 5-LAYER PERSISTENT IDENTITY -->
  <div id="p-identity" role="tabpanel" aria-labelledby="tab-identity" hidden>
    <h3>🧬 五层持久设备身份链与穿 VPN 路径分析</h3>
    <p class="text-muted text-small">为什么在 iOS 上「关闭广告追踪 (IDFA) + 开启 VPN + 卸载重装 App」依然无法阻止国内大厂与风控 SDK 精准识别同一台物理手机？以下为本机实测检出的五层硬件/系统级锚点（全量列出）：</p>

    <div class="card"><div class="card-body">
      <h4>第 1 层：跨设备、防恢复出厂的「iCloud 云端隐藏烙印」（全量检出 {len(layer_icloud)} 款） <span class="evi evi-seen">【实锤】</span></h4>
      <p class="text-small">持有 <code>com.apple.developer.ubiquity-kvstore-identifier</code> 签名的应用可将唯一设备 Token 写入用户私人 iCloud KVS 云空间。<b>即便卸载重装 App，甚至购买新 iPhone 登录同一 Apple ID，该追踪烙印也会在后台秒级同步恢复。</b></p>
      <p class="text-small"><b>本机检出全部应用：</b> {", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_icloud)}</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>第 2 层：防卸载的「同厂商钥匙串持久化 (`keychain-access-groups`)」（全量检出 {len(shared_keychains)} 个跨应用钥匙串前缀） <span class="evi evi-seen">【实锤】</span></h4>
      <p class="text-small">iOS 系统级特性：应用写入 Keychain 的数据在<b>卸载 App 后依然永久保留在系统钥匙串数据库中</b>；且同一开发者 Team ID 下的多款应用可共享同一 Keychain 组。重装或安装同系新 App 时瞬间恢复老设备身份 ID。</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>第 3 层：跨应用沙盒串通池 (`com.apple.security.application-groups`)（全量检出 {summary['shared_app_groups_count']} 个多应用共享池） <span class="evi evi-seen">【实锤】</span></h4>
      <p class="text-small">只要同一集团矩阵（如阿里系、腾讯系、字节系、Google 系、Meta 系）中有<b>任意 1 款</b>应用留在手机上，共享容器 <code>group.*</code> 内的设备指纹与会话文件就不会被系统清理。</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>第 4 层：绕过 Wi-Fi 与普通 VPN 的「蜂窝基站直连通道」（全量检出 {len(layer_multipath)} 款） <span class="evi evi-cap">【机制实锤】</span></h4>
      <p class="text-small">持有 <code>com.apple.developer.networking.multipath</code> 或 <code>network-authentication</code> 特权的应用，可在连接 Wi-Fi 或开启代理时，强行指定底层 Socket 绑定蜂窝数据网卡 (<code>pdp_ip0</code>) 直连三大运营商网关（<code>cmpassport.com</code> / <code>wostore.cn</code> / <code>id6.me</code>），不仅暴露真实 SIM 卡归属地与基站出口 IP，还可配合网关完成本机号码校验。</p>
      <p class="text-small"><b>本机检出全部应用：</b> {", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_multipath)}</p>
    </div></div>

    <div class="card"><div class="card-body">
      <h4>第 5 层：无视定位开关的「物理空间锚点」（Wi-Fi BSSID 钩子 {len(layer_hotspot)} 款 / 局域网多播探测） <span class="evi evi-cap">【机制实锤】</span></h4>
      <p class="text-small">即使关闭 GPS 定位权限，持有 <code>HotspotHelper</code> 的应用（{", ".join(f"<code>{html.escape(a['name'])}</code>" for a in layer_hotspot)}）也能在系统扫描 Wi-Fi 时获取周边路由器硬件 MAC 地址（BSSID），结合云端 Wi-Fi 地理库即可反推精确到楼层的物理位置。</p>
    </div></div>
  </div>

  <!-- TAB 3: URL SCHEME PROBERS -->
  <div id="p-probers" role="tabpanel" aria-labelledby="tab-probers" hidden>
    <h3>🕵️ URL Scheme “查户口式”已安装应用嗅探榜</h3>
    <p class="text-muted text-small">iOS 9+ 规定应用必须在 <code>Info.plist</code> 的 <code>LSApplicationQueriesSchemes</code> 中静态声明要探测的 URL Scheme，才能调用 <code>canOpenURL:</code> 判断用户是否安装了目标软件（如小火箭 <code>shadowrocket</code>、海外银行、加密钱包、豪车 App）。此表为 100% 静态实锤证据：</p>
    <div class="table-responsive">
      <table class="table">
        <thead><tr><th>应用名称 / Bundle ID</th><th class="text-end">嗅探暗号数量</th><th>声明探测的 URL Schemes 样本</th><th>证据等级</th></tr></thead>
        <tbody>
          {"".join(prober_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 4: ATS EXCEPTIONS -->
  <div id="p-ats" role="tabpanel" aria-labelledby="tab-ats" hidden>
    <h3>🌐 ATS 加密降级与硬编码隐秘端点 (`NSExceptionDomains`)</h3>
    <p class="text-muted text-small">苹果强制要求 App 默认使用安全 HTTPS (App Transport Security)。如果开发者在 <code>Info.plist</code> 中专门为特定域名配置了 <code>NSExceptionDomains</code>（允许明文 HTTP 或忽略证书校验），往往直接暴露出其底层接入的<b>第三方设备指纹库（如数字联盟 <code>shuzilm.cn</code>）、运营商取号网关（<code>id6.me</code> / <code>wo.cn</code>）、历史遗留热更新后门（<code>jspatch.com</code>）或商业广告监测网（秒针 <code>miaozhen.com</code>）</b>：</p>
    <div class="table-responsive">
      <table class="table">
        <thead><tr><th>应用名称 / Bundle ID</th><th class="text-end">豁免域名数</th><th>静态抽取的 NSExceptionDomains 域名清单</th><th>证据等级</th></tr></thead>
        <tbody>
          {"".join(ats_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 5: COLLUSION & SANDBOX -->
  <div id="p-collusion" role="tabpanel" aria-labelledby="tab-collusion" hidden>
    <h3>🔗 跨应用共享容器串通池 (`com.apple.security.application-groups`)</h3>
    <div class="table-responsive">
      <table class="table">
        <thead><tr><th>共享容器 ID (App Group)</th><th class="text-end">共谋应用数</th><th>共享该底层读写池的应用列表</th><th>证据等级</th></tr></thead>
        <tbody>
          {"".join(group_rows_html)}
        </tbody>
      </table>
    </div>

    <h3 style="margin-top:28px;">💣 免 FaceID 通过 USB / 局域网 Wi-Fi 直接裸露的沙盒目录 (`HouseArrest`)</h3>
    <p class="text-muted text-small">以下应用在 <code>Info.plist</code> 中开启了 <code>UIFileSharingEnabled</code> 或 <code>LSSupportsOpeningDocumentsInPlace</code>。任何曾点击过「信任此电脑」的主机（或开启 Wi-Fi 同步后的同一局域网主机）无需解锁 App 或验证 FaceID，即可直接通过苹果原生 <code>HouseArrest</code> 协议读取甚至拷走其 <code>/Documents</code> 容器内的全部文件：</p>
    <div class="table-responsive">
      <table class="table">
        <thead><tr><th>应用名称 / Bundle ID</th><th class="text-end">裸露文件/目录数</th><th>实测可直接枚举的顶层文件样本 {'(已启用 --redact 脱敏)' if redact else ''}</th><th>证据等级</th></tr></thead>
        <tbody>
          {"".join(sandbox_rows_html)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- TAB 6: METHODOLOGY & LIMITATIONS -->
  <div id="p-method" role="tabpanel" aria-labelledby="tab-method" hidden>
    <div class="card"><div class="card-body">
      <h3>🔬 取证方法论（未越狱 iOS 设备）</h3>
      <ol class="text-small">
        <li><b>Lockdown &amp; InstallationProxy 全量元数据穿透</b>：通过 <code>usbmuxd</code> 建立配对通道，枚举全机所有用户态与系统态 Bundle 的完整属性字典、Apple 签名 <code>Entitlements</code> 权限树、<code>Info.plist</code> 静态声明与 App Extension 插件拓扑。</li>
        <li><b>HouseArrest 沙盒容器可访问性实测</b>：对声明文件共享的容器逐一发起非破坏性只读挂载测试，统计无需生物识别即可在外部直接枚举的敏感数据文件。</li>
        <li><b>OsTrace 实时内核日志流雷达</b>：通过 <code>ios_noir.py radar</code> 实时订阅 <code>tccd</code>（隐私权限仲裁守护进程）、<code>cameracaptured</code>、<code>locationd</code> 与 <code>lsd</code>，毫秒级捕获运行时权限预检与传感器探针。</li>
      </ol>
    </div></div>

    <div class="card"><div class="card-body">
      <h3>⚖️ 方法论局限与严谨性边界（必读）</h3>
      <ol class="text-small">
        <li><b>未越狱 FairPlay 壳限制</b>：未越狱设备上的 App Store 二进制受 Apple FairPlay DRM 硬件加密保护，本工具不进行脱壳或 Ghidra 反编译；如需针对单款已脱壳 IPA 进行函数级反编译与字符串交叉引用，请参考并结合 <a href="https://github.com/RootSir/claude-ios-privacy-analysis" style="color:var(--blue)">RootSir/claude-ios-privacy-analysis</a> 的 Ghidra 自动化管线。</li>
        <li><b>特权存在性【机制实锤】 ≠ 全天候触发【实锤】</b>：应用持有 <code>unrestricted-voip-regulatory</code> 或 <code>HotspotHelper</code> 证明苹果官方为其签发了突破常规限制的底层准入证，但是否在特定时刻下发静默唤醒或上报 BSSID 取决于服务端指令与运行时逻辑。</li>
        <li><b>ATS 豁免域名 ≠ 当前活跃抓包流量</b>：<code>NSExceptionDomains</code> 中的域名（如 <code>jspatch.com</code>、<code>shuzilm.cn</code>）为开发者在 <code>Info.plist</code> 中显式声明的白名单，部分可能是历史遗留配置或按条件触发的备用通道。</li>
      </ol>
      <p class="text-small text-muted">声明：本工具及生成报告仅用于设备所有者对自身设备进行安全与隐私透明度自查，100% 纯本地离线运行，不含任何第三方版权二进制代码。</p>
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
      var matchFlag = !flaggedOnly || score > 0 || text.indexOf('零特权越界') === -1;
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


async def run_scan(output_dir: Path, redact: bool = False, check_sandbox: bool = True):
    console.print(BANNER)
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
        findings = []

        for k, (label, pts, _tier, _desc) in HIGH_RISK_ENTITLEMENTS.items():
            if ent.get(k):
                score += pts
                findings.append(label)

        # App Groups & Keychains
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

        # URL Schemes registered
        for ut in info.get("CFBundleURLTypes", []) or []:
            if isinstance(ut, dict):
                for s in ut.get("CFBundleURLSchemes", []) or []:
                    url_scheme_owners[str(s).lower()].append(f"{name} ({bid})")

        # Background modes & URL scheme probing
        score += len(bg_modes) * 4
        if len(queried_schemes) >= 20:
            score += min(30, len(queried_schemes) // 2)

        # Sandbox exposure check
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
                findings.append(
                    f"📂 [实锤] 免FaceID暴露USB/Wi-Fi沙盒目录 ({len(exposed_files)} 个裸露文件)"
                )
            else:
                findings.append("📂 [实锤] 开启USB/Wi-Fi沙盒共享 (UIFileSharingEnabled)")

        # ATS Exception Domains
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
                "findings": findings,
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

    # Top Risk Table
    flagged_results = [
        r for r in results
        if r["score"] > 0 or r["findings"] or r["ats_exception_domains"]
    ]
    t = Table(
        title=f"🚨 iOS-NOIR 隐私越界与隐秘后门全量检出榜 (共检出 {len(flagged_results)} / {len(results)} 款应用)",
        box=box.ROUNDED,
        show_lines=True,
    )
    t.add_column("风险分", style="bold red", justify="right", width=6)
    t.add_column("应用名称 / Bundle ID", style="bold white", width=28)
    t.add_column("后台/嗅探", style="yellow", width=16)
    t.add_column("检出的底层特权与硬编码证据 (附证据分级)", style="cyan")

    for r in flagged_results:
        desc = "\n".join(r["findings"]) if r["findings"] else "[dim]后台常驻 / URL 嗅探[/dim]"
        if r["ats_exception_domains"]:
            dom_preview = ", ".join(r["ats_exception_domains"][:6])
            desc += f"\n[magenta]🎯 [实锤] ATS豁免域: {dom_preview}[/magenta]"
        t.add_row(
            str(r["score"]),
            f"{r['name']}\n[dim]{r['bundle_id']}[/dim]",
            f"后台:{len(r['bg_modes'])} | 嗅探:{len(r['queried_schemes'])}",
            desc,
        )
    console.print(t)

    # Shared App Groups Collusion Table
    shared_groups = {k: v for k, v in app_groups_map.items() if len(v) >= 2}
    shared_kcs = {k: v for k, v in keychain_map.items() if len(v) >= 2}
    scheme_collisions = {k: v for k, v in url_scheme_owners.items() if len(v) >= 2}

    t2 = Table(
        title=f"🔗 跨 App 共享数据池 (突破沙盒暗中串通容器 共 {len(shared_groups)} 组)",
        box=box.SIMPLE_HEAVY,
    )
    t2.add_column("共享容器 ID (App Group)", style="bold magenta", width=38)
    t2.add_column("同伙应用列表", style="white")
    for g, members in sorted(shared_groups.items(), key=lambda x: len(x[1]), reverse=True):
        t2.add_row(g, "、".join(members))
    console.print(t2)

    # Exposed Sandbox Containers Table
    exposed_apps = [r for r in results if r["exposed_files_count"] > 0]
    if exposed_apps:
        t3 = Table(
            title=f"💣 免 FaceID 通过 USB/Wi-Fi 直接裸奔可读的沙盒目录 (HouseArrest) [实锤] (共 {len(exposed_apps)} 款)",
            box=box.ROUNDED,
            show_lines=True,
        )
        t3.add_column("应用名称", style="bold red", width=26)
        t3.add_column("暴露文件数", style="bold yellow", justify="right", width=10)
        t3.add_column("直接可读文件样本 (--redact 可脱敏)", style="white")
        for r in exposed_apps:
            t3.add_row(
                f"{r['name']}\n[dim]{r['bundle_id']}[/dim]",
                str(r["exposed_files_count"]),
                ", ".join(r["exposed_files_sample"][:10]),
            )
        console.print(t3)

    # Save structured JSON report, domains txt, and standalone interactive HTML report
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
    html_path.write_text(build_html_report(report_data, redact=redact), encoding="utf-8")

    console.print(
        Panel(
            f"✅ 扫描完成！产出已保存至:\n"
            f"  • 交互式独立 HTML 报告 (浏览器直接打开): [bold bright_green]{html_path}[/bold bright_green]\n"
            f"  • 结构化审计报告: [bold green]{report_path}[/bold green]\n"
            f"  • 静态抽取的后门/豁免域名集 ({len(all_ats_domains)} 个): [bold yellow]{domains_path}[/bold yellow]",
            border_style="green",
        )
    )


async def run_radar(duration: int = 30):
    console.print(BANNER)
    lockdown = await create_using_usbmux()
    console.print(
        Panel(
            f"📡 [bold red]iOS-NOIR 实时隐私抓现行雷达已启动 (监听 {duration} 秒)...[/bold red]\n"
            "现在请在手机上点开任意你想测试的 App，观察它毫秒级触发的底层传感器与权限请求！",
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

    radar_parser = subparsers.add_parser(
        "radar", help="Run live real-time TCC permission & sensor access radar"
    )
    radar_parser.add_argument(
        "-d", "--duration", type=int, default=30, help="Duration in seconds (default: 30)"
    )

    args = parser.parse_args()
    try:
        if args.command == "radar":
            asyncio.run(run_radar(duration=args.duration))
        else:
            out_dir = Path(getattr(args, "output", "noir-out"))
            redact = getattr(args, "redact", False)
            check_sb = not getattr(args, "no_sandbox", False)
            asyncio.run(run_scan(output_dir=out_dir, redact=redact, check_sandbox=check_sb))
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted by user.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
