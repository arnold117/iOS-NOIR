```text
  ██╗ ██████╗ ███████╗      ███╗   ██╗ ██████╗ ██╗██████╗ 
  ██║██╔═══██╗██╔════╝      ████╗  ██║██╔═══██╗██║██╔══██╗
  ██║██║   ██║███████╗█████╗██╔██╗ ██║██║   ██║██║██████╔╝
  ██║██║   ██║╚════██║╚════╝██║╚██╗██║██║   ██║██║██╔══██╗
  ██║╚██████╔╝███████║      ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝ ╚═════╝ ╚══════╝      ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
```

# iOS-NOIR

**English · [简体中文](README.zh-CN.md)**

[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![Platform: macOS (Tested)](https://img.shields.io/badge/Platform-macOS%20(Tested)-blue.svg)](#)
[![No Jailbreak Required](https://img.shields.io/badge/Jailbreak-Not%20Required-brightgreen.svg)](#)

**Turn "What is my iPhone silently leaking?" into a reproducible, evidence-backed forensic report — without jailbreaking.**  
**把「这台未越狱的 iPhone 到底在暗中泄露什么」变成一份可复现的底层取证报告。**

> 💡 **Acknowledgement / 致敬**  
> Heavily inspired by [**Verlintas/NOIR**](https://github.com/Verlintas/NOIR) (the local-first Android privacy auditor over `adb`). While Android NOIR leverages `adb dumpsys` and APK decompilation, **iOS-NOIR** pioneers a non-jailbroken iOS audit pipeline via `lockdownd`, `InstallationProxy`, `HouseArrest`, `OsTrace`, and `DVT Instruments` (`sysmon` / `netstat`).

---

## 🔍 What iOS-NOIR Uncovers (Real-World Findings on Stock iOS)

Most users believe stock iOS sandboxing makes privacy leaks impossible. By auditing low-level Apple lockdown services and Developer Mode DVT telemetry, **iOS-NOIR** exposes 10+ blind spots completely hidden from the iOS Settings UI:

1. **🚨 Regulatory Unrestricted Silent VoIP Wakeups (`unrestricted-voip-regulatory`)**  
   Since iOS 13, Apple requires VoIP pushes (`PushKit`) to trigger a full-screen call UI or face termination. **iOS-NOIR** detects apps holding Apple's undocumented `com.apple.developer.pushkit.unrestricted-voip-regulatory` entitlement (e.g., WeChat, QQ, DingTalk), allowing servers to silently wake dead background processes 10,000+ times without lighting up the screen.
2. **📶 System-Level Wi-Fi Scan Hooks (`HotspotHelper`)**  
   Identifies non-utility apps (e.g., food delivery & payment apps) holding `com.apple.developer.networking.HotspotHelper`. Every time you open Wi-Fi settings or walk through a mall, iOS automatically wakes these apps and feeds them nearby Wi-Fi BSSIDs/SSIDs.
3. **📡 Carrier Gateway Bypass (`multipath` & `network-authentication`)**  
   Detects apps capable of forcing cellular interface (`pdp_ip0`) connections to telecom gateways (`cmpassport.com`, `wostore.cn`, `id6.me`) for silent phone-number (`MDN`) extraction even while connected to Wi-Fi or a VPN.
4. **🕵️ App-List Probing (`LSApplicationQueriesSchemes`)**  
   Uncovers apps hardcoding 100~280+ URL schemes to probe whether you have VPN clients (`shadowrocket`), crypto wallets, foreign banks, or luxury car apps installed.
5. **🔗 Cross-App Collusion (`App Groups` & `Keychain Access Groups`)**  
   Maps hidden shared storage containers (`group.*`) and shared keychain prefixes used by app families to bypass sandbox isolation and share device fingerprints (`shuzilm.cn`, etc.).
6. **☁️ Uninstall-Proof iCloud Fingerprinting (`ubiquity-kvstore-identifier`)**  
   Flags apps writing persistent device tracking tokens into your private iCloud key-value store that survive app reinstallation and device upgrades.
7. **💣 USB / Wi-Fi Sandbox Exposure (`UIFileSharingEnabled` / `HouseArrest`)**  
   Audits apps exposing their `/Documents` container over USB/Wi-Fi without requiring FaceID or app-level authentication — catching exposed `.kdbx` password databases, bank statements, and plaintext `Sentiance` AI timeline SQLite databases.
8. **🧟‍♂️ Notification Extension Trojans (`NotificationServiceExtension`)**  
   Tracks background CPU wakeups and disk reads (`sysmon` diffing) triggered by `mutable-content: 1` push payloads, including embedded behavioral biometrics SDKs (`TMXBehavioSec` / ThreatMetrix) running inside push extensions.
9. **⚔️ URL Scheme Hijacking & Collisions**  
   Detects multiple apps registering identical sensitive URL schemes (e.g., `tc://` for TON Connect crypto wallets, or `com.apple.maps.action://`).
10. **🎯 ATS Exception Endpoint Extraction (`NSExceptionDomains`)**  
    Extracts hardcoded domains where developers explicitly bypass Apple's HTTPS App Transport Security (uncovering legacy `jspatch.com` hot-patching backdoors, ad exchanges like `miaozhen.com` inside enterprise meeting apps, or `0.0.0.0/1` CIDR bypasses).

---

## 🚀 Quick Start / 快速上手

> ⚠️ **Platform Note:** Currently tested and verified on **macOS** (where Apple's `usbmuxd` runs natively). **Windows and Linux have not been tested yet** (and may require additional iTunes / `usbmuxd` driver setup).

### 1. Install Dependencies
```bash
git clone https://github.com/arnold117/iOS-NOIR.git
cd iOS-NOIR
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Connect Your iPhone via USB
Plug in your iPhone, unlock the screen, and tap **"Trust This Computer"**.

### 3. Run Full Audit & Dashboard
```bash
# Run full audit (outputs to noir-out/)
python ios_noir.py scan

# Run in redacted mode (hides personal device name & filenames for safe sharing on X/Twitter)
python ios_noir.py scan --redact
```

### 4. Run Live Privacy Radar (Real-Time TCC / Sensor / IDFA Sniffer)
```bash
# Monitor real-time permission preflights, camera/mic probes, and IDFA requests for 30s
python ios_noir.py radar --duration 30
```

---

## 🛡️ Built-In Countermeasures (`shields/`)

Unlike Android, stock iOS does not provide `appops set` via shell. Instead, **iOS-NOIR** provides two zero-jailbreak mitigation shields in the [`shields/`](shields/) directory:

1. **VPN-Free Kernel Encrypted DNS Shield ([`shields/iOS-NOIR-System-Shield.mobileconfig`](shields/iOS-NOIR-System-Shield.mobileconfig))**  
   Uses Apple's native `com.apple.dnsSettings.managed` payload. AirDrop it to your iPhone to block trackers and encrypt DNS over HTTPS at the OS kernel level **24/7 without keeping a VPN connected or draining battery**. Automatically yields when you turn on Shadowrocket/Clash and resumes the moment VPN disconnects.
2. **Packet-Tunnel Reject Rules ([`shields/ios_noir_shield.conf`](shields/ios_noir_shield.conf))**  
   Drop-in rule set for **Shadowrocket / Surge / Loon / Clash** that blocks carrier silent-auth gateways (`cmpassport.com`, `wostore.cn`, `id6.me`), cross-app DNA fingerprinting (`shuzilm.cn`), hot-patch backdoors (`jspatch.com`), behavioral biometrics (`online-metrix.net`), and major ad-tech telemetry without breaking core app functionality.

---

## 🔒 Privacy & Security Guarantees

- **100% Offline & Local-First:** Zero telemetry, zero analytics, no cloud accounts, no external network calls.
- **Read-Only by Default:** Never modifies system partitions or app data.
- **Safe Sharing:** Built-in `--redact` flag and strict `.gitignore` rules ensure your personal `.json`, `.ips`, and `.pcapng` dumps are never accidentally committed.

---

## 📜 Credits & License

- **Inspired by:** [Verlintas/NOIR](https://github.com/Verlintas/NOIR) (Android Privacy Auditor)
- **Powered by:** [doronz88/pymobiledevice3](https://github.com/doronz88/pymobiledevice3) & [Textualize/rich](https://github.com/Textualize/rich)
- **Author:** Arnold · PGP: `C3D9 CA55 2798 2586 BB20  F2DB 7B25 BE32 527E FEA1`
- **License:** [MIT](LICENSE)
