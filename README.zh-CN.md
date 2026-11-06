```text
  ██╗ ██████╗ ███████╗      ███╗   ██╗ ██████╗ ██╗██████╗ 
  ██║██╔═══██╗██╔════╝      ████╗  ██║██╔═══██╗██║██╔══██╗
  ██║██║   ██║███████╗█████╗██╔██╗ ██║██║   ██║██║██████╔╝
  ██║██║   ██║╚════██║╚════╝██║╚██╗██║██║   ██║██║██╔══██╗
  ██║╚██████╔╝███████║      ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝ ╚═════╝ ╚══════╝      ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
```

# iOS-NOIR

**[English](README.md) · 简体中文**

[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![Platform: macOS (Tested)](https://img.shields.io/badge/Platform-macOS%20(已实测)-blue.svg)](#)
[![No Jailbreak Required](https://img.shields.io/badge/无需越狱-Stock%20iOS-brightgreen.svg)](#)

**把「这台未越狱的 iPhone 到底在暗中泄露什么」变成一份可复现的底层取证报告。**

> 💡 **致敬 / Inspired by**  
> 本项目深受 [**Verlintas/NOIR**](https://github.com/Verlintas/NOIR)（基于 `adb` 的 Android 本地隐私审计工具）启发。  
> 在 Android 上，NOIR 依靠 `adb dumpsys` 与 APK 反编译；而在无法脱壳反编译的未越狱 iOS 设备上，**iOS-NOIR** 开创了一套基于苹果底层 `lockdownd`、`InstallationProxy`、`HouseArrest`、`OsTrace` 与开发者模式 `DVT Instruments`（`sysmon` / `netstat`）的**免越狱深度隐私与遥测审计管线**。

---

## 🔍 iOS-NOIR 能揪出什么？（未越狱真机实测发现）

大多数人以为 iOS 有沙盒保护就不会泄露隐私。但通过穿透苹果底层 Lockdown 服务与内核遥测，**iOS-NOIR** 能够直接抓出 **10 类在 iOS 系统设置里完全不可见的隐秘后门**：

1. **🚨 监管特批：无限制静默 VoIP 后台唤醒（`unrestricted-voip-regulatory`）**  
   从 iOS 13 起，苹果强制规定任何 App 收到 VoIP 语音推送必须立刻弹出全屏来电界面，否则直接封杀后台唤醒权。但 **iOS-NOIR** 扫描发现，个别超级 App（如微信、QQ、钉钉）持有苹果未公开的 `com.apple.developer.pushkit.unrestricted-voip-regulatory: True` 豁免签名——它们的服务器随时可以下发无声指令，把死透的后台进程静默拉活上万次，**而手机屏幕不会亮、不会响、不留任何痕迹**。
2. **📶 系统级 Wi-Fi 扫描自动唤醒钩子（`HotspotHelper`）**  
   揪出伪装成外卖/支付/点评软件（如美团、大众点评、支付宝、微信、钉钉）却持有 `com.apple.developer.networking.HotspotHelper` 特权的应用。只要你打开系统 Wi-Fi 列表或走过商场，iOS 内核就会在后台自动唤醒它们，并把周围扫到的所有 Wi-Fi 列表（SSID 与路由器 MAC 地址 BSSID）直接喂给它们。
3. **📡 绕过 Wi-Fi 直连三大运营商基站取号（`multipath` & `network-authentication`）**  
   识别拥有多路径蜂窝并发特权的应用。哪怕你连着家里 Wi-Fi 或挂着 VPN，它们也能单独强行拉起 4G/5G 蜂窝数据网卡，直连联通（`wostore.cn` / `mdn.open.wo.cn` / `id6.me`）、移动（`cmpassport.com`）、电信（`189.cn`）网关静默提取本机号码或上报数据。
4. **🕵️ “查户口式”已安装应用嗅探（`LSApplicationQueriesSchemes`）**  
   揭穿单个查航班或社交软件在后台内置多达 **280 个** URL Scheme 白名单，挨个探测你手机里有没有装 `shadowrocket`（小火箭）、`telegram`、`openai`、海外银行、加密交易所或 15+ 家豪车车企 App（精准摸底你的资产与身价）。
5. **🔗 跨 App 数据池串通（`App Groups` & `Keychain Access Groups`）**  
   绘出同系应用如何通过共享底层容器（`group.*`）和同一开发者钥匙串前缀，绕过沙盒隔离暗中互通设备 DNA 指纹（如数字联盟 `shuzilm.cn`）。
6. **☁️ 卸载重装、换新机都洗不掉的“iCloud 云端烙印”（`ubiquity-kvstore`）**  
   抓出偷偷在你的私人 iCloud 隐藏键值对空间写入唯一设备追踪码的应用。
7. **💣 无需 FaceID！USB / Wi-Fi 1 秒掏空沙盒文件漏洞（`UIFileSharingEnabled` / `HouseArrest`）**  
   实测扫描哪些 App 将 `/Documents` 目录裸露在 USB 与局域网 Wi-Fi 同步接口下——无需解锁 App，1 秒即可列出暴露在外的 `.kdbx` 密码库、银行对账单 PDF、以及银行 App 体内潜伏的 `Sentiance` AI 全天候行程监控 SQLite 数据库。
8. **🧟‍♂️ 推送插件“借尸还魂”与行为生物特征探针（`NotificationServiceExtension`）**  
   即使划掉后台、关闭后台刷新，流氓软件仍可通过 `mutable-content: 1` 推送拉起通知扩展替身进程狂读硬盘，甚至在推送插件中植入 LexisNexis `TMXBehavioSec`（记录手指按压屏幕角度与打字敲击毫秒级节奏）。
9. **⚔️ URL Scheme 恶意抢注与截胡（Scheme Collisions）**  
   检测多个应用同时抢注同一个唤醒暗号（例如多家交易所同时抢注 Telegram 生态钱包连接协议 `tc://`，或多款旅游软件抢注 `com.apple.maps.action://` 与 `prefs://`）。
10. **🎯 静态端点抽取（`NSExceptionDomains`）**  
    直接从应用配置中抽取点名要求降级 HTTPS 加密的后门域名——当场抓获残留的 `jspatch.com`（被苹果封杀的远程热更新代码执行后门）、视频会议软件内嵌的 12 家商业广告竞价监测网（秒针 `miaozhen.com`、国双、AdMaster 等），以及 `0.0.0.0/1` 全局子网掩码绕过。

---

## 🚀 快速开始

> ⚠️ **平台兼容性说明**：目前仅在 **macOS** 下完成实机测试（macOS 原生自带苹果 `usbmuxd` 通信守护进程）。**Windows 与 Linux 暂未测试**（可能需要额外部署 iTunes 驱动或 `usbmuxd` 服务）。

### 1. 安装依赖
```bash
git clone https://github.com/arnold117/iOS-NOIR.git
cd iOS-NOIR
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 连接 iPhone
用 USB 数据线连接 iPhone，解锁手机屏幕并在弹窗中点击 **「信任此电脑」**。

### 3. 一键全量扫描与仪表盘
```bash
# 运行完整审计（结构化结果与域名清单默认输出至 noir-out/）
python ios_noir.py scan

# 脱敏截图模式（自动隐藏设备名称与暴露的具体私人文件名，方便直接截图发 X / 推特）
python ios_noir.py scan --redact
```

### 4. 启动实时“抓现行”隐私雷达
```bash
# 开启 30 秒实时监控，此时在手机上点开任意待测 App，毫秒级打印其调用的相机、麦克风、通讯录、定位与 IDFA 请求
python ios_noir.py radar --duration 30
```

---

## 🛡️ 内置反制护盾（`shields/`）

由于未越狱 iOS 不允许通过命令行直接执行 `appops`，**iOS-NOIR** 在 [`shields/`](shields/) 目录下提供了两套免越狱系统级阻断方案：

1. **免 VPN 系统级原生加密 DNS 护盾（[`shields/iOS-NOIR-System-Shield.mobileconfig`](shields/iOS-NOIR-System-Shield.mobileconfig)）**  
   基于苹果原生 `com.apple.dnsSettings.managed` 内核配置。通过隔空投送（AirDrop）发到手机安装后，**无需开启 VPN、零后台进程、零额外耗电**，由 iOS 内核网络栈 24 小时加密 DNS 查询（防运营商基站嗅探）并黑洞拦截主流追踪器域名；当你开启 Shadowrocket / Clash 时自动无缝让位，关闭 VPN 后 0 秒自动接管。
2. **分流拦截规则集（[`shields/ios_noir_shield.conf`](shields/ios_noir_shield.conf)）**  
   兼容 **Shadowrocket / Surge / Loon / Clash**，精准 `REJECT` 三大运营商免密取号网关（`cmpassport.com` / `wostore.cn` / `id6.me`）、数字联盟跨应用设备 DNA 指纹（`shuzilm.cn`）、`jspatch.com` 热更新后门、`online-metrix.net` 行为生物特征探针，以及穿山甲/广点通/友盟/阿里百川等核心遥测端点，且不影响正常聊天与支付功能。

---

## 🔒 隐私与安全承诺

- **100% 纯本地离线运行**：无任何遥测、无联网检查、无需注册账号。
- **默认完全只读**：绝不修改任何系统分区或应用沙盒数据。
- **防隐私泄露保护**：内置 `--redact` 截图脱敏参数，且 `.gitignore` 默认拦截所有 `.json`、`.ips`、`.pcapng`、`.sqlite` 本地扫描产物，严防误提交个人数据。

---

## 📜 致谢与开源许可

- **灵感来源**：[Verlintas/NOIR](https://github.com/Verlintas/NOIR)
- **底层通信支持**：[doronz88/pymobiledevice3](https://github.com/doronz88/pymobiledevice3) & [Textualize/rich](https://github.com/Textualize/rich)
- **作者**：Arnold · PGP 指纹：`C3D9 CA55 2798 2586 BB20  F2DB 7B25 BE32 527E FEA1`
- **许可证**：[MIT](LICENSE)
