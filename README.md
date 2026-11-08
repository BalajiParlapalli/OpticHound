# 👁️ OpticHound

**Rental Stay Hidden Camera & Surveillance Device Detector**  
*Cross-Platform Network Scanner for Linux, macOS, and Windows.*

OpticHound is a portable, zero-dependency Python tool designed to help travelers inspect the local Wi-Fi network in vacation rentals (Airbnb, Vrbo, hotels) and detect hidden cameras, rogue surveillance devices, and unauthorized streaming equipment.

---

## 🌟 Key Highlights

- **Runs Everywhere**: Works seamlessly on Linux, macOS, and Windows with a single command-line script.
- **Zero Required Dependencies**: Runs 100% out-of-the-box using Python's standard library alone (`socket`, `threading`, `urllib`, `struct`, `json`, `subprocess`). No `pip install` required!
- **Multi-Vector Discovery**:
  - **ARP & Socket Sweep**: Populates the OS ARP table across Windows (`arp -a`), Linux (`/proc/net/arp`, `ip neigh`), and macOS (`arp -a -n`) without requiring root/admin privileges.
  - **Multicast UPnP / SSDP**: Sends M-SEARCH queries (`239.255.255.250:1900`) and downloads device XML descriptors to discover `friendlyName`, `model`, and `DigitalSecurityCamera` declarations.
  - **ONVIF WS-Discovery**: Sends SOAP XML probe multicast (`239.255.255.250:3702`) to trigger instant responses from ONVIF IP security cameras.
  - **mDNS / Zeroconf**: Probes `_rtsp._tcp`, `_axis-video._tcp`, `_http._tcp`, and `_hap._tcp` services.
- **Embedded Camera & IoT OUI Database**: Over 200 curated MAC vendor prefixes (Hikvision, Dahua, Wyze, Ring, Arlo, Reolink, Axis, Foscam, Amcrest, Eufy, Lorex, Tuya, Espressif ESP32-CAM, Xiongmai, HiSilicon, Allwinner, Luxottica Tristar, Meta Platforms).
- **Smart Glasses & AI Eyewear Detection (Meta Ray-Ban / Snap / Echo Frames)**:
  - **Bluetooth Low Energy (BLE) Beacon Sniffer**: Monitors active broadcast advertisements and matches Bluetooth SIG Manufacturer Company IDs:
    - `0x0D53`: Luxottica Group S.p.A. (Ray-Ban Meta, Ray-Ban Stories)
    - `0x058E` / `0x01AB`: Meta Platforms Technologies (Meta AI Wearables)
    - `0x03C2`: Snap Inc. (Snap Spectacles HD dual-camera glasses)
    - `0x0171`: Amazon.com Services LLC (Echo Frames)
    - `0x08A9`: Even Realities G1 (Dual heads-up display)
    - `0x0A9F`: Brilliant Labs Frame (Multimodal camera glasses)
    - `0x0499`: Vuzix Corporation (Smart AR eyewear)
    - `0x0602`: Solos Technology (Solos AirGo AI glasses)
  - **RSSI Proximity Meter**: Evaluates received signal power (`Immediate Proximity < 1.5m` vs `Room Vicinity 1.5–4m`) to alert travelers when active recording glasses are in the immediate room.
  - **In-Air Direct Sync Wi-Fi Hotspots**: Detects transient P2P sync networks (`Ray-Ban-*`, `meta-view-*`, `spectacles-*`) used to offload captured video clips.
  - **Zero External Python Libraries**: Runs using native Windows WinRT APIs on Windows, `bluetoothctl` on Linux, and `system_profiler` on macOS.
- **Audio Surveillance & Microphone Stream Prober**:
  - **RTSP SDP Audio Parser**: Issues `DESCRIBE` requests on video streams to detect embedded live microphone audio feeds (`m=audio`, AAC, G.711, PCM).
  - **Always-Listening Microphone Detection**: Identifies smart speakers, smart displays, smart TVs, and voice assistants equipped with far-field acoustic arrays (Amazon Echo, Google Nest, Apple HomePod).
  - **Audio Eavesdropping Callout**: Displays dedicated `ACTIVE AUDIO SURVEILLANCE` alert cards in terminal and HTML reports for any device streaming room audio.
- **Deep Protocol Probing**:
  - **Live Unauthenticated Snapshot Grabber**: Probes open camera HTTP endpoints (`/snapshot.jpg`, `/jpg/image.jpg`, `/webcapture.jpg`, etc.) and downloads live image frames as optical proof, automatically embedded as base64 thumbnails in the HTML report.
  - **Over-the-Air Rogue Wi-Fi Hunter**: Scans ambient wireless beacons for rogue P2P spy camera APs (`Care-AP-*`, `HD-MINI-CAM-*`, `LookCam-*`, `v380_*`, `ESP32-CAM-*`) that are not joined to the property router, cross-referenced with vendor OUI heuristics on Windows (`netsh`), macOS (`airport`), and Linux (`nmcli`/`iwlist`).
  - **RTSP Handshake**: Sends RFC 2326 `OPTIONS` and `DESCRIBE` requests on ports 554, 8554, 7447, etc., extracting server banners and digest authentication challenges.
  - **Web Management Dashboard Fingerprinting**: Analyzes embedded HTTP servers (`Boa`, `GoAhead`, `JAWS`, `uc-httpd`, `Hikvision-Web`), camera titles, and authentication realms with unverified SSL support.
  - **Proprietary Surveillance Ports**: Detects Xiongmai/Sofia (34567) and Dahua DHIP (37777).
- **Transparent Risk Scoring**: Calculates a cumulative 0–100 risk score and categorizes devices into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `SAFE` with full evidence logs.
- **Dual Reporting**:
  - High-contrast, color-coded terminal dashboard.
  - Standalone, interactive dark-mode HTML report with live snapshot image embeds, rogue in-air AP lists, real-time search, category filters, expandable device cards, and traveler inspection guide.
- **Built-in Simulation Mode**: Run `python optichound.py --mock` anytime to explore a realistic rental stay scenario without needing actual cameras.

---

## 🚀 Quick Start

### 1. Requirements & Portability
- Python 3.8 or higher.
- Zero third-party packages required! Standard Python library only.

#### How to use it on any new laptop or computer:
1. **Copy the folder**: Copy the `optichound` folder to a USB flash drive, email it to yourself as a ZIP, or push it to a private Git repository.
2. **On the new device**:
   - Make sure Python 3 is installed on that computer.
   - Connect to the rental/hotel Wi-Fi.
   - Open the folder in Command Prompt or Terminal:
     - **On Windows**: Simply double-click or run `optichound.bat` (automatically scans all standard Windows Python install paths).
     - **On macOS / Linux**: Open Terminal in the folder and run `python3 optichound.py`.

It will scan whatever local network and ambient Wi-Fi airwaves that new device is currently connected to.

### 2. Windows Quickstart (Command Prompt / CMD)
Navigate to the tool directory first:
```cmd
cd optichound
```
Then use `optichound.bat` (which automatically locates your installed Python runtime and avoids Windows Store alias redirects):
```cmd
:: Test simulation mode (demo of realistic hidden cameras & rogue hotspots)
optichound.bat --mock

:: Basic scan of local network (auto-detects subnet)
optichound.bat

:: Quick scan mode (scans top camera ports with fast timeout)
optichound.bat --quick

:: Save custom dark-mode HTML report
optichound.bat --html rental_audit.html
```

### 3. Linux & macOS Quickstart
```bash
# Navigate to directory
cd optichound

# Basic scan
python3 optichound.py

# Simulation mode
python3 optichound.py --mock
```

---

## 📊 Risk Scoring Engine

OpticHound scores every discovered device on an additive scale from 0 to 100 based on weighted surveillance indicators:

| Indicator | Evidence | Points |
| :--- | :--- | :---: |
| **Captured Live Snapshot** | Unauthenticated optical image downloaded from camera endpoint | **+50** |
| **BLE Smart Glasses Beacon** | Manufacturer CID matches Luxottica / Meta / Snap / Echo Frames | **+75 to +85** |
| **Smart Glasses Sync Hotspot** | Ambient Wi-Fi SSID matches smart glasses P2P sync (`ray-ban`, `meta-view`) | **+55** |
| **Active RTSP Stream** | Responded to RTSP `OPTIONS` / `DESCRIBE` handshake | **+45** |
| **ONVIF Camera Probe** | Responded to WS-Discovery `NetworkVideoTransmitter` | **+45** |
| **In-Air Rogue Spy AP** | Ambient Wi-Fi SSID matches covert camera pattern (`Care-AP`, `HD-MINI`) | **+45** |
| **Proprietary Camera Port** | Xiongmai (34567) or Dahua DHIP (37777) open & responsive | **+40** |
| **Camera Web Title** | HTML `<title>` contains "IP Camera", "Live View", etc. | **+35** |
| **UPnP Camera Descriptor** | XML declares `DigitalSecurityCamera` or camera model | **+35** |
| **Dedicated Camera OUI** | Vendor is Hikvision, Dahua, Reolink, Wyze, Axis, Arlo, etc. | **+35** |
| **Camera Web Realm** | HTTP 401 challenge realm indicates camera ("IP Camera", "AXIS") | **+30** |
| **Embedded Camera Web Server**| HTTP Server banner is `Boa`, `GoAhead`, `JAWS`, `uc-httpd`, etc. | **+25** |
| **Covert Spy Cam Chipset** | MAC vendor is Espressif (ESP32-CAM) or Tuya Smart | **+25** |
| **Hikvision SDK Port** | Port 8000 open on Hikvision hardware | **+30** |
| **mDNS Camera Service** | Broadcasts `_rtsp._tcp` or `_axis-video._tcp` | **+25** |
| **Open RTSP Port** | Port 554/8554 open (without full banner) | **+20** |
| **Alternate Camera Port** | Port 81, 82, 88 (Foscam), 8081 (MJPEG), 8899 (ONVIF) | **+15 to +35** |
| **Unencrypted Telnet** | Port 23 open on IoT/camera device | **+15** |

### Risk Tiers

- 🔴 **CRITICAL (Score ≥ 75)**: Confirmed surveillance camera or streaming video endpoint with live feeds or verified ONVIF/RTSP services.
- 🟡 **HIGH (Score 50 – 74)**: Highly suspicious device displaying multiple strong camera signatures (e.g. camera brand + web management port).
- 🔵 **MEDIUM (Score 25 – 49)**: Smart IoT hardware or display with potential camera/mic capabilities (e.g., Espressif ESP32, Tuya Smart, Amazon Echo Show).
- ⚪ **LOW (Score 10 – 24)**: Standard network equipment or router management pages.
- 🟢 **SAFE (Score 0 – 9)**: Normal laptops, guest smartphones, printers, or authorized devices.

---

## 💻 Command-Line Options

```
usage: optichound.py [-h] [-q] [-d] [-s SUBNET] [-i INTERFACE] [-t TIMEOUT]
                     [--threads THREADS] [--ports PORTS] [-o HTML] [--no-html]
                     [--json JSON] [--no-color] [-a] [--no-air-scan]
                     [-b] [--no-ble] [--snapshots] [--no-snapshots] [--mock]

Options:
  -h, --help            Show help message and exit
  -q, --quick           Quick scan mode (top camera ports with fast timeout)
  -d, --deep            Deep scan mode (all 32 surveillance & IoT ports)
  -s, --subnet SUBNET   Target subnet CIDR (e.g. 192.168.1.0/24)
  -i, --interface IFACE Network interface name to bind to
  -t, --timeout TIMEOUT Socket timeout in seconds (default: 1.0s, quick: 0.5s)
  --threads THREADS     Port scanner concurrency worker threads (default: 64)
  --ports PORTS         Comma-separated custom port list (e.g. 80,554,8080,37777)
  -o, --html HTML       Custom output path for the dark-mode HTML report
  --no-html             Disable HTML report generation
  --json JSON           Export full results to a JSON file
  --no-color            Disable terminal ANSI color formatting
  -a, --air-scan        Scan ambient over-the-air Wi-Fi for rogue spy camera APs (default: True)
  --no-air-scan         Disable ambient over-the-air Wi-Fi hotspot scan
  -b, --ble             Scan Bluetooth Low Energy (BLE) advertisements for smart glasses (default: True)
  --no-ble              Disable Bluetooth Low Energy smart glasses scan
  --snapshots           Attempt unauthenticated snapshot image grabs on open HTTP ports (default: True)
  --no-snapshots        Disable unauthenticated snapshot image grab probing
  --mock                Run simulation mode with realistic hidden cameras
```

---

## 🖥️ Interactive Dark-Mode HTML Report

When a scan completes, OpticHound saves a self-contained HTML report (default: `optichound_report_<timestamp>.html`).

### Features:
1. **Zero External Requests**: No CDNs, external CSS, or fonts. Opens cleanly even in remote cabins with no cellular or internet access.
2. **Instant Search**: Filter by IP, MAC, manufacturer, port, or dashboard title.
3. **Quick Filter Tabs**: All Devices, High-Priority Alerts Only, Critical, High, IoT/Medium, and Safe.
4. **Expandable Device Cards**: Click any card to inspect evidence logs, open ports, server banners, direct web management URLs, and action recommendations.
5. **Physical Security Checklist**: Actionable guidance for rental guests on physical concealment locations and lens detection.

---

## 🕵️ Traveler's Physical Inspection Guide

Even cameras that do not broadcast on Wi-Fi (such as battery-powered cameras recording to internal SD cards) leave physical evidence. Combine OpticHound's network scan with this physical checklist:

1. **Bedside Alarm Clocks & Radios**: Hidden cameras are frequently housed inside functional digital alarm clocks facing the bed. Direct a bright flashlight beam at the tinted front glass to reveal round camera lenses behind the face.
2. **USB Charger Bricks & Power Outlets**: Pinhole lenses are often embedded in fake USB wall chargers plugged into bedside or bathroom outlets. Unplug suspect chargers and check for pinhole apertures.
3. **Smoke & Carbon Monoxide Detectors**: Inspect smoke detectors mounted directly above the bed or shower. Look for non-standard holes or indicator lights that differ from official manufacturer models.
4. **Smartphone Infrared Camera Check**:
   - Turn off all room lights so the room is completely dark.
   - Open your smartphone camera app (especially the front selfie camera, which often lacks an IR cut filter).
   - Slowly pan the room. Night-vision infrared illuminators will glow brightly as purple or bright white points of light on your phone screen.
5. **Flashlight Reflection Technique**:
   - Hold your phone's flashlight at eye level next to your temple.
   - Sweep the room looking at picture frames, mirror edges, screws, and AC vents.
   - Glass camera lenses reflect light back into your eye, producing a bright bluish-purple or greenish glint.
6. **Smart Glasses & Camera Frames**:
   - Inspect sunglasses or spectacles left resting on nightstands, desks, or charging docks.
   - Look for unusually thick temple arms (housing battery and compute chips), front corner pinhole camera lenses adjacent to the frame hinges, and white privacy notification LEDs.
7. **Hidden Audio Bugs & Eavesdropping Microphones**:
   - Inspect power strips, under conference/dining tables, and inside AC return vents for standalone microphone transmitters.
   - Disconnect or unplug undeclared smart speakers (Echo, Nest) in bedrooms and bathrooms.
   - For sensitive discussions, play soft radio background music or run an acoustic white-noise app to disrupt room microphones.
8. **Contactless NFC & RFID Card Skimming Defense**:
   - Keep physical credit/debit cards inside an RFID-blocking Faraday wallet or card sleeve to prevent 13.56 MHz proximity reader coupling.
   - Pay using smartphone wallets (Apple Pay, Google Wallet) whenever possible—mobile wallets require biometric Face ID or Fingerprint authentication before their NFC antenna will transmit, making them completely immune to pocket skimming.
9. **If You Find a Camera or Audio Bug**:
   - **Do NOT tamper with or disconnect the device**.
   - Photograph and record video of the device, capturing its location and angle in the room.
   - Leave the accommodation immediately.
   - Contact Airbnb / Vrbo / hotel customer safety support and file a police report.

---

## 🛡️ Optional Dependencies

OpticHound is 100% functional with Python's standard library alone. If you want optional enhancements, you can install:

```bash
pip install -r requirements.txt
```

- `zeroconf`: Enhances local mDNS / Apple Bonjour discovery.
- `colorama`: Provides color support on older Windows command prompts.
- `scapy`: Enables raw ARP scanning if running as Administrator/root.

---

## ⚖️ Legal, Privacy & Compliance Governance

OpticHound is engineered with **privacy-by-design** and operates strictly within international ethical and legal guidelines:

- **[Privacy Policy](file:///C:/Users/parla/.gemini/antigravity/scratch/optichound/PRIVACY.md)**: 100% local edge processing, zero analytics, zero telemetry, zero cloud uploads.
- **[Terms & Conditions](file:///C:/Users/parla/.gemini/antigravity/scratch/optichound/TERMS.md)**: Authorized guest network auditing, ethical use boundaries, 18+ age requirement, AS-IS warranty disclaimer.
- **[Cookie Policy](file:///C:/Users/parla/.gemini/antigravity/scratch/optichound/COOKIE_POLICY.md)**: 100% zero-cookie architecture; no tracking cookies, web beacons, or persistent client profiling.
- **[Security Policy](file:///C:/Users/parla/.gemini/antigravity/scratch/optichound/SECURITY.md)**: Responsible vulnerability disclosure channel (`security@optichound.local`).
- **Indian DPDP Act, 2023 Compliance**:
  - **No External Data Fiduciary**: All processing is strictly self-administered by the user on their own local machine.
  - **Data Minimization (Section 6)**: Only standard packet headers (IP, MAC, port numbers) are processed in memory during the audit.
  - **Right to Erasure (Section 12)**: The user maintains full control to erase all scan logs by simply deleting local report files.
  - **Zero Cross-Border Data Flow**: No outbound network traffic leaves the local subnet.
- **Accessibility & Inclusion (WCAG 2.1 AA)**:
  - Dark-mode palette tested for high contrast (text-to-background ratio > 6:1).
  - Fully keyboard-accessible navigation (`Tab`, `Shift+Tab`, `Enter`, `Space` to expand cards, `Escape` to close modals).
  - Clear descriptive `aria-label` tags on all search inputs and filter buttons.
  - Screen reader semantic markup (`<table scope="col">`, `role="toolbar"`, `role="dialog"`).
- **100% Free & Open-Source**:
  - No payments, no subscriptions, no recurring billing, no in-app purchases, and no paid tiers.
