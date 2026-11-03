# Cyber Guardian / Network Sentry (v1.3.0)

**Local Network Device Discovery, Native C Packet Engine, Npcap Live Wire Capture & Real-Time Threat Detection System**  
*(Yerel Ağ Cihaz Keşif, Native C Paket Motoru, Npcap Canlı Paket Yakalama ve Gerçek Zamanlı Güvenlik Tehdit Algılama Sistemi)*

---

## Important Notice & Limitations (Sınırlamalar ve Çalışma Modları)

1. **Active Wire Packet Capture Requires Npcap**:
   - Real-time wire frame acquisition requires **[Npcap](https://npcap.com/)** (Windows) or **libpcap** (Linux).
   - On Windows, Npcap by default enforces `AdminOnly = 0x1`. In standard (non-elevated) sessions or when Npcap is not installed, the application automatically, safely, and honestly operates in **Network Inventory Mode (`ESTIMATED_NIC`)**. In this mode, telemetry is computed directly from OS socket tables (`psutil.net_connections`) and interface I/O counters without deadlocking.
   - To activate raw wire capture, install Npcap with *"WinPcap API-compatible Mode"* enabled and run Cyber Guardian as Administrator.

2. **Authorized Networks Only (Yalnızca Yetkili Ağlar)**:
   - Network scanning and port inspection must **only** be conducted on local networks and devices that you own or have explicit authorization to assess.
   - Cyber Guardian includes an explicit authorization consent gate before any ARP sweep or port probe begins.
   - Automated port scanning of newly discovered devices is disabled by default (`auto_port_scan_new_devices: false`).

3. **Safe Localhost Verification Mode**:
   - To verify that the socket scanning subsystem is functioning properly without emitting a single packet onto the external network, use the self-contained localhost test mode:
     ```powershell
     python main.py --test-localhost
     ```
   - This spins up an ephemeral local loopback TCP listener, probes it, validates detection and banner extraction, and shuts down cleanly.

4. **Alert Confidence & False Positive Reduction**:
   - MAC address changes are not always malicious ARP spoofing attacks. Router reboots, dual-band (2.4/5 GHz) Wi-Fi handoffs, mesh Wi-Fi AP roaming, and DHCP lease expirations are common in residential and corporate networks.
   - Alerts are tagged with confidence levels (`HIGH_CONFIDENCE`, `MEDIUM_CONFIDENCE`, `SUSPECTED_DHCP_OR_REBOOT`) and include `first_seen` / `last_changed` timestamps.
   - Operators can click **"Approve Expected Change"** in the GUI or call `approve_expected_change()` to update the locked gateway baseline and resolve alerts.

---

## Overview (English)

**Network Sentry** is a hybrid **Python + Native C** local area network (LAN / Wi-Fi) security monitor and desktop application built with **PySide6**. It continuously maps active hosts on your subnet, resolves hardware manufacturers offline via IEEE OUI prefixes, detects unauthorized devices and randomized MACs, performs concurrent TCP port & banner scanning, and identifies **ARP Spoofing / Man-in-the-Middle (MITM)** attacks using a zero-copy **C packet parser engine** (`packet_parser.dll` / `packet_parser.so`).

### Key Features

1. **Phase 1 — Project Foundation (`src/core/interface_detector.py`, `src/database/`)**
   - Automatic detection of active IPv4 network interfaces, subnet CIDRs, and default gateways across Windows (`route print`) and Linux (`ip route`).
   - Thread-safe **SQLite WAL (Write-Ahead Logging)** database managing `devices`, `device_history`, `security_alerts`, `port_scans`, and `scan_sessions`.
2. **Phase 2 — Device Discovery (`src/core/arp_scanner.py`, `src/utils/oui_lookup.py`)**
   - High-speed multi-threaded kernel ARP probing via Win32 `iphlpapi.SendARP` (no administrator privileges required) merged with OS ARP cache inspection (`arp -a` / `/proc/net/arp`).
   - Offline hardware manufacturer lookup (`assets/oui_database.json` with 500+ OUI prefixes) plus **Locally Administered / Randomized MAC** detection for modern iOS/Android private Wi-Fi addresses.
   - Full device lifecycle tracking (`FIRST_SEEN`, `IP_CHANGED`, `OFFLINE`, `RECONNECTED`).
3. **Phase 3 — Security Engine (`src/security/`)**
   - **ARP Spoofing & MITM Detector (`arp_spoof_detector.py`)**: Locks the Default Gateway's authentic MAC address and triggers `CRITICAL` alerts on gateway MAC changes, duplicate IP-to-MAC conflicts, gratuitous ARP poisoning, or gateway MAC cloning.
   - **Concurrent TCP Port & Banner Scanner (`port_scanner.py`)**: Scans critical ports (`21` FTP, `22` SSH, `23` Telnet, `80/443` HTTP/S, `445` SMB, `3389` RDP, `5900` VNC, `8080` Proxy, etc.) with non-intrusive service banner grabbing.
   - **Risk Scoring Engine (`risk_engine.py`)**: Computes numeric risk scores (`0–100`) and classifies devices into `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` tiers.
4. **Phase 4 — Native C Packet Engine (`src/native/`)**
   - Written in C99 (`src/native/src/packet_parser.c`, `include/packet_parser.h`) and bridged to Python via `ctypes` (`src/native/c_bridge.py`).
   - Zero-allocation parsing of raw Ethernet II, IEEE 802.1Q VLAN-tagged, ARP, and IPv4/TCP/UDP frames (~100,000 ARP frames parsed in ~19 ms).
   - Flags Gratuitous ARP packets and Ethernet Frame vs. ARP Header Sender MAC mismatches (`mac_mismatch`).
5. **Phase 5 — PySide6 Desktop Application (`src/gui/`)**
   - Modern Dark SOC theme (`src/gui/styles.py`) with 6 live KPI dashboard cards.
   - Live Device Grid with instant search, risk/status filtering, one-click trust toggling, and interactive **Device Inspector & Port Scanner Dialog** (`src/gui/views/device_detail_dialog.py`).
   - Built-in **"Simulate ARP Attack"** button that crafts and parses a spoofed Gratuitous ARP frame through the Native C Engine to demonstrate real-time MITM detection.
   - System tray integration (`QSystemTrayIcon`), desktop notifications (`src/utils/notifier.py`), and one-click **CSV & JSON Audit Report Export** (`src/utils/reporter.py`).
6. **Phase 6 — Packaging & Cross-Platform Release (`package_release.bat`)**
   - Automated C compilation, `pytest` verification (26 unit & GUI tests + standalone C test runner), and standalone executable bundling via **PyInstaller**.

---

## Architecture

```text
NetworkSentry/
├── assets/
│   └── oui_database.json            # Offline IEEE OUI MAC vendor database
├── src/
│   ├── core/
│   │   ├── interface_detector.py    # Active NIC, CIDR & Default Gateway detector
│   │   └── arp_scanner.py           # Concurrent ARP scanner & state synchronizer
│   ├── database/
│   │   ├── models.py                # Dataclasses for Devices, Alerts, Ports, History
│   │   └── db_manager.py            # Thread-safe SQLite WAL database manager
│   ├── security/
│   │   ├── arp_spoof_detector.py    # Gateway MAC lock & MITM / ARP spoofing detector
│   │   ├── port_scanner.py          # Multi-threaded TCP port & banner scanner
│   │   └── risk_engine.py           # Threat scoring (0-100) & LOW/MEDIUM/HIGH/CRITICAL
│   ├── native/
│   │   ├── include/packet_parser.h  # C header & struct definitions
│   │   ├── src/packet_parser.c      # Zero-copy Ethernet/VLAN/ARP/IPv4 C parser
│   │   ├── src/test_packet_parser.c # Standalone C unit test & benchmark suite
│   │   ├── build.bat / Makefile     # Windows & Linux GCC build scripts
│   │   └── c_bridge.py              # Python ctypes wrapper & auto-compiler
│   ├── gui/
│   │   ├── main_window.py           # PySide6 Main Window, Dashboard, Tray & Workers
│   │   ├── styles.py                # Dark cybersecurity QSS theme
│   │   └── views/
│   │       └── device_detail_dialog.py # Per-device port scanner & history inspector
│   └── utils/
│       ├── config.py                # JSON configuration manager
│       ├── logger.py                # Rotating file & console logger
│       ├── notifier.py              # System tray & desktop toast notifications
│       ├── oui_lookup.py            # Offline MAC vendor & LAA randomization resolver
│       └── reporter.py              # CSV and JSON security audit report exporter
├── tests/
│   ├── test_interfaces.py           # Phase 1 interface detection tests
│   ├── test_db.py                   # Phase 1 SQLite WAL & schema tests
│   ├── test_discovery.py            # Phase 2 OUI, ARP parser & state diff tests
│   ├── test_security.py             # Phase 3 ARP spoof, port scan & risk engine tests
│   ├── test_c_parser.py             # Phase 4 Native C ctypes roundtrip tests
│   └── test_gui_and_reporting.py    # Phase 5 Headless PySide6 GUI & export tests
├── main.py                          # Unified GUI & CLI entry point
├── package_release.bat              # Automated C build + pytest + PyInstaller script
├── config.example.json              # Example configuration file
└── requirements.txt                 # Python dependencies
```

---

## Quick Start & Installation

### 1. Create Virtual Environment & Install Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Compile the Native C Engine (`packet_parser.dll` / `.so`)
On Windows (with MinGW-w64 / MSYS2 GCC):
```powershell
cd src\native
.\build.bat
cd ..\..
```
On Linux:
```bash
cd src/native && make test && cd ../..
```
*(Note: `NativePacketEngine` in `src/native/c_bridge.py` also auto-compiles the C shared library on first run if `gcc` is available.)*

### 3. Run the Application

* **Launch PySide6 Desktop GUI (Default):**
  ```powershell
  python main.py
  ```
* **Run System & C Engine Diagnostics:**
  ```powershell
  python main.py --diagnostics
  ```
* **Run CLI Subnet Scan & Export Reports:**
  ```powershell
  python main.py --scan --export-csv reports/devices.csv --export-json reports/audit.json
  ```

---

## Running Tests

Execute the full Python & headless GUI test suite with `pytest`:
```powershell
pytest -v
```

---

## Building a Standalone Windows Executable (`.exe`)

Run the automated release packaging script:
```powershell
.\package_release.bat
```
This compiles `packet_parser.dll`, runs all unit tests, and produces `dist\NetworkSentry\NetworkSentry.exe`.

---

## Türkçe Özet (Proje Aşamaları)

* **Aşama 1 — Project Foundation:** Aktif ağ kartı (NIC) ve varsayılan ağ geçidi (Gateway) tespiti, SQLite WAL veritabanı mimarisi.
* **Aşama 2 — Device Discovery:** Çok iş parçacıklı `SendARP` tarayıcısı, çevrimdışı OUI üretici veritabanı (`assets/oui_database.json`), rastgele (Private) MAC tespiti ve cihaz durum geçmişi (`device_history`).
* **Aşama 3 — Security Engine:** Gateway MAC kilitleme ile ARP Spoofing / MITM tespiti, eşzamanlı TCP port ve servis banner tarayıcısı, 0–100 arası dinamik risk puanlama motoru (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **Aşama 4 — Native C Engine:** `packet_parser.c` ile Ethernet, 802.1Q VLAN, ARP ve IPv4 paketlerinin C seviyesinde ayrıştırılması ve `ctypes` (`c_bridge.py`) köprüsü.
* **Aşama 5 — Desktop Application:** PySide6 koyu temalı masaüstü arayüzü, canlı cihaz tablosu, arama/filtreleme, tek tıkla ARP saldırı simülasyonu, sistem tepsisi bildirimleri ve CSV/JSON raporlama.
* **Aşama 6 — Final Release:** Birim ve arayüz testleri (`pytest`), PyInstaller paketleme (`package_release.bat`) ve dokümantasyon.

---

## License

Released under the [MIT License](LICENSE).
