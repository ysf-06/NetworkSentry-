# Network Sentry 🛡️

**Network Sentry** is a real-time local network discovery, intruder detection, ARP spoofing analyzer, and security monitoring desktop application built with Python, a high-performance Native C packet engine, SQLite (WAL), and PySide6.

## Roadmap Status
- [x] **Phase 1 — Project Foundation**: Directory structure, Python virtual environment, Git setup, Network Interface & Gateway auto-detection, SQLite WAL persistence layer, and unit tests.
- [ ] **Phase 2 — Device Discovery**: Active ARP scanning, IP/MAC collection, offline IEEE OUI vendor lookup, device state tracking, and new device detection.
- [ ] **Phase 3 — Security Engine**: ARP table change analysis, MITM / ARP spoofing detection, concurrent TCP port scanning, and device risk scoring.
- [ ] **Phase 4 — Native C Engine**: Npcap/libpcap raw packet parsing in C, `ctypes` bridge, and C unit tests.
- [ ] **Phase 5 — Desktop Application**: Modern dark-themed PySide6 GUI, live device table, system tray toast notifications, and CSV/JSON audit reporting.
- [ ] **Phase 6 — Final Release**: Cross-platform verification, PyInstaller standalone executable packaging, documentation, and v1.0.0 release.

## Quick Start (Phase 1 Diagnostics)

```powershell
# Run Phase 1 Foundation Diagnostics
.\.venv\Scripts\python.exe main.py

# Run Automated Unit Tests
.\.venv\Scripts\pytest.exe -v
```
