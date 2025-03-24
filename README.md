# KobePower Fork – Proxmark3 Ultimate Firmware v3.0

🔧 Advanced RFID/NFC Research Firmware  
🔥 Replaces Iceman fork with a faster, cleaner, Python-integrated toolchain

---

## ✅ Features

- LF / HF / UHF RFID tag support (EM410x, MIFARE, ISO14443A/B, EPC Gen2)
- Command-line interface with history, help, and tab-completion
- Signal analysis: RSSI, noise, modulation detection
- Flash memory config, tag database, wear leveling
- AI tag classification (basic offline model)
- Brute-force engine for MIFARE Classic
- Python toolchain + Makefile automation
- Firmware flashing, CLI control, signal plots
- Emergency save, watchdog, voltage protection
- SWIG interface for Python scripting & automation
- MIT licensed, 100% open source

---

## 🐍 Python Tools Included (in `Python_Tools/`)

| File | Description |
|------|-------------|
| `kobe_flash.py` | Flash firmware over serial |
| `kobe_cli.py` | Command-line shell to send commands |
| `kobe_analyzer.py` | Visualize signal data (RSSI + Noise) |
| `kobe_wrapper.i` | SWIG interface for Python integration |
| `test_communication.py` | Basic test suite for command pipeline |

---
This firmware is for educational & research use only.
Do NOT use it on tags or systems you don't own or have explicit permission to test.
Violating laws in your country is your responsibility.
Don't be stupid. Don't be illegal.

MIT License © 2025 KobePower
Feel free to fork, mod, or build on it — just give credit where it’s due.



## 🧰 Build & Python Bindings

```bash
make python_bindings
