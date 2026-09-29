# esp32-deauth-detector
ESP32-based Wi-Fi Deauth Attack Detector with PRESENT encryption and email alerts

# ESP32 Deauth Attack Detector

An ESP32-based Wi-Fi Deauthentication (Deauth) attack detector with **PRESENT cipher** encryption and automated email alerts.

---

## 📋 Overview

This project implements a security monitoring system on the ESP32 that:

1. **Sniffs the air** — Captures management frames on Wi-Fi channel 6
2. **Detects Deauth attacks** — Identifies Deauth frames (Subtype 0x0C) and logs their details
3. **Encrypts data** — Encrypts attack info (count, timestamp, attacker MAC, reason code) using the PRESENT cipher
4. **Sends alerts** — Delivers email notifications via SMTP over TLS
5. **Displays status** — Shows real-time status on a 16×2 LCD and an LED indicator

---

## 🛠️ Hardware

| Component | Description |
|-----------|-------------|
| ESP32 DevKit | Main microcontroller |
| LCD 16×2 (HD44780) | Status display |
| LED | Alert indicator |
| Resistors & wires | For connections |

### 🔌 LCD Wiring

| LCD Pin | ESP32 GPIO |
|---------|------------|
| RS      | GPIO 22    |
| E       | GPIO 23    |
| D4      | GPIO 18    |
| D5      | GPIO 19    |
| D6      | GPIO 21    |
| D7      | GPIO 5     |
| LED     | GPIO 2     |

---

## 🧠 How It Works
┌──────────────────────────────────────────┐
│ 1. Connect to Wi-Fi (STA Mode) │
│ 2. Enable Promiscuous Mode (Sniffer) │
│ 3. Capture Deauth frames │
│ 4. Encrypt data with PRESENT cipher │
│ 5. Send email via SMTP over TLS │
│ 6. Display alert on LCD + LED │
└──────────────────────────────────────────┘

text

### Detection Flow

| Phase | Description |
|-------|-------------|
| **Phase 1** | Attack detected + 10-second settle delay |
| **Phase 2** | Stop sniffer + reconnect to Wi-Fi |
| **Phase 3** | Encrypt + send email + resume sniffer |

---

## 📁 Project Structure
blink/
├── main/
│ ├── blink_example_main.c # Main application code
│ ├── CMakeLists.txt
│ ├── Kconfig.projbuild
│ └── idf_component.yml
├── components/
│ └── present_cipher/ # PRESENT cipher library
│ ├── present_cipher.c
│ ├── present_cipher.h
│ └── CMakeLists.txt
├── .gitignore
├── CMakeLists.txt
└── README.md

text

---

## 🔐 PRESENT Cipher

| Property | Value |
|----------|-------|
| Cipher type | Block Cipher |
| Block size | 64 bits (8 bytes) |
| Key size | 80 bits (10 bytes) |
| Rounds | 31 + final round |
| Operations | AddRoundKey, S-Box, P-Box |

> ⚠️ **Note:** Decryption is a placeholder in this version and is not fully implemented.

---

## ⚙️ Configuration

### 1. Environment Requirements

- [ESP-IDF v5.x](https://docs.espressif.com/projects/esp-idf/)
- Python 3.8+
- VS Code + ESP-IDF Extension (optional)

### 2. Edit Settings

Open `main/blink_example_main.c` and modify:

```c
#define WIFI_SSID       "your_wifi_ssid"
#define WIFI_PASS       "your_wifi_password"

#define SMTP_USERNAME   "your.email@gmail.com"
#define SMTP_PASSWORD   "your_app_password"
#define EMAIL_TO_1      "recipient1@example.com"
#define EMAIL_TO_2      "recipient2@example.com"
⚠️ Security Warning: Use a Google App Password, not your regular account password.

3. Build & Flash
bash
idf.py set-target esp32
idf.py build
idf.py -p COMx flash monitor
📊 Example Email Alert
text
Subject: [PRESENT-ALERT] Deauth Attack Detected

[PRESENT-ALERT]
Encrypted Data: A1B2C3D4E5F60718293A4B5C6D7E8F90
⚠️ Security Warnings
Never commit credentials (WiFi/SMTP) to a public repository

Revoke any leaked App Password immediately

Educational use only — using this system against networks you do not own is illegal

🧪 Built With
ESP-IDF — ESP32 development framework

mbedTLS — TLS/SSL library

hd44780 — LCD driver library

📜 License
This project is for educational and research purposes. Use responsibly
