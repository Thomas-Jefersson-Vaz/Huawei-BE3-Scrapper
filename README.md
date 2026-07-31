# Huawei WiFi BE3 (WS8100) Zabbix Scraper

[![Zabbix 7.0 Compatible](https://img.shields.io/badge/Zabbix-7.0-blue.svg)](https://www.zabbix.com/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-green.svg)](https://www.python.org/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-blue)](https://www.docker.com/)

An asynchronous, containerized Python scraper for monitoring **Huawei WiFi BE3 (WS8100)** routers with **Zabbix 7.0+** and **Grafana**.

It uses native SCRAM authentication to interface with HarmonyOS router APIs, collects real-time router health, WAN stats, bandwidth, and connected device details (including connection band **2.4 GHz / 5 GHz / Ethernet**), pushing telemetry directly into Zabbix via the Trapper protocol and Low-Level Discovery (LLD).

---

## ✨ Features

- **HarmonyOS SCRAM Auth**: Full challenge-response authentication with automatic CSRF token management and 60s session backoff protection against rate limits (`Too_Many_user`).
- **Endpoint Fallback Discovery**: Automatically handles API endpoint variations across Huawei firmware builds, preventing 404 authentication loops.
- **Low-Level Discovery (LLD)**: Auto-discovers online network devices and provisions per-device monitoring items in Zabbix.
- **WiFi Band Detection**: Identifies whether connected devices are on **2.4 GHz**, **5 GHz**, **6 GHz**, or **Ethernet**.
- **Smart Hostname Fallbacks**: Solves empty device names by inspecting `HostName`, `ActualName`, `DeviceName`, `UserDeviceName`, or falling back to IP/MAC labels.
- **Ready-to-Use Zabbix Template**: Pre-configured `zabbix_template.xml` with valid UUIDv4 identifiers, value maps, and discovery rules for Zabbix 7.0+.

---

## 📊 Monitored Metrics

### Router & System Metrics
| Metric Key | Description | Type |
|---|---|---|
| `huawei.router.name` | Friendly Router Name | String |
| `huawei.router.model` | Model (e.g. `WUKUN-BE32-40`) | String |
| `huawei.router.firmware` | Software / Firmware Version | String |
| `huawei.router.hardware` | Hardware Revision | String |
| `huawei.router.harmonyos` | HarmonyOS Version | String |
| `huawei.router.serial` | Serial Number | String |
| `huawei.router.uptime` | System Uptime (seconds) | Numeric |

### WAN Metrics
| Metric Key | Description | Type |
|---|---|---|
| `huawei.wan.status` | WAN Connection Status (1 = Connected, 0 = Disconnected) | Integer (Value Map) |
| `huawei.wan.external_ip` | Public WAN IP Address | String |
| `huawei.wan.uptime` | WAN Connection Uptime (seconds) | Numeric |
| `huawei.wan.upload_rate` | Real-time WAN Upload Speed (Bps) | Numeric |
| `huawei.wan.download_rate` | Real-time WAN Download Speed (Bps) | Numeric |

### Connected Device Metrics (LLD)
| Metric Key Prototype | Description | Type |
|---|---|---|
| `huawei.devices.count` | Total Number of Active Connected Devices | Integer |
| `huawei.device.ip[{#MAC}]` | IP Address of Discovered Device | String |
| `huawei.device.hostname[{#MAC}]` | Hostname / Display Name | String |
| `huawei.device.access_type[{#MAC}]` | Connection Band / Type (`2.4 GHz`, `5 GHz`, `Ethernet`) | String |
| `huawei.device.upload[{#MAC}]` | Real-time Upload Rate (Bps) | Numeric |
| `huawei.device.download[{#MAC}]` | Real-time Download Rate (Bps) | Numeric |

---

## 📁 Repository Structure

```text
├── .env.example         # Template for environment configuration
├── .gitignore           # Ignores secrets, caches, and logs
├── Dockerfile           # Lightweight Python 3.12-slim container build
├── docker-compose.yml   # Container orchestra file
├── requirements.txt     # Dependencies (aiohttp, py-zabbix)
├── crypto.py            # SCRAM auth & proof calculation helpers
├── huawei_client.py     # Async Huawei HTTP client & API failover
├── zabbix_push.py       # Zabbix Trapper client & LLD builder
├── scraper.py           # Polling execution loop & error handling
└── zabbix_template.xml  # Importable Zabbix 7.0 Template
```

---

## 🚀 Quick Start

### 1. Configure Environment
Copy `.env.example` to `.env` and fill in your details:

```bash
cp .env.example .env
```

Edit `.env`:
```env
ROUTER_HOST=192.168.3.2
ROUTER_PASSWORD=YourRouterPasswordHere

ZABBIX_SERVER=10.0.1.192
ZABBIX_PORT=10051
ZABBIX_HOST_NAME=HuaweiBE3

SCRAPE_INTERVAL=30
LOG_LEVEL=INFO
```

> **Note**: `ZABBIX_HOST_NAME` must match the exact Host name configured in Zabbix.

### 2. Import Zabbix Template
1. Open your **Zabbix Web UI**.
2. Navigate to **Data collection** ➔ **Templates** ➔ Click **Import**.
3. Select `zabbix_template.xml` and click **Import**.
4. Create a host named **`HuaweiBE3`** (or matching your `ZABBIX_HOST_NAME`) and link the **`Huawei BE3 Router`** template to it.

### 3. Build & Run Container

```bash
docker compose up -d --build
```

To view real-time logs:
```bash
docker compose logs -f
```

---

## 🛠️ Troubleshooting

- **`Too_Many_user` Error**: The Huawei router restricts active HTTP sessions. The scraper includes automatic 60-second backoff logic to allow session timeouts before retrying.
- **Metrics show as unsupported in Zabbix**: Ensure the Host Name in Zabbix matches `ZABBIX_HOST_NAME` in `.env` character-for-character.
- **Debugging**: Set `LOG_LEVEL=DEBUG` in `.env` and restart the container (`docker compose restart`) to view full raw JSON metric payloads.
