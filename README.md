# 🛡️ NetGuard — AI-Powered Network Security Monitor

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Groq%20%7C%20LLaMA%203.3--70B-blueviolet?logo=meta&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows&logoColor=white" />
</p>

> **NetGuard** scans your local network, identifies every connected device, analyzes each one for security vulnerabilities using AI, and visualizes the results in a real-time dashboard — all from a single Python command.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Network Discovery** | ARP-based scan finds every live device on your subnet automatically |
| 🔌 **Deep Port Scanning** | nmap TCP connect scan across 70+ dangerous ports — no root/admin required |
| 🤖 **AI Risk Scoring** | Groq-powered LLaMA 3.3-70B analyzes device context and assigns a risk score (0–100) |
| 📡 **Shodan Enrichment** | Queries Shodan InternetDB for known CVEs, device tags, and historical port data |
| 🧮 **Hybrid Scoring** | Final score blends AI judgment (60%) with deterministic rule engine (40%) |
| 🗺️ **Network Topology** | Interactive graph showing devices, connections, and lateral movement paths |
| ⚔️ **Attack Simulator** | Simulates WannaCry, Mirai, MITM, Brute-force, and Ransomware attacks on your network |
| 💬 **AI Copilot** | Ask plain-English questions about your entire network's security posture |
| 🔔 **Real-Time Alerts** | WebSocket-pushed alerts for critical and high severity findings |
| 💾 **Persistent Storage** | SQLite database stores scan history, device profiles, and alerts |

---

## 🖼️ How It Works

```
Your Network
     │
     ▼
[ARP Discovery] ──► finds all live devices
     │
     ▼
[nmap Deep Scan] ──► TCP connect on 70+ dangerous ports, OS + version detection
     │
     ▼
[Shodan InternetDB] ──► CVEs, device tags, historical exposure
     │
     ▼
[Firmware Estimator] ──► estimates firmware age from service banners
     │
     ▼
[AI Engine (Groq / LLaMA 3.3-70B)] ──► contextual risk analysis + remediation
     │
     ▼
[Rule Engine] ──► deterministic scoring for known dangerous configurations
     │
     ▼
[Score Blender] ──► final score = AI×0.6 + Rules×0.4
     │
     ▼
[FastAPI + WebSocket] ──► real-time dashboard in your browser
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- [nmap](https://nmap.org/download.html) installed and on your PATH
- A free [Groq API key](https://console.groq.com/)

### 1. Clone the repository

```bash
git clone https://github.com/your-username/netguard.git
cd netguard
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

Create a `.env` file in the project root (or edit the existing one):

```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
SCAN_INTERVAL=300
RISK_THRESHOLD_CRITICAL=80
RISK_THRESHOLD_HIGH=60
RISK_THRESHOLD_MEDIUM=40
```

> ⚠️ **Never commit your `.env` file.** Add it to `.gitignore`.

### 4. Run NetGuard

```bash
python main.py
```

NetGuard will start a local server and automatically open the dashboard in your browser at `http://127.0.0.1:<port>`.

---

## 📁 Project Structure

```
netguard/
├── main.py                        # Entry point — starts FastAPI + opens browser
├── attack_simulator.py            # AI-powered attack scenario simulator
├── graph_builder.py               # Network topology graph (NetworkX)
│
├── api/
│   └── server.py                  # FastAPI app, REST endpoints, WebSocket
│
├── core/
│   ├── pipeline.py                # Orchestrates discovery → scan → analyze flow
│   │
│   ├── scanner/
│   │   ├── arp_scan.py            # ARP-based device discovery
│   │   └── port_scan.py          # nmap TCP connect deep scan
│   │
│   ├── enrichment/
│   │   └── shodan_lookup.py      # Shodan InternetDB queries
│   │
│   ├── profiler/
│   │   └── firmware_checker.py   # Firmware age estimation from banners
│   │
│   ├── risk/
│   │   ├── ai_engine.py          # Groq AI scoring, chat, and copilot
│   │   ├── rule_engine.py        # Deterministic rule-based scoring
│   │   └── score_blender.py      # Blends AI + rule scores into final score
│   │
│   └── storage/
│       └── database.py           # SQLite persistence layer
│
├── frontend/
│   └── index.html                 # Single-file dashboard (HTML + JS + CSS)
│
├── requirements.txt
└── .env
```

---

## 🔌 API Reference

All endpoints are served by the FastAPI backend. Once running, interactive docs are available at `http://127.0.0.1:<port>/docs`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/devices` | List all discovered devices and their risk data |
| `GET` | `/api/devices/{ip}/history` | Scan history for a specific device |
| `POST` | `/api/scan` | Trigger an ARP discovery scan |
| `POST` | `/api/devices/{ip}/deep-scan` | Trigger a full deep scan for one device |
| `POST` | `/api/scan/deep-all` | Deep scan all unscanned devices |
| `GET` | `/api/alerts` | Fetch unread critical/high severity alerts |
| `POST` | `/api/alerts/read` | Mark all alerts as read |
| `GET` | `/api/topology` | Network topology graph (nodes + edges) |
| `GET` | `/api/status` | Server health check |
| `POST` | `/api/chat` | Ask the AI about a specific device |
| `POST` | `/api/copilot` | Ask the AI about your entire network |
| `POST` | `/api/simulate/{attack_type}` | Simulate a cyber attack on your network |
| `WS` | `/ws` | WebSocket stream for real-time scan events |

### Attack Types

| Key | Name | Entry Ports |
|---|---|---|
| `wannacry` | WannaCry Ransomware | 445, 139 |
| `mirai` | Mirai Botnet | 23, 2323 |
| `mitm` | Man-in-the-Middle | 80, 21 |
| `bruteforce` | Default Credential Attack | 22, 3389 |
| `ransomware` | Generic Ransomware | 445, 3389 |

---

## 🧠 AI Risk Scoring

NetGuard uses a **two-layer scoring system**:

### Layer 1 — AI Engine (Groq / LLaMA 3.3-70B)
The AI receives the full device context: OS, all open ports with version banners, Shodan CVEs, device tags, and firmware age. It returns:
- A risk score (0–100)
- Severity classification (`critical` / `high` / `medium` / `low`)
- Plain-English explanation
- A specific remediation action
- Per-port risk analysis

### Layer 2 — Rule Engine
Deterministic fallback that scores based on:
- Dangerous port severity (critical: +30, high: +20, medium: +10)
- Known CVEs from Shodan (+10 per CVE, capped at 30)
- Outdated firmware detected from banners (+10)

### Final Score
```
final_score = (ai_score × 0.6) + (rule_score × 0.4)
```

| Score | Severity |
|---|---|
| 80–100 | 🔴 Critical |
| 60–79 | 🟠 High |
| 40–59 | 🟡 Medium |
| 0–39 | 🟢 Low |

---

## ⚙️ Configuration

All settings are controlled via the `.env` file:

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | *(required)* | Your Groq API key |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Groq model to use |
| `SCAN_INTERVAL` | `300` | Seconds between automatic ARP scans |
| `RISK_THRESHOLD_CRITICAL` | `80` | Score threshold for critical alerts |
| `RISK_THRESHOLD_HIGH` | `60` | Score threshold for high alerts |
| `RISK_THRESHOLD_MEDIUM` | `40` | Score threshold for medium alerts |

---

## ⚠️ Legal & Ethical Use

> **Only scan networks you own or have explicit written permission to test.**
>
> NetGuard is designed for home and authorized office networks. Running network scans against systems you do not own may be illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction.
>
> The attack simulator is a **read-only educational tool** — it analyzes scan data already in the database and does not send any packets to devices.

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI, uvicorn, asyncio
- **Scanning:** python-nmap (nmap TCP connect — no root required)
- **AI:** Groq API — LLaMA 3.3-70B Versatile
- **Threat Intel:** Shodan InternetDB (free, no API key needed)
- **Graph:** NetworkX
- **Storage:** SQLite (via built-in `sqlite3`)
- **Frontend:** Vanilla HTML/CSS/JS (zero build step)
- **Real-time:** WebSockets

---

## 🤝 Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">Built with ❤️ for home network security awareness</p>
