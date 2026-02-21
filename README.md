# 📡 PacketScope — Network Packet Analyzer

A real-time network packet analyzer web app powered by **Wireshark / tshark**.  
Capture live traffic from any network interface, or upload `.pcap` / `.pcapng` files for deep inspection — all from a sleek browser UI.

![PacketScope UI](https://img.shields.io/badge/UI-Deep%20Space%20Theme-blueviolet?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## ✨ Features

- **Live capture** — stream packets in real-time using Server-Sent Events (SSE)
- **PCAP upload** — analyze existing `.pcap` / `.pcapng` captures
- **Smart filtering** — instant show/hide filter by IP, protocol, info, or port (no DOM rebuild)
- **Protocol stats** — live doughnut chart + bar breakdown by protocol
- **Packet inspector** — click any row to expand raw tshark JSON layers
- **Protocol color coding** — TCP, UDP, DNS, TLS, ICMP, ARP and more, each with a distinct color
- **High performance** — chunked rendering, rAF-coalesced stats, DOM element caching

## 🖥️ Tech Stack

| Layer    | Technology |
|----------|-----------|
| Backend  | Python 3, Flask, Flask-CORS |
| Capture  | Wireshark / tshark (subprocess) |
| Frontend | Vanilla HTML / CSS / JS (no framework) |
| Streaming | Server-Sent Events (SSE) |
| Charts   | Chart.js |

---

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10+**
2. **Wireshark** (with tshark on PATH) — [download here](https://www.wireshark.org/download.html)
3. **Npcap** (Windows only, for live capture) — [download here](https://npcap.com/#download)

### Install & Run

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/packet-analyzer.git
cd packet-analyzer

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Run the app (requires admin/sudo for live capture)
python app.py
```

Then open **http://localhost:5000** in your browser.

> ⚠️ **Windows:** Run as Administrator for live capture (tshark needs elevated privileges for Npcap).

---

## 📂 Project Structure

```
packet-analyzer/
├── app.py               # Flask backend — routes, tshark integration, SSE
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # Main page
└── static/
    ├── style.css        # Deep-space dark theme
    └── app.js           # Frontend logic (capture, filter, render, stats)
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Main UI |
| `GET`  | `/api/tshark-check` | Check tshark availability |
| `GET`  | `/api/interfaces` | List network interfaces `{id, name}` |
| `POST` | `/api/capture/start` | Start live capture `{interface: "1"}` |
| `POST` | `/api/capture/stop` | Stop live capture |
| `GET`  | `/api/stream` | SSE stream of live packets |
| `POST` | `/api/upload` | Upload a `.pcap`/`.pcapng` file |
| `GET`  | `/api/packet-detail/<session>/<idx>` | Lazy-fetch raw packet layers |

---

## 📸 Screenshots

> _Start a capture or upload a pcap — packets stream in real-time with protocol-color-coded rows._

---

## 📄 License

MIT © 2026
