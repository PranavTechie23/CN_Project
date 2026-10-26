# Network Traffic Analyzer & Anomaly Detector

A lightweight, passive network-monitoring tool and mini Intrusion Detection System (IDS) built with **Python 3.11+ (FastAPI, Scapy)** and **React 18 (TypeScript, Vite, Recharts, Lucide-react)**.

Designed for college network security labs, demonstrations, and passive traffic inspection without packet injection, external databases, or raw payload interception.

---

## 1. Overview & Distinction from Wireshark

| Dimension | Wireshark | Network Traffic Analyzer (Mini IDS) |
| :--- | :--- | :--- |
| **Primary Purpose** | Deep Packet Inspection (DPI) & byte-level protocol dissection | High-level traffic operations monitor & live security anomaly detector |
| **Payload Handling** | Full payload storage, disassembly, and hex inspection | **Strict zero-payload policy:** Inspects and serializes L2–L4 header metadata only; raw application payloads are discarded instantly |
| **Operational Mode** | Heavy desktop application, often analyzing static `.pcap` files | Live browser dashboard with 1-second WebSocket metric streaming |
| **Anomaly Detection**| Manual display filters and expert analysis | Automated, deterministic heuristic engine running in real-time |
| **State & Footprint** | Large memory footprint capturing raw packet buffers | Bounded in-memory circular buffers; no database required |

---

## 2. Feature Highlights & Safety Boundaries

### Core Capabilities
* **Passive Traffic Sniffing:** Safe observation using Scapy `AsyncSniffer(store=False)`. Never blocks, alters, or injects traffic.
* **L2–L4 Header Classification:** Normalizes IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, and provides a defensive fallback for unsupported protocols.
* **Real-time Rolling Metrics:** Computes moving-window throughput (`bytes/s`, `packets/s`) and protocol distribution over 60-second windows.
* **Host Directionality Tracking:** Tracks TX/RX byte counters and per-host bandwidth rates for up to 1,000 active endpoints.
* **Deterministic Anomaly Detection:** Real-time heuristic alerts for TCP Port Scans, SYN Floods, and ARP Spoofing/Conflicts.
* **Interactive Operations Dashboard:** Built with React, Vite, Recharts, and Lucide icons featuring KPI cards, charts, sortable host tables, packet metadata inspector, and alert acknowledgement.

### Explicit Safety Boundaries
* **Loopback-Only Binding:** Backend binds strictly to `127.0.0.1:8000`. Unauthenticated endpoints are never exposed to external networks.
* **Zero-Payload Guarantee:** Packet payloads (`Raw.load`) are never stored, logged, or serialized across API responses or WebSockets.
* **Safe Lab Generator:** Lab evaluation tools (`scripts/lab/traffic_generator.py`) include strict destination IP guards refusing to target public or external addresses.

---

## 3. Architecture & Data Flow

```text
       +-----------------------------------------------------------+
       |                  Physical / Virtual Interface             |
       |                (eth0, wlan0, lo0, Mininet netns)          |
       +-----------------------------+-----------------------------+
                                     |
                                     v  (Passive promiscuous read, store=False)
       +-----------------------------------------------------------+
       |              CaptureManager (Scapy AsyncSniffer)          |
       +-----------------------------+-----------------------------+
                                     |
                                     v  Raw Scapy Packet
       +-----------------------------------------------------------+
       |         Packet Parser (Zero-Payload L2-L4 Normalization)  |
       +-----------------------------+-----------------------------+
                                     |
                                     v  Immutable PacketObservation
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
+---------------------------------+     +---------------------------------+
|       MetricsStore              |     |        DetectionEngine          |
| - Total session bytes/packets   |     | - Rule A: Port Scan Detector    |
| - Protocol breakdown            |     | - Rule B: SYN Flood Detector    |
| - Rolling window throughput     |     | - Rule C: ARP Spoof Detector    |
| - Host TX/RX rates (top talkers)|     +----------------+----------------+
| - Bounded packet ring buffer    |                      |
+----------------+----------------+                      v
                 |                              +-----------------+
                 |                              |   AlertStore    |
                 |                              | - Deduplication |
                 |                              | - Cooldowns     |
                 |                              | - Bounded FIFO  |
                 |                              +--------+--------+
                 +-------------------+-------------------+
                                     |
                                     v
       +-----------------------------------------------------------+
       |               FastAPI Application Layer                   |
       |  - REST Endpoints (/api/capture, /api/metrics, /api/alerts)|
       |  - Periodic Streaming WebSocket (/ws/live @ 1 Hz)         |
       +-----------------------------+-----------------------------+
                                     |
                                     v  HTTP / WebSocket (JSON)
       +-----------------------------------------------------------+
       |           React + TypeScript Dashboard (Vite)             |
       |  - KPIs, Recharts Visualizations, Host Table, Alert Feed  |
       +-----------------------------------------------------------+
```

---

## 4. Prerequisites & Tested Environments

* **Python:** Version 3.11 or newer (tested on **Python 3.13.15**).
* **Node.js:** Version 18 or newer (tested on **Node.js v24.19.0**, npm 11.1.0).
* **Supported Operating Systems:**
  * **Linux:** Ubuntu 22.04 LTS / 24.04 LTS, Debian 12, Alpine Linux (inside Mininet or host VMs).
  * **macOS:** macOS Sonoma / Sequoia (Darwin 24) on Apple Silicon and Intel.

---

## 5. Installation & Quickstart

### Step 1: Clone Repository & Setup Environment
```bash
git clone <repo-url> sniffy
cd sniffy
```

### Step 2: Backend Setup
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the backend API server:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
* Verify health: `curl http://127.0.0.1:8000/api/health`
* Response: `{"status":"ok","service":"network-traffic-analyzer"}`

### Step 3: Frontend Setup
In a new terminal window:
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser. The Vite dev proxy automatically forwards `/api` and `/ws` to `http://127.0.0.1:8000`.

---

## 6. Packet Capture Permissions & Interface Guidance

Passive packet sniffing requires raw socket access (`CAP_NET_RAW` / `CAP_NET_ADMIN` on Linux, or BPF device read permissions on macOS).

### Recommended: Running with Non-Root Capabilities (Linux)
To allow the backend Python environment to capture packets without running `sudo`:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

### Running with Sudo (Linux)
Alternatively, start the uvicorn process directly with root privileges:
```bash
sudo $(pwd)/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Selecting the Monitored Interface
The frontend provides a real-time interface picker listing all system interfaces discovered via `psutil`:
* **Linux Standard:** `eth0`, `enp0s3`, `wlan0`.
* **macOS:** `en0` (Wi-Fi), `lo0` (loopback).
* **Mininet Virtual Topologies:**
  * When running inside an isolated host network namespace (e.g. `mininet> h2 xterm`): select `h2-eth0`.
  * When running in the root OS namespace monitoring an Open vSwitch bridge: select `s1-eth1` or `s1-eth2`.

For detailed Mininet network namespace instructions, consult [LAB_GUIDE.md](LAB_GUIDE.md).

---

## 7. Anomaly Detection Rules & Heuristics

The engine executes three deterministic detection algorithms against incoming `PacketObservation` metadata:

| Rule ID | Rule Name | Window | Threshold | Heuristic Condition |
| :--- | :--- | :--- | :--- | :--- |
| `PORT_SCAN` | TCP Port Scan | 10 seconds | 15 distinct ports | A single source IP sends bare SYN packets (`SYN=1, ACK=0`) to $\ge 15$ unique destination ports on the same target IP within 10 seconds. |
| `SYN_FLOOD` | Possible SYN Flood | 5 seconds | 100 packets | A single destination IP receives $\ge 100$ bare SYN packets (`SYN=1, ACK=0`) within 5 seconds. |
| `ARP_SPOOF` | Possible ARP Spoofing | 60 seconds | 2 distinct MACs | Two or more distinct MAC addresses claim the same IPv4 address in ARP requests/replies within 60 seconds. |

### Deduplication & Evidence
* **Cooldown Deduplication:** Repeated alerts for the same source/target are throttled using a 30-second cooldown window. Instead of flooding alerts, existing alerts increment `occurrence_count` and update `last_seen`.
* **Evidence Payloads:** Alerts include structured JSON evidence containing timestamps, port samples, observed rates, and conflicting MAC addresses.

### Overriding Thresholds for Demonstrations
For quick lab demonstrations (e.g. on low-throughput VMs), thresholds can be adjusted without code modifications using environment variables in `backend/.env`:

```ini
# backend/.env
PORT_SCAN_UNIQUE_PORTS_THRESHOLD=5
PORT_SCAN_WINDOW_SECONDS=10

SYN_FLOOD_SYN_THRESHOLD=25
SYN_FLOOD_WINDOW_SECONDS=5

ARP_CONFLICT_WINDOW_SECONDS=60
```

---

## 8. REST API & WebSocket Contracts

### REST Endpoints

| Method | Path | Description | Query / Body Params |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status | None |
| `GET` | `/api/capture/interfaces` | List available system interfaces | None |
| `GET` | `/api/capture/status` | Current capture engine state and counters | None |
| `POST` | `/api/capture/start` | Start passive capture | `{"interface": "en0"}` |
| `POST` | `/api/capture/stop` | Stop active capture | None |
| `GET` | `/api/metrics/summary` | Global totals, protocol breakdown, and bandwidth | `?window=60` (seconds, range 5–3600) |
| `GET` | `/api/metrics/hosts` | Top talkers sorted by observed volume | `?window=60&sort_by=bytes\|tx\|rx&limit=10` |
| `GET` | `/api/packets` | Recent packet metadata buffer | `?limit=50&protocol=TCP` (max 100) |
| `GET` | `/api/alerts` | List detected anomaly alerts | `?acknowledged=false&severity=high` |
| `POST` | `/api/alerts/{id}/acknowledge` | Mark an alert as acknowledged | Path parameter `id` |

### WebSocket Endpoint (`/ws/live`)
* **Cadence:** Pushes an aggregated snapshot every 1.0 second.
* **Payload Structure:**
```json
{
  "type": "snapshot",
  "timestamp": "2026-10-21T10:00:00Z",
  "capture": { "state": "running", "interface": "en0", "packets_seen": 420 },
  "summary": { "session": { "packets": 420, "bytes": 85000 }, "window": { "bytes_per_second": 1420.5 } },
  "top_hosts": [ ... ],
  "recent_packets": [ ... ],
  "alerts": { "items": [ ... ], "total": 2, "unacknowledged_count": 1 }
}
```

---

## 9. Testing & Build Verification

The backend test suite is completely decoupled from real network interfaces and raw socket permissions using synthetic fixtures and dependency injection.

### Running Backend Tests
```bash
cd backend
PYTHONPATH=. .venv/bin/pytest tests/ -v
```
* **Coverage:** 49 test cases covering parser layers, rolling window rate calculations, host directionality, Rule A/B/C detectors, deduplication, alert store eviction, REST routes, and end-to-end multi-host simulation.

### Running Frontend Type Check & Production Build
```bash
cd frontend
npm run build
```
Executes `tsc` (TypeScript type check) and Vite production bundling to `frontend/dist/`.

---

## 10. Lab Demonstration Runbook

We provide a standalone, safety-guarded traffic generator in `scripts/lab/traffic_generator.py`. It refuses to target non-RFC1918 private addresses.

### 1. Normal Traffic Baseline (No Alerts)
Generate benign HTTP/DNS queries and verify metrics increase with **0 alerts**:
```bash
python scripts/lab/traffic_generator.py benign --target 10.0.0.2 --count 20
```

### 2. TCP Port Scan Demonstration (Triggers Rule A)
Send bare SYNs to 20 distinct ports on the target:
```bash
python scripts/lab/traffic_generator.py port-scan --target 10.0.0.2 --ports 1-20
```
* **Dashboard Result:** Alert `PORT_SCAN` appears under High Severity with evidence listing the probed ports.

### 3. SYN Flood Anomaly Demonstration (Triggers Rule B)
Send 120 bare SYNs to port 80 of the target within 2 seconds:
```bash
python scripts/lab/traffic_generator.py syn-flood --target 10.0.0.2 --count 120 --rate 60
```
* **Dashboard Result:** Alert `SYN_FLOOD` appears indicating the packet threshold was exceeded.

### 4. Synthetic ARP Conflict Demonstration (Triggers Rule C)
Send conflicting ARP responses for the same IP address using two distinct MAC addresses:
```bash
python scripts/lab/traffic_generator.py arp --target 10.0.0.2 --count 2
```
* **Dashboard Result:** Alert `ARP_SPOOF` appears showing both conflicting MAC addresses in the evidence drawer.

*(For full Mininet multi-node instructions and Wireshark cross-verification steps, see [LAB_GUIDE.md](LAB_GUIDE.md).)*

---

## 11. Known Limitations & Technical Nuances

1. **Heuristic Detection vs. Ground Truth:**
   * **Rule A (Port Scan):** Legitimate security vulnerability scanners (e.g. Nessus, OpenVAS) or network discovery tools may trigger this heuristic.
   * **Rule B (SYN Flood):** High-traffic web servers or benchmark testing may exceed the threshold without a malicious denial-of-service attack.
   * **Rule C (ARP Conflict):** Mobile devices with randomized MACs re-associating, high-availability router failovers (VRRP/HSRP), or dual-homed NICs can cause benign MAC changes.
2. **Asymmetric Routing:**
   * Passive sniffers can only analyze traffic traversing the monitored link. If outbound packets take path A and inbound return packets take path B, full TCP handshakes may appear incomplete.
3. **Bandwidth & Dropped Packets:**
   * High-throughput links (>1 Gbps) may cause packet drops if the single-threaded Python packet callback cannot keep pace. For multi-gigabit workloads, kernel-level ring buffers (e.g. AF_PACKET, DPDK) are required.
4. **Encrypted Payloads:**
   * Modern network traffic (TLS 1.3, QUIC, HTTPS) encrypts application payloads. Sniffy operates exclusively on L2–L4 header metadata and never inspects encrypted content.
5. **In-Memory Session Lifecycle:**
   * All metrics, packet histories, and alerts are stored purely in memory. Stopping capture or restarting the backend resets the session counters. No historical database is maintained.
6. **Host Accounting Note:**
   * Unicast packets contribute to TX for the source host and RX for the destination host. Consequently, the sum of total host bytes in the Top Talkers table is approximately **twice** the observed physical wire byte count.

---

## 12. Security & Deployment Warning

> [!WARNING]
> **UNAUTHENTICATED LOCAL TOOL ONLY:**
> This application is built as an educational demonstration and local operations dashboard. It does **not** implement user authentication, session authorization, or CSRF protection.
> 
> * **DO NOT** bind the backend to `0.0.0.0` or expose port `8000` / `5173` to the public internet or untrusted local area networks.
> * If remote access is required, place the application behind a secure SSH tunnel or reverse proxy with TLS and mutual authentication.
