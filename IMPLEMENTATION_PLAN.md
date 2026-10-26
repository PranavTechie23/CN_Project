# Implementation Plan: Network Traffic Analyzer & Anomaly Detector

**Project:** College Mini-Project / Mini IDS  
**Primary Stack:** Python 3.11+ (FastAPI, Scapy), React + TypeScript + Vite, Recharts  
**Source of Truth:** [network_traffic_analyzer_prd.md](network_traffic_analyzer_prd.md)

---

## Progress Overview

- [x] **Phase 0: Technical Skeleton & Health Check** *(Completed)*
- [x] **Phase 1: Data Schemas & Pure Packet Parser** *(Completed)*
- [x] **Phase 2: In-Memory Metrics Store & Rolling Bandwidth** *(Completed)*
- [x] **Phase 3: Detection Engine & Alert Store** *(Completed)*
- [x] **Phase 4: Capture Manager & REST API Integration** *(Completed)*
- [x] **Phase 5: WebSocket & Live Dashboard UI** *(Completed)*
- [x] **Phase 6: Lab Validation & Detector Tuning** *(Completed)*
- [x] **Phase 7: Stabilization, Documentation & Release Readiness** *(Completed)*

---

## Detailed Task Breakdown

### Phase 0: Technical Skeleton & Health Check
- [x] Inspect environment (Python 3.13, Node v24, npm 11).
- [x] Create repository structure (`backend/` and `frontend/`).
- [x] Create `.gitignore`, `.env.example`, and README skeleton.
- [x] Create `IMPLEMENTATION_PLAN.md` tracking progress.
- [x] Build FastAPI application with configuration and `GET /api/health`.
- [x] Build React + TypeScript + Vite frontend with health check status display.
- [x] Configure Vite proxy for `/api` and `/ws` to `http://127.0.0.1:8000`.
- [x] Verify backend `/api/health` test with `pytest`.
- [x] Verify frontend build (`npm run build`) and type check.

### Phase 1: Data Schemas & Pure Packet Parser
- [x] Define immutable `PacketObservation` dataclass.
- [x] Define Pydantic request and response schemas.
- [x] Implement `parse_packet()` supporting Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, and fallback `OTHER`.
- [x] Implement monotonic packet ID generation and timezone-aware UTC timestamps.
- [x] Ensure strict zero-payload policy (no raw payloads or Scapy packet objects retained).
- [x] Write in-memory unit tests for parser across all protocol layers, including malformed and unsupported packets without root access.

### Phase 2: In-Memory Metrics Store & Rolling Bandwidth
- [x] Implement thread-safe `MetricsStore` with mutex locking.
- [x] Implement session totals (packet count, byte count, protocol breakdown).
- [x] Implement per-host TX/RX counters and rolling bandwidth calculations (`bytes_in_window / window_seconds`).
- [x] Implement bounded recent packet metadata ring buffer (capped at 100).
- [x] Implement time-window rolling bucket expiry.
- [x] Write deterministic unit tests with simulated timestamps verifying counters, expiry, and top-host sorting.

### Phase 3: Detection Engine & Alert Store
- [x] Implement `DetectionEngine` with 3 deterministic heuristic rules:
  - [x] Rule A: TCP Port Scan (distinct destination ports $\ge 15$ within 10s per `(src, dst)`).
  - [x] Rule B: Possible SYN Flood (bare SYNs $\ge 100$ within 5s per `dst`).
  - [x] Rule C: Possible ARP Spoofing (conflicting MAC for same IPv4 within 60s).
- [x] Implement bounded `AlertStore` (capped at 500) with deduplication fingerprints, 30s cooldown updates, and acknowledgement.
- [x] Write unit tests for all positive triggers, negative non-triggers, boundary conditions, and cooldown updates.

### Phase 4: Capture Manager & REST API Integration
- [x] Implement `InterfaceService` for OS interface enumeration and validation.
- [x] Implement `CaptureManager` wrapping Scapy `AsyncSniffer(store=False)` with non-blocking lifecycle management.
- [x] Ensure capture states (`stopped`, `starting`, `running`, `stopping`, `error`) and idempotency (409 on active capture).
- [x] Wire pipeline: Sniffer callback -> Parser -> MetricsStore + DetectionEngine -> AlertStore.
- [x] Implement REST routes:
  - [x] `GET /api/health`
  - [x] `GET /api/interfaces`
  - [x] `GET /api/capture/status`
  - [x] `POST /api/capture/start`
  - [x] `POST /api/capture/stop`
  - [x] `GET /api/metrics/summary`
  - [x] `GET /api/metrics/hosts`
  - [x] `GET /api/packets`
  - [x] `GET /api/alerts`
  - [x] `POST /api/alerts/{alert_id}/acknowledge`
- [x] Implement API tests with mocks (no root required).

### Phase 5: WebSocket & Live Dashboard UI
- [x] Implement `WS /ws/live` pushing periodic snapshots (~1s) of capture status, metrics, top hosts, recent packets, and alerts.
- [x] Implement frontend WebSocket hook with exponential backoff and stable ID record deduplication.
- [x] Build UI components:
  - [x] Header (capture controls, interface picker, status badges).
  - [x] KPI cards (packets, formatted bytes, packet rate, active alerts).
  - [x] Protocol distribution chart & rolling traffic/bandwidth chart.
  - [x] Top talkers host table with TX/RX rates.
  - [x] Recent packet metadata table with detail modal (no payload).
  - [x] Alerts panel with severity indicators, evidence drawer, and acknowledgement.
  - [x] Loading, error, empty, and reconnect states.
- [x] Verify frontend build and responsive styling.

### Phase 6: Lab Validation & Detector Tuning
- [x] Document safe isolated lab setup (Mininet / VMs).
- [x] Verify baseline normal traffic (ping/HTTP) generates no alerts.
- [x] Validate port scan detection using bounded `nmap -sS`.
- [x] Validate SYN rate anomaly detection using bounded `hping3`.
- [x] Validate ARP conflict detection with synthetic in-memory packets.
- [x] Document results, false positive nuances, and limitations.

### Phase 7: Stabilization, Documentation & Release Readiness
- [x] Run backend tests (49 passed in 0.16s), type checks, and frontend build (`tsc` + Vite).
- [x] Verify memory bounds (ring buffers, deques) and clean session reset across components.
- [x] Final security audit (no payload leakage, loopback binding only `127.0.0.1`).
- [x] Finalize `README.md` with complete architecture, installation, demo instructions, and limitations (meeting all 16 PRD Section 19 criteria).
- [x] Final check against PRD Section 20 Definition of Done (all 18 criteria verified).

