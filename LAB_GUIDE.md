# Safe Lab Validation & Demonstration Guide

This guide provides instructions for setting up an isolated network lab (via **Mininet** or **host-only virtual machines**) to demonstrate the **Network Traffic Analyzer & Anomaly Detector** (Mini IDS) without exposing external networks to test traffic.

---

## 1. Safety Notice & Ethical Boundaries

> [!CAUTION]
> **STRICT SAFETY BOUNDARIES:**
> - Never target external hosts, public IP addresses, campus networks, or production systems.
> - The application is purely a **passive sensor**; it never sends packets.
> - Test scripts provided in `scripts/lab/` enforce destination IP checks and refuse to target non-private addresses.

---

## 2. Lab Environment Options

### Option A: Mininet Topology (Recommended for Linux)
Mininet emulates a complete virtual network topology of OpenFlow switches and isolated Linux host namespaces on a single machine.

```bash
# Launch a 3-host single-switch topology
sudo mn --topo single,3 --mac --switch ovsbr --controller none
```
In this topology:
* Host 1 (`h1`): `10.0.0.1` (Traffic generator / benign host)
* Host 2 (`h2`): `10.0.0.2` (Target server / Monitored node)
* Host 3 (`h3`): `10.0.0.3` (Attacker node)

#### Handling the Mininet Network Namespace
Mininet host interfaces (such as `h2-eth0`) live inside isolated network namespaces (`netns`) and are not visible in the root OS namespace by default.

**To attach Sniffy properly, choose one of these two approaches:**
1. **Host Namespace Execution (Recommended):** Run the backend directly in the target host's namespace:
   ```bash
   # From the Mininet CLI:
   mininet> h2 xterm &
   # Inside the h2 xterm window:
   cd /path/to/sniffy/backend
   source .venv/bin/activate
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. **Switch Interface Monitoring:** If running the backend in the root namespace, monitor the switch port connected to the target (e.g. `s1-eth2`), which is visible to the root OS via `ip link`.

---

### Option B: Isolated Virtual Machines / Local Host-Only Network
Set up 2 or 3 lightweight Linux VMs (Ubuntu, Debian, or Alpine) configured with a **Host-Only / Internal Network**:
* VM 1 (Analyzer & Target): `192.168.56.10`
* VM 2 (Test Client / Scanner): `192.168.56.20`

---

## 3. Evaluator Demonstration Runbook

### Step 1: Start the Application
1. **Backend:**
   ```bash
   cd backend
   source .venv/bin/activate
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. **Frontend:**
   ```bash
   cd frontend
   npm run dev
   ```
3. Open `http://localhost:5173` in your browser.
4. Select the monitored interface from the dropdown (e.g. `h2-eth0`, `s1-eth2`, or `lo0`) and click **Start Capture**.

---

### Step 2: Normal Baseline Traffic (Zero False Positives)
Generate ordinary low-volume traffic to confirm counter updates without false alerts.

* **Using standard tools:**
  ```bash
  # Send 4 ICMP echo requests
  ping -c 4 10.0.0.2
  ```
* **Or using the lab utility:**
  ```bash
  python3 scripts/lab/traffic_generator.py --mode normal --target 10.0.0.2
  ```
* **Expected Result:**
  * Protocol distribution increments ICMP count.
  * Host table lists `10.0.0.1` and `10.0.0.2` with TX/RX bytes.
  * **0 alerts** are raised.

---

### Step 3: TCP Port Scan Demonstration (Rule A)
Simulate a port reconnaissance probe against the monitored host.

* **Using Nmap:**
  ```bash
  # SYN scan against ports 1-30
  nmap -sS -Pn -p 1-30 10.0.0.2
  ```
* **Or using the lab utility:**
  ```bash
  python3 scripts/lab/traffic_generator.py --mode port_scan --target 10.0.0.2 --count 20
  ```
* **Expected Result:**
  * Once the unique port count reaches $\ge 15$ distinct destination ports within 10s:
  * A `PORT_SCAN` alert is displayed in the live alerts feed.
  * Click the alert to inspect: source IP, target IP, exact port count, and sampled destination ports.

---

### Step 4: SYN-Rate Flood Demonstration (Rule B)
Simulate an unusually high burst of bare TCP SYN packets.

* **Using Hping3:**
  ```bash
  sudo hping3 -S -p 80 -c 120 -i u10000 10.0.0.2
  ```
* **Or using the lab utility:**
  ```bash
  python3 scripts/lab/traffic_generator.py --mode syn_flood --target 10.0.0.2 --count 110
  ```
* **Expected Result:**
  * When $\ge 100$ bare SYNs are detected within a 5-second window:
  * A `SYN_FLOOD` alert is flagged with `high` severity.
  * Evidence drawer shows: observed SYN count, time window, and distinct source count.

---

### Step 5: ARP Spoofing Conflict Demonstration (Rule C)
Simulate conflicting IP-to-MAC claims for the same IPv4 address.

* **Using the lab utility:**
  ```bash
  python3 scripts/lab/traffic_generator.py --mode arp_spoof --target 10.0.0.1 --iface s1-eth1
  ```
* **Automated in-memory test:**
  ```bash
  cd backend && pytest tests/test_arp_spoof_detector.py
  ```
* **Expected Result:**
  * An `ARP_SPOOF` alert flags that `10.0.0.1` was observed claiming two distinct MAC addresses inside the 60s window.
  * Evidence drawer displays the claimed IP, prior MAC, and new conflicting MAC.

---

## 4. Threshold Tuning for Rapid Demos

For quick 2-minute classroom or evaluator presentations, default thresholds can be lowered in `.env`:

```dotenv
# Quick demo thresholds in .env:
PORT_SCAN_WINDOW_SECONDS=5
PORT_SCAN_UNIQUE_PORTS_THRESHOLD=5      # Trigger scan after only 5 distinct ports
SYN_FLOOD_WINDOW_SECONDS=3
SYN_FLOOD_SYN_THRESHOLD=20              # Trigger flood after only 20 bare SYNs
ARP_CONFLICT_WINDOW_SECONDS=30
```

Restart the backend after updating `.env`.

---

## 5. Independent Verification with Wireshark

To verify that Sniffy's observation matches ground truth wire traffic:
1. Open Wireshark on the same interface:
   ```bash
   wireshark -k -i s1-eth2 &
   ```
2. Apply display filter `tcp.flags.syn == 1 && tcp.flags.ack == 0` for bare SYNs.
3. Compare the packet count, timestamp, and port sequence against Sniffy's **Recent Packets** table and **Throughput Chart**.

---

## 6. Academic Nuances & Heuristic Limitations

| Question | Academic Explanation |
|---|---|
| **Does an alert prove a malicious breach?** | **No.** Alerts are heuristic indicators of suspicious packet patterns. Legitimate security scanners, vulnerability assessments, or load balancers create identical bare SYN probes. |
| **Why "Possible SYN flood" instead of "Confirmed DDoS"?** | As a passive monitor, Sniffy observes arrival rates. It does not inspect server memory, socket backlogs, or incomplete three-way handshakes to verify host exhaustion. |
| **Why can ARP conflicts occur legitimately?** | Hardware failovers, NIC bonding, virtual machine migrations (e.g. vMotion), and router VRRP/HSRP switches legitimately rebind IP addresses to new MACs. |
| **What happens to encrypted traffic?** | Sniffy inspects only Layer 2–4 headers (IPs, ports, flags, packet lengths). Payload bytes and TLS application contents are strictly ignored and never decrypted. |
