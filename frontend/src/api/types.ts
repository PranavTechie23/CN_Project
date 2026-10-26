export interface InterfaceInfo {
  name: string;
  description?: string;
  is_up: boolean;
  is_loopback: boolean;
  addresses: string[];
}

export interface CaptureStatus {
  state: 'stopped' | 'starting' | 'running' | 'stopping' | 'error';
  interface: string | null;
  started_at: string | null;
  packets_seen: number;
  packets_processed: number;
  processing_errors: number;
  last_error: string | null;
}

export interface ProtocolMetric {
  protocol: string;
  packets: number;
  bytes: number;
}

export interface HostTraffic {
  host_ip: string;
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  tx_bytes_per_second: number;
  rx_bytes_per_second: number;
  last_seen: string;
}

export interface PacketMetadata {
  packet_id: number;
  timestamp: string;
  interface: string;
  protocol: string;
  length_bytes: number;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_mac?: string | null;
  dst_mac?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  tcp_syn: boolean;
  tcp_ack: boolean;
  tcp_fin?: boolean;
  tcp_rst?: boolean;
  tcp_psh?: boolean;
  tcp_urg?: boolean;
  tcp_flags_int?: number | null;
  tcp_flags?: string | null;
  arp_sender_ip?: string | null;
  arp_sender_mac?: string | null;
  arp_target_ip?: string | null;
}

export interface Alert {
  id: string;
  rule_id: 'PORT_SCAN' | 'SYN_FLOOD' | 'ARP_SPOOF' | 'ICMP_FLOOD' | 'UDP_FLOOD' | 'TCP_FLAG_ANOMALY' | 'LAND_ATTACK' | string;
  severity: 'medium' | 'high' | string;
  title: string;
  description: string;
  source_ip?: string | null;
  target_ip?: string | null;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  acknowledged: boolean;
  evidence: Record<string, unknown>;
}

export interface LiveSnapshotMetrics {
  window_seconds: number;
  session_packets: number;
  session_bytes: number;
  window_packets: number;
  window_bytes: number;
  packets_per_second: number;
  bytes_per_second: number;
}

export interface LiveSnapshot {
  type: 'snapshot';
  timestamp: string;
  capture: CaptureStatus;
  metrics: LiveSnapshotMetrics;
  protocols: ProtocolMetric[];
  top_hosts: HostTraffic[];
  recent_packets: PacketMetadata[];
  recent_alerts: Alert[];
}

export interface ChartDataPoint {
  time: string;
  bytesPerSec: number;
  packetsPerSec: number;
}
