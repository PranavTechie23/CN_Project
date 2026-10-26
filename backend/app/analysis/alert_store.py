from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional


@dataclass
class Alert:
    """Represents a security anomaly detection alert."""
    id: str
    rule_id: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str]
    target_ip: Optional[str]
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    acknowledged: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to a JSON-serializable dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "occurrence_count": self.occurrence_count,
            "acknowledged": self.acknowledged,
            "evidence": self.evidence,
        }


class AlertStore:
    """Thread-safe bounded in-memory alert store with deduplication and cooldown."""

    def __init__(
        self,
        *,
        max_alerts: int = 500,
        dedup_cooldown_seconds: int = 30
    ) -> None:
        self.max_alerts = max_alerts
        self.dedup_cooldown_seconds = dedup_cooldown_seconds

        self._lock = threading.RLock()
        self._next_id: int = 1

        # Ordered map preserving insertion order: alert_id -> Alert
        self._alerts: OrderedDict[str, Alert] = OrderedDict()
        # Fingerprint -> alert_id mapping for active deduplication
        self._fingerprints: Dict[str, str] = {}

    def reset(self) -> None:
        """Reset the alert store, clearing all alerts and resetting IDs."""
        with self._lock:
            self._next_id = 1
            self._alerts.clear()
            self._fingerprints.clear()

    def add_or_update_alert(
        self,
        *,
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        fingerprint: str,
        source_ip: Optional[str],
        target_ip: Optional[str],
        evidence: Dict[str, Any],
        timestamp: Optional[datetime] = None
    ) -> Alert:
        """Add a new alert or deduplicate/update an existing alert if within cooldown."""
        now = timestamp if timestamp is not None else datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        with self._lock:
            # Check if an existing alert with this fingerprint is within cooldown
            if fingerprint in self._fingerprints:
                existing_id = self._fingerprints[fingerprint]
                existing_alert = self._alerts.get(existing_id)
                if existing_alert is not None:
                    elapsed = (now - existing_alert.last_seen).total_seconds()
                    if elapsed <= self.dedup_cooldown_seconds:
                        # Cooldown active: update occurrence count and last seen
                        existing_alert.last_seen = now
                        existing_alert.occurrence_count += 1
                        existing_alert.evidence = evidence
                        return existing_alert

            # Cooldown expired or new alert: generate new alert
            alert_id = f"alert_{self._next_id:06d}"
            self._next_id += 1

            new_alert = Alert(
                id=alert_id,
                rule_id=rule_id,
                severity=severity,
                title=title,
                description=description,
                source_ip=source_ip,
                target_ip=target_ip,
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
                acknowledged=False,
                evidence=evidence,
            )

            # Enforce max alerts capacity bound
            if len(self._alerts) >= self.max_alerts:
                # Evict the oldest alert (FIFO)
                oldest_id, oldest_alert = self._alerts.popitem(last=False)
                # Clean up fingerprint mapping if it pointed to the evicted alert
                for fp, aid in list(self._fingerprints.items()):
                    if aid == oldest_id:
                        del self._fingerprints[fp]

            self._alerts[alert_id] = new_alert
            self._fingerprints[fingerprint] = alert_id
            return new_alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve a single alert by its ID."""
        with self._lock:
            return self._alerts.get(alert_id)

    def acknowledge_alert(self, alert_id: str) -> Optional[Alert]:
        """Acknowledge an alert by ID. Returns updated alert or None if not found."""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                return None
            alert.acknowledged = True
            return alert

    def get_alerts(
        self,
        *,
        limit: int = 100,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        rule_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return newest-first alerts matching optional filters, bounded by limit."""
        safe_limit = max(1, min(limit, self.max_alerts))

        with self._lock:
            all_alerts = list(self._alerts.values())
            unack_count = sum(1 for a in all_alerts if not a.acknowledged)

            # Filter newest-first (reversed from insertion order)
            filtered = []
            for alert in reversed(all_alerts):
                if severity is not None and alert.severity.lower() != severity.lower():
                    continue
                if acknowledged is not None and alert.acknowledged != acknowledged:
                    continue
                if rule_id is not None and alert.rule_id != rule_id:
                    continue
                filtered.append(alert.to_dict())
                if len(filtered) >= safe_limit:
                    break

            return {
                "alerts": filtered,
                "total": len(self._alerts),
                "unacknowledged_count": unack_count,
            }
