import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import settings
from app.services.runtime import runtime

logger = logging.getLogger("traffic_analyzer.websocket")

router = APIRouter(tags=["WebSocket"])


def build_live_snapshot() -> Dict[str, Any]:
    """Assemble a bounded, lightweight snapshot of the current analyzer state."""
    now = datetime.now(timezone.utc)

    capture_status = runtime.capture_manager.get_status().model_dump()
    summary = runtime.metrics_store.get_summary(
        window_seconds=settings.METRICS_WINDOW_SECONDS,
        now=now
    )
    top_hosts_data = runtime.metrics_store.get_top_hosts(
        window_seconds=settings.METRICS_WINDOW_SECONDS,
        limit=10,
        now=now
    )
    recent_packets = runtime.metrics_store.get_recent_packets(limit=25)
    recent_alerts_data = runtime.alert_store.get_alerts(limit=25)

    return {
        "type": "snapshot",
        "timestamp": now.isoformat(),
        "capture": capture_status,
        "metrics": {
            "window_seconds": summary["window_seconds"],
            "session_packets": summary["session"]["packets"],
            "session_bytes": summary["session"]["bytes"],
            "window_packets": summary["window"]["packets"],
            "window_bytes": summary["window"]["bytes"],
            "packets_per_second": summary["window"]["packets_per_second"],
            "bytes_per_second": summary["window"]["bytes_per_second"],
        },
        "protocols": summary["protocols"],
        "top_hosts": top_hosts_data["hosts"],
        "recent_packets": recent_packets,
        "recent_alerts": recent_alerts_data["alerts"],
    }


@router.websocket("/ws/live")
async def live_dashboard_websocket(websocket: WebSocket) -> None:
    """Stream live analyzer snapshots to connected dashboard clients at regular intervals."""
    await websocket.accept()
    client_host = websocket.client.host if websocket.client else "unknown"
    logger.info("WebSocket client connected from %s", client_host)

    try:
        # Send initial snapshot immediately upon connection
        initial_snapshot = build_live_snapshot()
        await websocket.send_json(initial_snapshot)

        # Stream recurring periodic snapshots
        interval = max(0.2, settings.WS_UPDATE_INTERVAL_SECONDS)
        while True:
            await asyncio.sleep(interval)
            snapshot = build_live_snapshot()
            await websocket.send_json(snapshot)

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected: %s", client_host)
    except Exception as e:
        logger.warning("WebSocket connection terminated with error: %s", e)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
