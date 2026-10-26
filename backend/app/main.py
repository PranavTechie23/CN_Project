from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.api.routes_health import router as health_router
from app.api.routes_capture import router as capture_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_packets import router as packets_router
from app.api.routes_alerts import router as alerts_router
from app.api.websocket import router as ws_router
from app.services.runtime import runtime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("traffic_analyzer")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and graceful shutdown."""
    logger.info("Starting Network Traffic Analyzer backend on %s:%d", settings.HOST, settings.PORT)
    yield
    logger.info("Shutting down Network Traffic Analyzer backend")
    runtime.shutdown()


app = FastAPI(
    title="Network Traffic Analyzer & Anomaly Detector API",
    version="1.0.0",
    description="Passive network monitoring and heuristic anomaly detection service",
    lifespan=lifespan
)

# CORS configuration
allowed_origins = list({
    settings.FRONTEND_ORIGIN,
    "http://localhost:5173",
    "http://127.0.0.1:5173"
})

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API routers under /api
app.include_router(health_router, prefix="/api")
app.include_router(capture_router, prefix="/api")
app.include_router(metrics_router, prefix="/api")
app.include_router(packets_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")

# Mount WebSocket router
app.include_router(ws_router)
