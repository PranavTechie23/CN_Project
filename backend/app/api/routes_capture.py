from fastapi import APIRouter, HTTPException, status

from app.schemas import (
    CaptureStartRequest,
    CaptureStatusResponse,
    InterfacesResponse,
)
from app.services.runtime import runtime

router = APIRouter(tags=["Capture"])


@router.get("/interfaces", response_model=InterfacesResponse)
@router.get("/capture/interfaces", response_model=InterfacesResponse)
async def list_interfaces() -> InterfacesResponse:
    """List available network interfaces on the host."""
    interfaces = runtime.interface_service.get_interfaces()
    return InterfacesResponse(interfaces=interfaces)


@router.get("/capture/status", response_model=CaptureStatusResponse)
async def get_capture_status() -> CaptureStatusResponse:
    """Retrieve current capture lifecycle state and counters."""
    return runtime.capture_manager.get_status()


@router.post("/capture/start", response_model=CaptureStatusResponse)
async def start_capture(req: CaptureStartRequest) -> CaptureStatusResponse:
    """Start passive packet capture on the specified interface."""
    clean_interface = req.interface.strip()
    try:
        return runtime.capture_manager.start(clean_interface)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "CAPTURE_PERMISSION_DENIED",
                    "message": str(e),
                }
            },
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "INVALID_INTERFACE",
                    "message": str(e),
                }
            },
        ) from e
    except RuntimeError as e:
        if "already active" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "CAPTURE_ALREADY_ACTIVE",
                        "message": str(e),
                    }
                },
            ) from e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": "CAPTURE_START_FAILED",
                    "message": str(e),
                }
            },
        ) from e


@router.post("/capture/stop", response_model=CaptureStatusResponse)
async def stop_capture() -> CaptureStatusResponse:
    """Stop active packet capture session safely and idempotently."""
    return runtime.capture_manager.stop()
