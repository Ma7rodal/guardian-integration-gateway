import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from app.ai_client import AIServiceError, MockAIClient
from app.audit_log import AuditLogger
from app.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.config import Settings, get_settings
from app.crypto import MessageEncryptor
from app.sanitizer import PresidioSanitizer
from app.schemas import (
    CircuitBreakerStatus,
    HealthResponse,
    InquiryRequest,
    InquiryResponse,
)

logger = logging.getLogger("guardian.gateway")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


def create_app(
    settings: Optional[Settings] = None,
    sanitizer: Optional[PresidioSanitizer] = None,
) -> FastAPI:
    """Application factory for clean dependency injection and testability."""
    cfg = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Initializing Guardian Integration Gateway...")
        encryptor = MessageEncryptor(cfg.encryption_key)
        app.state.settings = cfg
        app.state.sanitizer = sanitizer or PresidioSanitizer(
            spacy_model_name=cfg.spacy_model_name
        )
        app.state.ai_client = MockAIClient(delay_seconds=cfg.mock_ai_delay_seconds)
        app.state.circuit_breaker = CircuitBreaker(
            failure_threshold=cfg.cb_failure_threshold,
            recovery_timeout_seconds=cfg.cb_recovery_timeout_seconds,
        )
        app.state.audit_logger = AuditLogger(
            file_path=cfg.audit_log_path,
            encryptor=encryptor,
        )
        logger.info("Guardian Integration Gateway ready (Presidio pre-warmed).")
        yield
        logger.info("Shutting down Guardian Integration Gateway.")

    app = FastAPI(
        title=cfg.app_name,
        version=cfg.app_version,
        description=(
            "Secure AI Middleware Gateway with Microsoft Presidio PII redaction, "
            "AES-256-GCM encrypted audit logging, and a 3-state Circuit Breaker."
        ),
        lifespan=lifespan,
    )

    @app.get("/health", response_model=HealthResponse, tags=["Observability"])
    async def health(request: Request) -> HealthResponse:
        cb_snapshot = request.app.state.circuit_breaker.snapshot()
        return HealthResponse(
            status="healthy",
            service=cfg.app_name,
            version=cfg.app_version,
            circuitBreaker=CircuitBreakerStatus(
                state=cb_snapshot["state"],
                consecutiveFailures=cb_snapshot["consecutive_failures"],
                failureThreshold=cb_snapshot["failure_threshold"],
                retryAfterSeconds=cb_snapshot["retry_after_seconds"],
            ),
        )

    @app.post(
        "/secure-inquiry",
        response_model=InquiryResponse,
        responses={
            502: {"description": "Upstream Mock AI call failed"},
            503: {"description": "Circuit Breaker OPEN - Instant 'Service Busy' fallback"},
        },
        tags=["Gateway"],
    )
    async def secure_inquiry(
        payload: InquiryRequest,
        request: Request,
        x_simulate_failure: bool = Header(
            default=False,
            alias="X-Simulate-Failure",
            description="Set to 'true' to deterministically simulate an upstream AI failure.",
        ),
    ) -> JSONResponse:
        start = time.perf_counter()

        # Step 1: Sanitize PII before touching any downstream AI service
        sanitization = request.app.state.sanitizer.sanitize(payload.message)

        cb: CircuitBreaker = request.app.state.circuit_breaker
        ai_client: MockAIClient = request.app.state.ai_client
        audit_logger: AuditLogger = request.app.state.audit_logger

        # Step 2: Protected Mock AI Call via Circuit Breaker
        try:
            answer = await cb.call(
                ai_client.generate_answer,
                sanitization.sanitized_text,
                simulate_failure=x_simulate_failure,
            )
            outcome = "SUCCESS"
            status_code = 200
            retry_after: Optional[float] = None
        except CircuitOpenError as exc:
            # Instant fallback without waiting for the 2-second AI timeout
            answer = "Service Busy"
            outcome = "CIRCUIT_OPEN"
            status_code = 503
            retry_after = exc.retry_after_seconds
            logger.warning(
                "Circuit OPEN for userId=%s; returning instant 'Service Busy' fallback.",
                payload.user_id,
            )
        except AIServiceError:
            answer = "Upstream AI Service Error"
            outcome = "AI_FAILURE"
            status_code = 502
            retry_after = cb.snapshot()["retry_after_seconds"]
            logger.error(
                "Mock AI call failed for userId=%s (consecutive_failures=%d).",
                payload.user_id,
                cb.snapshot()["consecutive_failures"],
            )

        # Step 3: Persist Audit Log (encrypted original + plaintext redacted)
        await audit_logger.record(
            user_id=payload.user_id,
            original_message=payload.message,
            redacted_message=sanitization.sanitized_text,
            redacted_types=sanitization.redacted_types,
            outcome=outcome,
        )

        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        cb_state = cb.snapshot()["state"]

        response_body = InquiryResponse(
            userId=payload.user_id,
            sanitizedMessage=sanitization.sanitized_text,
            answer=answer,
            redactedTypes=sanitization.redacted_types,
            circuitState=cb_state,
            latencyMs=latency_ms,
            retryAfterSeconds=retry_after,
        )

        headers = {}
        if status_code == 503 and retry_after is not None:
            headers["Retry-After"] = str(int(retry_after) + 1)

        return JSONResponse(
            status_code=status_code,
            content=response_body.model_dump(by_alias=True, exclude_none=True),
            headers=headers,
        )

    return app


app = create_app()
