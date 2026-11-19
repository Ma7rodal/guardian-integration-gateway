import json
import time
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.crypto import MessageEncryptor
from app.main import create_app
from app.sanitizer import PresidioSanitizer


@pytest.fixture(scope="module")
def shared_sanitizer() -> PresidioSanitizer:
    return PresidioSanitizer(spacy_model_name="en_core_web_sm")


@pytest.mark.asyncio
async def test_secure_inquiry_happy_path_and_audit_log(
    tmp_path: Path, shared_sanitizer: PresidioSanitizer
):
    audit_file = tmp_path / "audit_log.json"
    settings = Settings(
        audit_log_path=str(audit_file),
        mock_ai_delay_seconds=0.05,  # Fast delay for unit test suite
        cb_failure_threshold=3,
        cb_recovery_timeout_seconds=30.0,
    )
    app = create_app(settings=settings, sanitizer=shared_sanitizer)

    raw_message = (
        "Email: bob@example.com, Card: 4532-0151-1283-0366, SSN: 123-45-6789."
    )

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/secure-inquiry",
                json={"userId": "user-101", "message": raw_message},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["userId"] == "user-101"
    assert body["answer"] == "Generated Answer"
    assert body["circuitState"] == "CLOSED"
    assert "<REDACTED: EMAIL>" in body["sanitizedMessage"]
    assert "<REDACTED: CREDIT_CARD>" in body["sanitizedMessage"]
    assert "<REDACTED: SSN>" in body["sanitizedMessage"]
    assert "bob@example.com" not in body["sanitizedMessage"]

    # Verify audit log contains encrypted original + plaintext redacted
    records = json.loads(audit_file.read_text(encoding="utf-8"))
    assert len(records) == 1
    entry = records[0]
    assert entry["userId"] == "user-101"
    assert entry["outcome"] == "SUCCESS"
    assert entry["redactedMessage"] == body["sanitizedMessage"]
    assert entry["originalMessageEncrypted"] != raw_message
    assert "bob@example.com" not in entry["originalMessageEncrypted"]

    encryptor = MessageEncryptor(settings.encryption_key)
    assert encryptor.decrypt(entry["originalMessageEncrypted"]) == raw_message


@pytest.mark.asyncio
async def test_circuit_breaker_instant_fallback_without_waiting(
    tmp_path: Path, shared_sanitizer: PresidioSanitizer
):
    audit_file = tmp_path / "audit_log.json"
    # Use a noticeable 0.5s simulated AI delay so we can prove the 4th call bypasses it
    settings = Settings(
        audit_log_path=str(audit_file),
        mock_ai_delay_seconds=0.5,
        cb_failure_threshold=3,
        cb_recovery_timeout_seconds=30.0,
    )
    app = create_app(settings=settings, sanitizer=shared_sanitizer)

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 3 consecutive simulated failures
            for idx in range(3):
                resp = await client.post(
                    "/secure-inquiry",
                    json={"userId": f"u-{idx}", "message": "Test failure"},
                    headers={"X-Simulate-Failure": "true"},
                )
                assert resp.status_code == 502

            # Health endpoint should report OPEN
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["circuitBreaker"]["state"] == "OPEN"

            # 4th call must return 503 "Service Busy" INSTANTLY (< 0.15s vs 0.5s delay)
            start = time.perf_counter()
            fallback = await client.post(
                "/secure-inquiry",
                json={"userId": "u-4", "message": "My SSN is 987654321"},
            )
            elapsed = time.perf_counter() - start

    assert fallback.status_code == 503
    assert "Retry-After" in fallback.headers
    fb_body = fallback.json()
    assert fb_body["answer"] == "Service Busy"
    assert fb_body["circuitState"] == "OPEN"
    assert "<REDACTED: SSN>" in fb_body["sanitizedMessage"]
    assert elapsed < 0.15

    # All 4 calls should be audited
    records = json.loads(audit_file.read_text(encoding="utf-8"))
    assert len(records) == 4
    assert [r["outcome"] for r in records] == [
        "AI_FAILURE",
        "AI_FAILURE",
        "AI_FAILURE",
        "CIRCUIT_OPEN",
    ]
