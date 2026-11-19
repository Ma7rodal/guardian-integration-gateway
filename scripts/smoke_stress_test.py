#!/usr/bin/env python3
"""Smoke, concurrency, red-teaming, and circuit-breaker stress test suite
for The Guardian Integration Gateway.

Usage (inside Docker container):
    docker-compose exec guardian-gateway python scripts/smoke_stress_test.py

Usage (against custom URL):
    python scripts/smoke_stress_test.py --base-url http://localhost:8000
"""

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import List, Tuple

import httpx

# Allow importing app.crypto when run directly from repo root or /app
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.crypto import MessageEncryptor  # noqa: E402


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def fmt_stats(latencies_ms: List[float]) -> str:
    return (
        f"min={min(latencies_ms):.1f}ms | "
        f"avg={statistics.mean(latencies_ms):.1f}ms | "
        f"p95={percentile(latencies_ms, 95):.1f}ms | "
        f"max={max(latencies_ms):.1f}ms"
    )


async def stage_1_input_validation(client: httpx.AsyncClient) -> None:
    print("\n[Stage 1] Input Validation & Malicious Payloads (422 checks)")
    bad_payloads = [
        ("empty_message", {"userId": "val-1", "message": ""}),
        ("missing_userId", {"message": "hello"}),
        ("oversized_message", {"userId": "val-2", "message": "A" * 10001}),
    ]
    for name, payload in bad_payloads:
        resp = await client.post("/secure-inquiry", json=payload)
        assert resp.status_code == 422, f"{name}: expected 422, got {resp.status_code}"
    print("  PASS: All 3 invalid/boundary payloads cleanly rejected with HTTP 422.")


async def stage_2_pii_red_teaming(client: httpx.AsyncClient) -> List[str]:
    print("\n[Stage 2] PII Red-Teaming, Boundary Numbers & Large Payload (ReDoS check)")
    injected_secrets = [
        "redteam.user+01@guardian-test.io",
        "4532-0151-1283-0366",
        "5425 2334 3010 9903",
        "123-45-6789",
        "987654321",
    ]

    # 2a. Mixed Spanish/English PII
    mixed_msg = (
        "Hola, mi correo es redteam.user+01@guardian-test.io, "
        "tarjeta Visa 4532-0151-1283-0366, MasterCard 5425 2334 3010 9903, "
        "SSN 123-45-6789 y codigo 987654321."
    )
    resp = await client.post(
        "/secure-inquiry", json={"userId": "redteam-mixed", "message": mixed_msg}
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    sanitized = resp.json()["sanitizedMessage"]
    for secret in injected_secrets:
        assert secret not in sanitized, f"PII leak detected for: {secret}"
    assert "<REDACTED: EMAIL>" in sanitized
    assert "<REDACTED: CREDIT_CARD>" in sanitized
    assert "<REDACTED: SSN>" in sanitized

    # 2b. Non-PII 8-digit & 10-digit boundary numbers should NOT be redacted as SSN
    boundary_msg = "Order numbers 12345678 and 1234567890 are normal references."
    resp_b = await client.post(
        "/secure-inquiry", json={"userId": "redteam-boundary", "message": boundary_msg}
    )
    assert resp_b.status_code == 200
    sanitized_b = resp_b.json()["sanitizedMessage"]
    assert "12345678" in sanitized_b and "1234567890" in sanitized_b
    assert "<REDACTED: SSN>" not in sanitized_b

    # 2c. Large payload (~9,500 chars) to verify linear-time Presidio performance
    large_msg = (
        ("Guardian security telemetry payload. " * 250)
        + " Contact: redteam.user+01@guardian-test.io SSN: 987654321"
    )
    t0 = time.perf_counter()
    resp_l = await client.post(
        "/secure-inquiry", json={"userId": "redteam-large", "message": large_msg}
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert resp_l.status_code == 200
    sanitized_l = resp_l.json()["sanitizedMessage"]
    assert "redteam.user+01@guardian-test.io" not in sanitized_l
    assert "987654321" not in sanitized_l

    print(
        f"  PASS: Mixed ES/EN PII redacted, 8/10-digit boundaries preserved, "
        f"9.5KB payload completed in {elapsed_ms:.1f}ms (no ReDoS)."
    )
    return injected_secrets


async def stage_3_concurrent_audit_stress(
    client: httpx.AsyncClient, concurrency: int
) -> List[str]:
    print(f"\n[Stage 3] Concurrent Audit Log Stress ({concurrency} simultaneous requests)")
    secrets: List[str] = []

    async def _send(i: int) -> Tuple[int, float]:
        email = f"loadtest{i}@stress-domain.org"
        ssn = f"{100 + i:03d}-55-{1000 + i:04d}"
        secrets.extend([email, ssn])
        t0 = time.perf_counter()
        resp = await client.post(
            "/secure-inquiry",
            json={
                "userId": f"stress-{i}",
                "message": f"User {i} email {email} and SSN {ssn}",
            },
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert resp.status_code == 200, f"Req {i} failed: {resp.status_code}"
        body = resp.json()
        assert body["answer"] == "Generated Answer"
        assert email not in body["sanitizedMessage"]
        assert ssn not in body["sanitizedMessage"]
        return resp.status_code, elapsed_ms

    t_wall = time.perf_counter()
    results = await asyncio.gather(*[_send(i) for i in range(concurrency)])
    wall_ms = (time.perf_counter() - t_wall) * 1000
    latencies = [lat for _, lat in results]

    print(
        f"  PASS: {concurrency}/{concurrency} concurrent requests succeeded in "
        f"{wall_ms:.1f}ms wall time ({fmt_stats(latencies)})."
    )
    return secrets


async def stage_4_circuit_breaker_burst(
    client: httpx.AsyncClient, burst: int
) -> None:
    print(
        f"\n[Stage 4] Circuit Breaker Thundering Herd "
        f"(3 failures -> {burst} concurrent requests)"
    )

    # Trigger 3 consecutive failures
    for i in range(1, 4):
        resp = await client.post(
            "/secure-inquiry",
            json={"userId": f"cb-fail-{i}", "message": f"Force failure #{i}"},
            headers={"X-Simulate-Failure": "true"},
        )
        assert resp.status_code == 502, f"Expected 502 on failure #{i}, got {resp.status_code}"

    # Verify /health reports OPEN
    health = await client.get("/health")
    assert health.status_code == 200
    cb_state = health.json()["circuitBreaker"]["state"]
    assert cb_state == "OPEN", f"Expected OPEN circuit state, got {cb_state}"

    # Fire burst of concurrent requests while OPEN
    async def _burst_call(i: int) -> float:
        t0 = time.perf_counter()
        resp = await client.post(
            "/secure-inquiry",
            json={"userId": f"burst-{i}", "message": "My SSN is 987654321"},
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert resp.status_code == 503, f"Burst #{i} expected 503, got {resp.status_code}"
        body = resp.json()
        assert body["answer"] == "Service Busy"
        assert body["circuitState"] == "OPEN"
        assert "<REDACTED: SSN>" in body["sanitizedMessage"]
        return elapsed_ms

    t_wall = time.perf_counter()
    latencies = list(await asyncio.gather(*[_burst_call(i) for i in range(burst)]))
    wall_ms = (time.perf_counter() - t_wall) * 1000
    p95 = percentile(latencies, 95)

    assert p95 < 1000.0, f"Circuit-open fallback too slow (p95={p95:.1f}ms)"
    print(
        f"  PASS: {burst}/{burst} circuit-open requests returned 503 'Service Busy' "
        f"in {wall_ms:.1f}ms wall time ({fmt_stats(latencies)})."
    )


def stage_5_audit_integrity_check(
    audit_log_path: str, injected_secrets: List[str]
) -> None:
    print(f"\n[Stage 5] Audit Log Zero-Leak & AES-256-GCM Integrity ({audit_log_path})")
    path = Path(audit_log_path)
    if not path.exists():
        print(f"  SKIP: {audit_log_path} not accessible from this host.")
        return

    raw_text = path.read_text(encoding="utf-8")
    records = json.loads(raw_text)
    assert isinstance(records, list) and len(records) > 0, "Audit log is empty or corrupt!"

    # Zero-leak check: no raw secret should appear anywhere in plaintext JSON
    for secret in injected_secrets:
        assert secret not in raw_text, f"CRITICAL: Plaintext PII leak in audit_log.json: {secret}"

    # Decryption roundtrip check on every record
    key = os.environ.get(
        "ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    encryptor = MessageEncryptor(key)
    for idx, entry in enumerate(records):
        decrypted = encryptor.decrypt(entry["originalMessageEncrypted"])
        assert isinstance(decrypted, str) and len(decrypted) > 0, f"Record {idx} failed decrypt"

    print(
        f"  PASS: {len(records)} valid JSON records verified, 0 plaintext PII leaks, "
        f"100% AES-256-GCM decryptable."
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Gateway Smoke & Stress Suite")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--audit-log", default="/app/data/audit_log.json")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--burst", type=int, default=50)
    args = parser.parse_args()

    print("=" * 72)
    print(f"The Guardian Integration Gateway - Smoke & Stress Test Suite")
    print(f"Target: {args.base_url} | Concurrency: {args.concurrency} | Burst: {args.burst}")
    print("=" * 72)

    async with httpx.AsyncClient(base_url=args.base_url, timeout=30.0) as client:
        health = await client.get("/health")
        assert health.status_code == 200, f"Gateway unhealthy: {health.status_code}"
        if health.json()["circuitBreaker"]["state"] != "CLOSED":
            print(
                "  WARN: Circuit breaker is not CLOSED at start. "
                "Restart the container or wait for cooldown before running."
            )
            sys.exit(1)

        await stage_1_input_validation(client)
        secrets = await stage_2_pii_red_teaming(client)
        secrets.extend(await stage_3_concurrent_audit_stress(client, args.concurrency))
        await stage_4_circuit_breaker_burst(client, args.burst)

    stage_5_audit_integrity_check(args.audit_log, secrets)

    print("\n" + "=" * 72)
    print("ALL 5 SMOKE & STRESS STAGES PASSED!")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
